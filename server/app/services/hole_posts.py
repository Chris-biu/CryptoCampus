import base64
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import SM2_PUBLIC_KEY_SIZE
from app.models.audit import RevocationLog
from app.models.credential import ConsumedSN
from app.models.hole import HolePost, HolePostIdempotency
from app.schemas.credential import CredentialProof, encode_credential_message
from app.schemas.hole import HolePost as HolePostSchema, HolePostPage
from app.schemas.inspect import InspectEvent, InspectStepInput
from app.services.credential_verification import (
    ConsumptionCredentialVerificationError,
    verify_consumption_credential,
)
from app.services.inspection import InspectionRecorder, get_inspection_recorder
from app.services.signer_provider import (
    ServerSignerVerificationKeyProvider,
    get_signer_verification_key_provider,
)


class HolePostServiceError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


class HolePostService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        signer_verification_key_provider: ServerSignerVerificationKeyProvider | None = None,
        recorder: InspectionRecorder | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.signer_verification_key_provider = (
            signer_verification_key_provider or get_signer_verification_key_provider()
        )
        self.recorder = recorder or get_inspection_recorder()

    def publish(
        self,
        *,
        content: str,
        credential: CredentialProof,
        idempotency_key: str,
        now: datetime,
    ) -> HolePost:
        # 1. Validate content and idempotency_key
        if not isinstance(content, str) or not (1 <= len(content) <= 5000):
            raise HolePostServiceError("invalid_content", "帖子内容长度必须在 1 至 5000 字符之间")
        if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
            raise HolePostServiceError("invalid_idempotency_key", "幂等键长度必须在 16 至 128 字符之间")

        # 2. Verify credential for consumption (defer revocation check until after idempotency check)
        try:
            verified = verify_consumption_credential(
                session=self.session,
                crypto_engine=self.crypto_engine,
                signer_verification_key_provider=self.signer_verification_key_provider,
                credential=credential,
                expected_service="hole_post",
                now=now,
                check_revocation=False,
            )
        except ConsumptionCredentialVerificationError as err:
            raise HolePostServiceError(err.code, err.message) from err


        now_utc = self._utc(now)
        sn_bytes = verified.sn_bytes
        sig_bytes = verified.signature_bytes

        # 7. Compute SM3 digests and check idempotency first

        key_hash = self.crypto_engine.sm3_digest(idempotency_key.encode("utf-8"))
        canonical_req = f"{content}|{credential.sn.lower()}|{credential.service}|{credential.period}|{credential.signature}".encode("utf-8")
        request_hash = self.crypto_engine.sm3_digest(canonical_req)

        # Pre-transaction idempotency check
        existing_idemp = (
            self.session.query(HolePostIdempotency)
            .filter_by(key_hash=key_hash)
            .one_or_none()
        )
        if existing_idemp is not None:
            if self.crypto_engine.constant_time_equal(existing_idemp.request_hash, request_hash):
                post = self.session.get(HolePost, existing_idemp.post_id)
                if post is not None:
                    return post
            raise HolePostServiceError("idempotency_conflict", "同一幂等键已用于不同发布请求")

        # 8. Revocation check (for new publish requests)
        revoked = (
            self.session.query(RevocationLog).filter_by(sn=sn_bytes).first() is not None
        )
        if revoked:
            raise HolePostServiceError("credential_revoked", "凭证已被撤销")

        # 10. Atomic database transaction
        try:
            with self._transaction():
                # Check ConsumedSN
                if self.session.get(ConsumedSN, (sn_bytes, credential.service)) is not None:
                    raise HolePostServiceError("credential_consumed", "该凭证已消费，不能重复使用")

                consumed = ConsumedSN(
                    sn=sn_bytes,
                    service=credential.service,
                    consumed_at=now_utc,
                )
                self.session.add(consumed)

                post = HolePost(
                    id=str(uuid.uuid4()),
                    content=content,
                    credential_sn=sn_bytes,
                    credential_service=credential.service,
                    credential_period=credential.period,
                    credential_signature=sig_bytes,
                    credential_prefix=credential.sn.lower()[:8],
                    credential_valid=True,
                    status="published",
                    created_at=now_utc,
                )
                self.session.add(post)

                idemp_record = HolePostIdempotency(
                    id=str(uuid.uuid4()),
                    key_hash=key_hash,
                    request_hash=request_hash,
                    post_id=post.id,
                    created_at=now_utc,
                )
                self.session.add(idemp_record)

                self.recorder.record(
                    event=InspectEvent(
                        operation="hole.credential.verify",
                        owner_user_id=None,
                        steps=(
                            InspectStepInput(
                                order=1,
                                name="匿名凭证核验与发帖",
                                algorithm="SM2-Blind-Verify",
                                result="passed",
                                redacted_values={
                                    "service": "hole",
                                    "period": credential.period,
                                    "signature_valid": True,
                                    "revoked": False,
                                },
                            ),
                        ),
                        occurred_at=now_utc,
                    ),
                    session=self.session,
                )
                self.session.flush()

            return post
        except IntegrityError as ie:
            self.session.rollback()
            # Race condition handling
            race_idemp = (
                self.session.query(HolePostIdempotency)
                .filter_by(key_hash=key_hash)
                .one_or_none()
            )
            if race_idemp is not None:
                if self.crypto_engine.constant_time_equal(race_idemp.request_hash, request_hash):
                    p = self.session.get(HolePost, race_idemp.post_id)
                    if p is not None:
                        return p
                raise HolePostServiceError("idempotency_conflict", "同一幂等键已用于不同发布请求") from ie

            if self.session.get(ConsumedSN, (sn_bytes, credential.service)) is not None:
                raise HolePostServiceError("credential_consumed", "该凭证已消费，不能重复使用") from ie
            raise HolePostServiceError("conflict", "发布数据写入冲突") from ie
        except Exception:
            self.session.rollback()
            raise

    def list_posts(self, *, page: int = 1, page_size: int = 20) -> HolePostPage:
        if page < 1:
            page = 1
        if page_size < 1:
            page_size = 20
        elif page_size > 100:
            page_size = 100

        query = (
            self.session.query(HolePost)
            .filter(HolePost.status.in_(["published", "withdrawn"]))
            .order_by(HolePost.created_at.desc(), HolePost.id.desc())
        )
        total = query.count()
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all() if offset < total else []

        return HolePostPage(
            items=[HolePostSchema.model_validate(p) for p in items],
            page=page,
            page_size=page_size,
            total=total,
        )

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        manager = (
            self.session.begin_nested()
            if self.session.in_transaction()
            else self.session.begin()
        )
        with manager:
            yield

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
