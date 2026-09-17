from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator
import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.models.credential import ConsumedSN
from app.models.hole import (
    HoleComment,
    HoleCommentIdempotency,
    HoleLike,
    HoleLikeIdempotency,
    HolePost,
)
from app.schemas.credential import CredentialProof
from app.schemas.hole import (
    HoleComment as HoleCommentSchema,
    HoleCommentPage,
)
from app.services.credential_verification import (
    ConsumptionCredentialVerificationError,
    verify_consumption_credential,
)
from app.services.signer_provider import (
    ServerSignerVerificationKeyProvider,
    get_signer_verification_key_provider,
)


class HoleInteractionServiceError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


class HoleInteractionService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        signer_verification_key_provider: ServerSignerVerificationKeyProvider | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.signer_verification_key_provider = (
            signer_verification_key_provider or get_signer_verification_key_provider()
        )

    def create_comment(
        self,
        *,
        post_id: str,
        content: str,
        credential: CredentialProof,
        idempotency_key: str,
        now: datetime,
    ) -> HoleComment:
        # 1. Validate post_id, content, idempotency_key
        try:
            uuid.UUID(post_id)
        except Exception:
            raise HoleInteractionServiceError("invalid_post_id", "帖子 ID 必须是合法 UUID")

        if not isinstance(content, str) or not (1 <= len(content) <= 2000):
            raise HoleInteractionServiceError("invalid_content", "评论内容长度必须在 1 至 2000 字符之间")

        if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
            raise HoleInteractionServiceError("invalid_idempotency_key", "幂等键长度必须在 16 至 128 字符之间")

        # 2. Check target post exists and is published
        post = self.session.get(HolePost, post_id)
        if post is None or post.status != "published":
            raise HoleInteractionServiceError("post_not_available", "目标帖子不存在或非公开状态")

        # 3. Verify credential for consumption (expected_service=hole_comment)
        try:
            verified = verify_consumption_credential(
                session=self.session,
                crypto_engine=self.crypto_engine,
                signer_verification_key_provider=self.signer_verification_key_provider,
                credential=credential,
                expected_service="hole_comment",
                now=now,
            )
        except ConsumptionCredentialVerificationError as err:
            raise HoleInteractionServiceError(err.code, err.message) from err

        now_utc = self._utc(now)
        sn_bytes = verified.sn_bytes
        sig_bytes = verified.signature_bytes

        # 4. Compute SM3 digests using CryptoEngine (no hashlib)
        key_hash = self.crypto_engine.sm3_digest(idempotency_key.encode("utf-8"))
        canonical_req = (
            f"comment|{post_id}|{content}|{verified.normalized_sn}|{verified.service}|{verified.period}|{credential.signature}"
        ).encode("utf-8")
        request_hash = self.crypto_engine.sm3_digest(canonical_req)

        # 5. Pre-transaction idempotency check
        existing_idemp = (
            self.session.query(HoleCommentIdempotency)
            .filter_by(key_hash=key_hash)
            .one_or_none()
        )
        if existing_idemp is not None:
            if self.crypto_engine.constant_time_equal(existing_idemp.request_hash, request_hash):
                comment = self.session.get(HoleComment, existing_idemp.comment_id)
                if comment is not None:
                    return comment
            raise HoleInteractionServiceError("idempotency_conflict", "同一幂等键已用于不同评论请求")

        # 6. Atomic database transaction
        try:
            with self._transaction():
                # Check ConsumedSN
                if self.session.get(ConsumedSN, (sn_bytes, verified.service)) is not None:
                    raise HoleInteractionServiceError("credential_consumed", "该凭证已消费，不能重复使用")

                consumed = ConsumedSN(
                    sn=sn_bytes,
                    service=verified.service,
                    consumed_at=now_utc,
                )
                self.session.add(consumed)

                comment = HoleComment(
                    id=str(uuid.uuid4()),
                    post_id=post_id,
                    content=content,
                    credential_sn=sn_bytes,
                    credential_service=verified.service,
                    credential_period=verified.period,
                    credential_signature=sig_bytes,
                    credential_prefix=verified.normalized_sn[:8],
                    credential_valid=True,
                    created_at=now_utc,
                )
                self.session.add(comment)

                idemp_record = HoleCommentIdempotency(
                    id=str(uuid.uuid4()),
                    key_hash=key_hash,
                    request_hash=request_hash,
                    comment_id=comment.id,
                    created_at=now_utc,
                )
                self.session.add(idemp_record)
                self.session.flush()

            return comment
        except IntegrityError as ie:
            self.session.rollback()
            # Race condition handling
            race_idemp = (
                self.session.query(HoleCommentIdempotency)
                .filter_by(key_hash=key_hash)
                .one_or_none()
            )
            if race_idemp is not None:
                if self.crypto_engine.constant_time_equal(race_idemp.request_hash, request_hash):
                    c = self.session.get(HoleComment, race_idemp.comment_id)
                    if c is not None:
                        return c
                raise HoleInteractionServiceError("idempotency_conflict", "同一幂等键已用于不同评论请求") from ie

            if self.session.get(ConsumedSN, (sn_bytes, verified.service)) is not None:
                raise HoleInteractionServiceError("credential_consumed", "该凭证已消费，不能重复使用") from ie
            raise HoleInteractionServiceError("conflict", "评论数据写入冲突") from ie
        except Exception:
            self.session.rollback()
            raise

    def list_comments(
        self,
        *,
        post_id: str,
        page: int = 1,
        page_size: int = 20,
    ) -> HoleCommentPage:
        try:
            uuid.UUID(post_id)
        except Exception:
            raise HoleInteractionServiceError("invalid_post_id", "帖子 ID 必须是合法 UUID")

        post = self.session.get(HolePost, post_id)
        if post is None or post.status != "published":
            raise HoleInteractionServiceError("post_not_found", "目标帖子不存在")

        if page < 1:
            page = 1
        if page_size < 1:
            page_size = 20
        elif page_size > 100:
            page_size = 100

        query = (
            self.session.query(HoleComment)
            .filter_by(post_id=post_id)
            .order_by(HoleComment.created_at.desc(), HoleComment.id.desc())
        )
        total = query.count()
        offset = (page - 1) * page_size
        items = query.offset(offset).limit(page_size).all() if offset < total else []

        return HoleCommentPage(
            items=[HoleCommentSchema.model_validate(c) for c in items],
            page=page,
            page_size=page_size,
            total=total,
        )

    def like_post(
        self,
        *,
        post_id: str,
        credential: CredentialProof,
        idempotency_key: str,
        now: datetime,
    ) -> None:
        # 1. Validate post_id, idempotency_key
        try:
            uuid.UUID(post_id)
        except Exception:
            raise HoleInteractionServiceError("invalid_post_id", "帖子 ID 必须是合法 UUID")

        if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
            raise HoleInteractionServiceError("invalid_idempotency_key", "幂等键长度必须在 16 至 128 字符之间")

        # 2. Check target post exists and is published
        post = self.session.get(HolePost, post_id)
        if post is None or post.status != "published":
            raise HoleInteractionServiceError("post_not_available", "目标帖子不存在或非公开状态")

        # 3. Verify credential for consumption (expected_service=hole_like)
        try:
            verified = verify_consumption_credential(
                session=self.session,
                crypto_engine=self.crypto_engine,
                signer_verification_key_provider=self.signer_verification_key_provider,
                credential=credential,
                expected_service="hole_like",
                now=now,
            )
        except ConsumptionCredentialVerificationError as err:
            raise HoleInteractionServiceError(err.code, err.message) from err

        now_utc = self._utc(now)
        sn_bytes = verified.sn_bytes
        sig_bytes = verified.signature_bytes

        # 4. Compute SM3 digests using CryptoEngine (no hashlib)
        key_hash = self.crypto_engine.sm3_digest(idempotency_key.encode("utf-8"))
        canonical_req = (
            f"like|{post_id}|{verified.normalized_sn}|{verified.service}|{verified.period}|{credential.signature}"
        ).encode("utf-8")
        request_hash = self.crypto_engine.sm3_digest(canonical_req)

        # 5. Pre-transaction idempotency check
        existing_idemp = (
            self.session.query(HoleLikeIdempotency)
            .filter_by(key_hash=key_hash)
            .one_or_none()
        )
        if existing_idemp is not None:
            if self.crypto_engine.constant_time_equal(existing_idemp.request_hash, request_hash):
                return
            raise HoleInteractionServiceError("idempotency_conflict", "同一幂等键已用于不同点赞请求")

        # 6. Atomic database transaction
        try:
            with self._transaction():
                # Recheck post status
                current_post = self.session.get(HolePost, post_id)
                if current_post is None or current_post.status != "published":
                    raise HoleInteractionServiceError("post_not_available", "目标帖子不存在或非公开状态")

                # Check ConsumedSN
                if self.session.get(ConsumedSN, (sn_bytes, verified.service)) is not None:
                    raise HoleInteractionServiceError("credential_consumed", "该凭证已消费，不能重复使用")

                consumed = ConsumedSN(
                    sn=sn_bytes,
                    service=verified.service,
                    consumed_at=now_utc,
                )
                self.session.add(consumed)

                like = HoleLike(
                    id=str(uuid.uuid4()),
                    post_id=post_id,
                    credential_sn=sn_bytes,
                    credential_service=verified.service,
                    credential_period=verified.period,
                    credential_signature=sig_bytes,
                    created_at=now_utc,
                )
                self.session.add(like)

                idemp_record = HoleLikeIdempotency(
                    id=str(uuid.uuid4()),
                    key_hash=key_hash,
                    request_hash=request_hash,
                    like_id=like.id,
                    created_at=now_utc,
                )
                self.session.add(idemp_record)
                self.session.flush()

            return
        except IntegrityError as ie:
            self.session.rollback()
            # Race condition handling
            race_idemp = (
                self.session.query(HoleLikeIdempotency)
                .filter_by(key_hash=key_hash)
                .one_or_none()
            )
            if race_idemp is not None:
                if self.crypto_engine.constant_time_equal(race_idemp.request_hash, request_hash):
                    return
                raise HoleInteractionServiceError("idempotency_conflict", "同一幂等键已用于不同点赞请求") from ie

            if self.session.get(ConsumedSN, (sn_bytes, verified.service)) is not None:
                raise HoleInteractionServiceError("credential_consumed", "该凭证已消费，不能重复使用") from ie
            raise HoleInteractionServiceError("conflict", "点赞数据写入冲突") from ie
        except Exception:
            self.session.rollback()
            raise

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
