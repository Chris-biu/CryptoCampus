import base64
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, NamedTuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.models.audit import AuditLog
from app.models.credential import CredentialIssueIdempotency
from app.models.user import User
from app.services.quota import QuotaError, QuotaService
from app.services.commitment_store import BlindCommitmentStore, get_commitment_store
from app.services.signer_provider import (
    DefaultServerSignerKeyProvider,
    ServerSignerKeyProvider,
)


CREDENTIAL_QUOTA_RESOURCE = {
    "hole_post": "hole_credential",
    "hole_comment": "interaction_credential",
    "hole_like": "interaction_credential",
}


class CredentialIssuanceError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


class IssuedCredential(NamedTuple):
    blind_signature: bytes
    algorithm: str = "SM2-BLIND-PROTOCOL-V1"

    @property
    def blind_signature_b64(self) -> str:
        return base64.b64encode(self.blind_signature).decode("ascii")


class CredentialIssuanceService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        signer_key_provider: ServerSignerKeyProvider | None = None,
        commitment_store: BlindCommitmentStore | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.signer_key_provider = (
            signer_key_provider or DefaultServerSignerKeyProvider()
        )
        self.commitment_store = commitment_store or get_commitment_store()

    def issue(
        self,
        *,
        user_id: str,
        service: str,
        period: str,
        blinded_message_b64: str,
        idempotency_key: str,
        now: datetime,
    ) -> IssuedCredential:
        # 1. User validation
        user = self.session.get(User, user_id)
        if user is None or user.status != "active":
            raise CredentialIssuanceError("user_inactive", "用户不存在或处于不可用状态")

        # 2. Service check and quota resource mapping
        if service not in CREDENTIAL_QUOTA_RESOURCE:
            raise CredentialIssuanceError("invalid_service", f"不支持的凭证服务申领: {service}")
        quota_resource = CREDENTIAL_QUOTA_RESOURCE[service]

        # 3. Period check (must be server's current UTC date YYYY-MM-DD)
        now_utc = self._utc(now)
        current_period = now_utc.date().isoformat()
        if period != current_period:
            raise CredentialIssuanceError("invalid_period", "申领周期必须为服务端当前 UTC 日期")

        # 4. Idempotency-Key validation (16 to 128 characters)
        if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
            raise CredentialIssuanceError("invalid_idempotency_key", "幂等键长度必须在 16 至 128 字符之间")

        # 5. Base64 blinded message validation
        if not isinstance(blinded_message_b64, str) or not blinded_message_b64:
            raise CredentialIssuanceError("invalid_blinded_message", "盲化消息不能为空")
        try:
            blinded_bytes = base64.b64decode(blinded_message_b64, validate=True)
            if not blinded_bytes:
                raise CredentialIssuanceError("invalid_blinded_message", "盲化消息解码后不能为空")
        except Exception as err:
            if isinstance(err, CredentialIssuanceError):
                raise
            raise CredentialIssuanceError("invalid_blinded_message", "盲化消息不是合法 base64 编码") from err

        # ADR-0001: 16B commitment_id || 32B c'。旧形状仅保留给单元测试
        # MockCryptoEngine；真实 HitlsCryptoEngine 在缺少 secret_k 时会失败关闭。
        commitment_id = blinded_bytes[:16].hex() if len(blinded_bytes) == 48 else None

        # 6. Compute SM3 digests using CryptoEngine (strict: no hashlib)
        key_hash = self.crypto_engine.sm3_digest(idempotency_key.encode("utf-8"))
        request_hash = self.crypto_engine.sm3_digest(
            f"{service}|{period}|{blinded_message_b64}".encode("utf-8")
        )

        # 7. Check idempotency record before transaction
        existing = (
            self.session.query(CredentialIssueIdempotency)
            .filter_by(
                user_id=user_id,
                service=service,
                period=period,
                key_hash=key_hash,
            )
            .one_or_none()
        )
        if existing is not None:
            if self.crypto_engine.constant_time_equal(existing.request_hash, request_hash):
                # Idempotent replay: return existing signature without consuming quota
                return IssuedCredential(
                    blind_signature=existing.blind_signature,
                    algorithm="SM2-BLIND-PROTOCOL-V1",
                )
            raise CredentialIssuanceError("idempotency_conflict", "同一幂等键已用于不同申领请求")

        # 8. Atomic transaction for quota, commitment, engine blind_sign, idempotency record, and audit log
        try:
            with self._transaction():
                # 8.0 Consume commitment (ADR-0001: one-time consumption, anti-replay)
                consumed_record = None
                if commitment_id is not None:
                    try:
                        consumed_record = self.commitment_store.consume(
                            commitment_id=commitment_id,
                            user_id=user_id,
                            service=service,
                            period=period,
                            now=now_utc,
                        )
                    except Exception as ce:
                        raise CredentialIssuanceError("invalid_commitment", str(ce)) from ce

                # 8.1 Reserve quota
                quota_service = QuotaService(self.session, digest=self.crypto_engine.sm3_digest)
                try:
                    quota_service.reserve(user_id=user_id, resource=quota_resource, now=now_utc)
                except QuotaError as qe:
                    if qe.code == "exhausted":
                        raise CredentialIssuanceError("quota_exhausted", "当日盲签名凭证额度已用尽") from qe
                    raise CredentialIssuanceError("internal_error", "额度扣减失败") from qe

                # 8.2 Get controlled server signer private key
                signer_key = self.signer_key_provider.get_signer_private_key(service)
                if signer_key is None or len(signer_key) != SM2_PRIVATE_KEY_SIZE:
                    raise CredentialIssuanceError("engine_unavailable", "服务端盲签名私钥不可用")

                # 8.3 Call CryptoEngine.blind_sign
                try:
                    blind_sig = self.crypto_engine.blind_sign(
                        blinded_message=blinded_bytes,
                        signer_private_key=signer_key,
                        secret_k=consumed_record.secret_k if consumed_record else None,
                    )
                except CryptoBridgeError as cbe:
                    raise CredentialIssuanceError("engine_unavailable", "密码引擎不可用或盲签名失败") from cbe

                # 8.4 Create CredentialIssueIdempotency record
                idemp = CredentialIssueIdempotency(
                    user_id=user_id,
                    service=service,
                    period=period,
                    key_hash=key_hash,
                    request_hash=request_hash,
                    blind_signature=blind_sig,
                    created_at=now_utc,
                )
                self.session.add(idemp)

                # 8.5 Write AuditLog with SM3 digest (no sensitive plaintext)
                detail_hash = self.crypto_engine.sm3_digest(
                    f"credential.issue|{service}|{period}|{key_hash.hex()}".encode("utf-8")
                )
                audit = AuditLog(
                    actor=user_id,
                    action="credential.issue",
                    target=f"user:{user_id}",
                    detail_hash=detail_hash,
                    ts=now_utc,
                )
                self.session.add(audit)
                self.session.flush()

            self.session.commit()
            return IssuedCredential(
                blind_signature=blind_sig,
                algorithm="SM2-BLIND-PROTOCOL-V1",
            )
        except IntegrityError as ie:
            self.session.rollback()
            # Race condition check on unique constraint
            existing_after_race = (
                self.session.query(CredentialIssueIdempotency)
                .filter_by(
                    user_id=user_id,
                    service=service,
                    period=period,
                    key_hash=key_hash,
                )
                .one_or_none()
            )
            if existing_after_race is not None:
                if self.crypto_engine.constant_time_equal(
                    existing_after_race.request_hash, request_hash
                ):
                    return IssuedCredential(
                        blind_signature=existing_after_race.blind_signature,
                        algorithm="SM2-BLIND-PROTOCOL-V1",
                    )
                raise CredentialIssuanceError("idempotency_conflict", "同一幂等键已用于不同申领请求") from ie
            raise CredentialIssuanceError("internal_error", "并发数据写入冲突") from ie
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
