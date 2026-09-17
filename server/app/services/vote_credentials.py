import base64
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, NamedTuple, Optional
from uuid import uuid4

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.models.audit import AuditLog
from app.models.user import User
from app.models.vote import VoteCredentialIssue, VoteRecord
from app.schemas.inspect import InspectEvent, InspectStepInput
from app.services.inspection import InspectionRecorder, get_inspection_recorder
from app.services.quota import QuotaError, QuotaService
from app.services.commitment_store import BlindCommitmentStore, get_commitment_store
from app.services.vote_scope import DefaultVoteScopePolicy, VoteScopeError, VoteScopePolicy
from app.services.vote_signer import VoteSignerMaterialProvider, get_vote_signer_provider


class VoteCredentialIssuanceError(Exception):
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


class VoteCredentialIssuanceService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        signer_provider: Optional[VoteSignerMaterialProvider] = None,
        scope_policy: Optional[VoteScopePolicy] = None,
        recorder: Optional[InspectionRecorder] = None,
        commitment_store: BlindCommitmentStore | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.signer_provider = signer_provider or get_vote_signer_provider()
        self.scope_policy = scope_policy or DefaultVoteScopePolicy(session)
        self.recorder = recorder or get_inspection_recorder()
        self.commitment_store = commitment_store or get_commitment_store()

    def issue(
        self,
        *,
        user_id: str,
        vote_id: str,
        service: str,
        period: str,
        blinded_message_b64: str,
        idempotency_key: str,
        now: datetime,
    ) -> IssuedCredential:
        now_utc = self._utc(now)

        # 1. User validation
        user = self.session.get(User, user_id)
        if user is None or user.status != "active":
            raise VoteCredentialIssuanceError("user_inactive", "用户不存在或状态不可用")
        if user.role not in ("student", "admin", "teacher"):
            raise VoteCredentialIssuanceError("permission_denied", "角色无权申领选票凭证")

        # 2. Service validation (strictly vote_ballot)
        if service != "vote_ballot":
            raise VoteCredentialIssuanceError("invalid_service", "投票凭证签发服务必须为 vote_ballot")

        # 3. Period validation (matches vote_id for vote credentials)
        if period != vote_id:
            raise VoteCredentialIssuanceError("invalid_period", "投票凭证申领周期必须为 vote_id")

        # 4. Idempotency-Key validation (16 to 128 characters)
        if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
            raise VoteCredentialIssuanceError("invalid_idempotency_key", "幂等键长度必须在 16 至 128 字符之间")

        # 5. Blinded message validation
        if not isinstance(blinded_message_b64, str) or not blinded_message_b64:
            raise VoteCredentialIssuanceError("invalid_blinded_message", "盲化消息不能为空")
        try:
            blinded_bytes = base64.b64decode(blinded_message_b64, validate=True)
            if not blinded_bytes:
                raise VoteCredentialIssuanceError("invalid_blinded_message", "盲化消息解码后不能为空")
        except Exception as err:
            if isinstance(err, VoteCredentialIssuanceError):
                raise
            raise VoteCredentialIssuanceError("invalid_blinded_message", "盲化消息必须是合法 base64 编码") from err

        # 两轮协议载荷：16B commitment_id || 32B c'。旧载荷仅供既有 Mock 单测；
        # 真实 HitlsCryptoEngine 在没有服务端 k 时会失败关闭。
        commitment_id = blinded_bytes[:16].hex() if len(blinded_bytes) == 48 else None

        canonical_b64 = base64.b64encode(blinded_bytes).decode("ascii")

        # 6. Vote existence and scope check
        vote = self.session.get(VoteRecord, vote_id)
        if vote is None:
            raise VoteCredentialIssuanceError("vote_not_found", "投票不存在")

        try:
            self.scope_policy.require_can_issue(user_id=user_id, vote_id=vote_id)
        except VoteScopeError as se:
            raise VoteCredentialIssuanceError(se.code, se.message) from se

        # 7. Compute cryptographic digests using CryptoEngine (strict: no hashlib)
        key_hash = self.crypto_engine.sm3_digest(idempotency_key.encode("utf-8"))
        request_hash = self.crypto_engine.sm3_digest(
            f"{vote_id}|{service}|{period}|{canonical_b64}".encode("utf-8")
        )

        # 8. Check existing issuance by unique(user_id, vote_id)
        existing = (
            self.session.query(VoteCredentialIssue)
            .filter_by(user_id=user_id, vote_id=vote_id)
            .one_or_none()
        )
        if existing is not None:
            if (
                self.crypto_engine.constant_time_equal(existing.key_hash, key_hash)
                and self.crypto_engine.constant_time_equal(existing.request_hash, request_hash)
            ):
                # Idempotent replay: return cached signature without re-reserving quota or signing
                return IssuedCredential(
                    blind_signature=existing.blind_signature,
                    algorithm=existing.algorithm,
                )
            # Same user and vote, but different key or request -> 409 Conflict
            raise VoteCredentialIssuanceError("credential_already_issued", "同一用户在同场投票仅能申领一次选票凭证")

        # 9. Deadline and status check (must be open and now < closes_at)
        closes_at_utc = self._utc(vote.closes_at)
        if vote.status != "open" or now_utc >= closes_at_utc:
            raise VoteCredentialIssuanceError("vote_closed", "投票已截止或不可用")

        # 10. Atomic transaction for quota reservation, blind signing, issue record, and audit log
        try:
            with self._transaction():
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
                    except Exception as error:
                        raise VoteCredentialIssuanceError(
                            "invalid_commitment", str(error)
                        ) from error

                # 10.1 Reserve quota: resource="vote_ballot", period=vote_id
                quota_service = QuotaService(self.session, digest=self.crypto_engine.sm3_digest)
                quota_service.reserve(user_id=user_id, resource="vote_ballot", now=now_utc, period=vote_id)

                # 10.2 Retrieve signer private key
                signer_key = self.signer_provider.get_signer_private_key(vote_id=vote_id)
                if signer_key is None or len(signer_key) != SM2_PRIVATE_KEY_SIZE:
                    raise VoteCredentialIssuanceError("engine_unavailable", "投票签发私钥不可用")

                # 10.3 Call CryptoEngine.blind_sign
                try:
                    blind_sig = self.crypto_engine.blind_sign(
                        blinded_message=blinded_bytes,
                        signer_private_key=signer_key,
                        secret_k=consumed_record.secret_k if consumed_record else None,
                    )
                except CryptoBridgeError as cbe:
                    raise VoteCredentialIssuanceError("engine_unavailable", "密码引擎不可用或盲签名失败") from cbe

                # 10.4 Write VoteCredentialIssue record
                issue_record = VoteCredentialIssue(
                    id=str(uuid4()),
                    vote_id=vote_id,
                    user_id=user_id,
                    key_hash=key_hash,
                    request_hash=request_hash,
                    blind_signature=blind_sig,
                    algorithm="SM2-BLIND-PROTOCOL-V1",
                    created_at=now_utc,
                )
                self.session.add(issue_record)

                # 10.5 Write AuditLog with SM3 digest (no sensitive plaintext, no SN, no blind factor)
                detail_hash = self.crypto_engine.sm3_digest(
                    f"vote.credential.issue|{user_id}|{vote_id}|{key_hash.hex()}".encode("utf-8")
                )
                audit = AuditLog(
                    actor=user_id,
                    action="vote.credential.issue",
                    target=f"vote:{vote_id}",
                    detail_hash=detail_hash,
                    ts=now_utc,
                )
                self.session.add(audit)

                import uuid as _uuid
                self.recorder.record(
                    event=InspectEvent(
                        operation="vote.credential.issue",
                        owner_user_id=_uuid.UUID(user_id),
                        steps=(
                            InspectStepInput(
                                order=1,
                                name="投票盲凭证签发",
                                algorithm="SM2-Blind-Sign",
                                result="passed",
                                redacted_values={
                                    "vote_scope": vote.scope,
                                    "credential_issued": True,
                                },
                            ),
                        ),
                        occurred_at=now_utc,
                    ),
                    session=self.session,
                )
                self.session.flush()

            self.session.commit()
            return IssuedCredential(
                blind_signature=blind_sig,
                algorithm="SM2-BLIND-PROTOCOL-V1",
            )
        except QuotaError as qe:
            self.session.rollback()
            if qe.code == "exhausted":
                existing_after_quota = (
                    self.session.query(VoteCredentialIssue)
                    .filter_by(user_id=user_id, vote_id=vote_id)
                    .one_or_none()
                )
                if existing_after_quota is not None:
                    if (
                        self.crypto_engine.constant_time_equal(existing_after_quota.key_hash, key_hash)
                        and self.crypto_engine.constant_time_equal(existing_after_quota.request_hash, request_hash)
                    ):
                        return IssuedCredential(
                            blind_signature=existing_after_quota.blind_signature,
                            algorithm=existing_after_quota.algorithm,
                        )
                    raise VoteCredentialIssuanceError(
                        "credential_already_issued", "同一用户在同场投票仅能申领一次选票凭证"
                    ) from qe
                raise VoteCredentialIssuanceError("quota_exhausted", "本场投票凭证额度已用尽") from qe
            raise VoteCredentialIssuanceError("internal_error", "额度扣减失败") from qe
        except IntegrityError as ie:
            self.session.rollback()
            # Race condition check on unique(user_id, vote_id)
            existing_after_race = (
                self.session.query(VoteCredentialIssue)
                .filter_by(user_id=user_id, vote_id=vote_id)
                .one_or_none()
            )
            if existing_after_race is not None:
                if (
                    self.crypto_engine.constant_time_equal(existing_after_race.key_hash, key_hash)
                    and self.crypto_engine.constant_time_equal(existing_after_race.request_hash, request_hash)
                ):
                    return IssuedCredential(
                        blind_signature=existing_after_race.blind_signature,
                        algorithm=existing_after_race.algorithm,
                    )
                raise VoteCredentialIssuanceError("credential_already_issued", "同一用户在同场投票仅能申领一次选票凭证") from ie
            raise VoteCredentialIssuanceError("internal_error", "并发数据写入冲突") from ie
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
