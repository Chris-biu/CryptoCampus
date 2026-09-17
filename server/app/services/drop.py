from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
import re
import secrets
import string
from typing import Iterator
from uuid import uuid4

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    MAX_DER_CERTIFICATE_SIZE,
    MAX_DROP_CONTENT_SIZE,
    MAX_SM2_ENC_KEY_SIZE,
    MLKEM_ENC_KEY_SIZE,
    MLKEM_PRIVATE_KEY_SIZE,
    SM2_PRIVATE_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
    EnvelopeArtifact,
)
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord
from app.models.drop import Drop, DropExtractIdempotency, DropIdempotency
from app.models.user import User
from app.pki.material import UnavailablePlatformCAMaterialProvider
from app.pki.service import PlatformCAService
from app.schemas.drop import (
    CreateDropResponse,
    DropMetadataResponse,
    ExtractedDropResponse,
)
from app.security.auth_dependencies import HTTP_ROLES
from app.security.key_cache import PrivateKeyUnlockCacheProtocol
from app.services.drop_destruction import DropDestructionService
from app.services.extract_cooldown import (
    ExtractAttemptGuard,
    SqlAlchemyExtractCooldownGuard,
)
from app.services.notification import NotificationService
from app.services.quota import QuotaError, QuotaService
from app.services.recipient_provider import (
    DefaultRecipientPrivateKeyProvider,
    RecipientPrivateKeyProvider,
)
from app.services.recipient_resolver import RecipientKeyResolver

_LINK_CODE_CHARS = string.ascii_letters + string.digits
_ACCESS_CODE_CHARS = string.ascii_uppercase + string.digits
_ALLOWED_TTL_POLICIES = frozenset({"burn_after_read", "hours_24", "days_7"})


from app.core.errors import DropServiceError
from app.schemas.inspect import InspectEvent, InspectStepInput
from app.services.inspection import InspectionRecorder, get_inspection_recorder


class DropService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        key_cache: PrivateKeyUnlockCacheProtocol,
        quota_service: QuotaService,
        recipient_resolver: RecipientKeyResolver,
        recipient_provider: RecipientPrivateKeyProvider | None = None,
        ca_service: PlatformCAService | None = None,
        cooldown_guard: ExtractAttemptGuard | None = None,
        destruction_service: DropDestructionService | None = None,
        notification_service: NotificationService | None = None,
        recorder: InspectionRecorder | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.key_cache = key_cache
        self.quota_service = quota_service
        self.recipient_resolver = recipient_resolver
        self.recipient_provider = recipient_provider or DefaultRecipientPrivateKeyProvider()
        self.cooldown_guard = cooldown_guard or SqlAlchemyExtractCooldownGuard(session)
        self.destruction_service = destruction_service or DropDestructionService(session, crypto_engine)
        self.notification_service = notification_service or NotificationService(session)
        self.recorder = recorder or get_inspection_recorder()
        if ca_service is None:
            self.ca_service = PlatformCAService(
                session=session,
                crypto_engine=crypto_engine,
                material_provider=UnavailablePlatformCAMaterialProvider(),
            )
        else:
            self.ca_service = ca_service

    def destroy_expired(self, *, now: datetime | None = None, limit: int = 100) -> int:
        if now is None:
            now = datetime.now(timezone.utc)
        return self.destruction_service.destroy_expired(now=now, limit=limit)


    def create_text_drop(
        self,
        *,
        sender_id: str,
        content: str,
        ttl_policy: str,
        pqc_mode: bool,
        access_password: str | None = None,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> CreateDropResponse:
        if now is None:
            now = datetime.now(timezone.utc)
        if not isinstance(content, str) or not content:
            raise DropServiceError("invalid_content", "文字内容不能为空")
        if len(content) > 1048576:
            raise DropServiceError("content_too_long", "文字内容超过最大字符限制")
        plaintext = content.encode("utf-8")
        if len(plaintext) > MAX_DROP_CONTENT_SIZE:
            raise DropServiceError("payload_too_large", "文字内容超过最大字节限制")

        return self._create_drop(
            sender_id=sender_id,
            plaintext=plaintext,
            kind="text",
            filename=None,
            ttl_policy=ttl_policy,
            pqc_mode=pqc_mode,
            access_password=access_password,
            idempotency_key=idempotency_key,
            operation="create_text",
            now=now,
        )

    def create_file_drop(
        self,
        *,
        sender_id: str,
        file_bytes: bytes,
        filename: str | None,
        ttl_policy: str,
        pqc_mode: bool,
        access_password: str | None = None,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> CreateDropResponse:
        if now is None:
            now = datetime.now(timezone.utc)
        if not isinstance(file_bytes, bytes) or not file_bytes:
            raise DropServiceError("invalid_file", "文件内容不能为空")
        if len(file_bytes) > MAX_DROP_CONTENT_SIZE:
            raise DropServiceError("payload_too_large", "文件超过课程上限 100 MiB")

        safe_filename = None
        if filename:
            safe_filename = os.path.basename(filename).strip()
            if len(safe_filename) > 255:
                safe_filename = safe_filename[:255]

        return self._create_drop(
            sender_id=sender_id,
            plaintext=file_bytes,
            kind="file",
            filename=safe_filename,
            ttl_policy=ttl_policy,
            pqc_mode=pqc_mode,
            access_password=access_password,
            idempotency_key=idempotency_key,
            operation="create_file",
            now=now,
        )

    def _create_drop(
        self,
        *,
        sender_id: str,
        plaintext: bytes,
        kind: str,
        filename: str | None,
        ttl_policy: str,
        pqc_mode: bool,
        access_password: str | None,
        idempotency_key: str,
        operation: str,
        now: datetime,
    ) -> CreateDropResponse:
        if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
            raise DropServiceError("invalid_idempotency_key", "幂等键长度必须在 16 至 128 之间")
        if ttl_policy not in _ALLOWED_TTL_POLICIES:
            raise DropServiceError("invalid_ttl_policy", "无效的有效期策略")
        if access_password is not None and not (1 <= len(access_password) <= 128):
            raise DropServiceError("invalid_access_password", "提取口令长度必须在 1 至 128 之间")

        # Check sender
        sender = self.session.get(User, sender_id)
        if sender is None or sender.status != "active" or sender.role not in HTTP_ROLES:
            raise DropServiceError("unauthorized", "未授权或用户状态异常")

        # Sender private key from unlock cache
        sender_private_key = self.key_cache.get(sender_id, now)
        if sender_private_key is None:
            raise DropServiceError("key_not_unlocked", "发送者私钥未解锁或已过期")

        # Sender active certificate
        cert_query = self.session.query(CertificateRecord).filter(
            CertificateRecord.subject_user_id == sender_id,
            CertificateRecord.status == "active",
            CertificateRecord.kind == "user_identity",
        )
        if sender.cert_serial:
            cert_query = cert_query.filter(CertificateRecord.serial == sender.cert_serial)
        sender_cert = cert_query.first()
        if sender_cert is None:
            raise DropServiceError("sender_certificate_invalid", "发送者身份证书不可用")

        # Check idempotency record
        key_hash = self.crypto_engine.sm3_digest(idempotency_key.encode("utf-8"))
        existing_idemp = self.session.query(DropIdempotency).filter_by(
            owner_user_id=sender_id, operation=operation, key_hash=key_hash
        ).first()
        if existing_idemp is not None:
            raise DropServiceError("idempotency_conflict", "幂等请求冲突")

        # Resolve recipient
        resolved = self.recipient_resolver.resolve_for_create(self.session, sender_id, pqc_mode)
        if resolved is None:
            raise DropServiceError("recipient_resolution_failed", "收件人解析失败")

        # Codes & factor generation
        link_code, link_code_hash = self._generate_link_code()
        access_code, access_code_hash = self._generate_access_code()

        salt: bytes | None = None
        access_factor: bytes | None = None
        if access_password is not None:
            salt = secrets.token_bytes(16)
            access_factor = self.crypto_engine.hkdf_sm3(
                access_password.encode("utf-8"), salt, b"drop-access-factor", 32
            )

        utc_now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)
        if ttl_policy == "burn_after_read":
            burn_after_read = True
            expires_at = None
        elif ttl_policy == "hours_24":
            burn_after_read = False
            expires_at = utc_now + timedelta(hours=24)
        else:  # days_7
            burn_after_read = False
            expires_at = utc_now + timedelta(days=7)

        drop_id = str(uuid4())

        try:
            with self._transaction():
                # 1. Reserve quota
                try:
                    self.quota_service.reserve(sender_id, "drop", utc_now)
                except QuotaError as qe:
                    if qe.code == "exhausted":
                        raise DropServiceError("quota_exhausted", "当日密信创建额度已达上限") from qe
                    raise DropServiceError(f"quota_{qe.code}", "额度服务异常") from qe

                # 2. Seal digital envelope
                artifact = self.crypto_engine.envelope_seal(
                    plaintext=plaintext,
                    recipient_sm2_public_key=resolved.sm2_public_key,
                    pqc_mode=pqc_mode,
                    recipient_mlkem_public_key=resolved.mlkem_public_key,
                    sender_private_key=sender_private_key,
                    sender_certificate_der=sender_cert.certificate_der,
                    access_factor=access_factor,
                )

                # 3. Create Drop record
                drop = Drop(
                    id=drop_id,
                    owner_user_id=sender_id,
                    recipient_user_id=resolved.recipient_user_id,
                    link_code_hash=link_code_hash,
                    kind=kind,
                    envelope_version=1,
                    ciphertext=artifact.ciphertext,
                    nonce=artifact.nonce,
                    tag=artifact.tag,
                    enc_key_sm2=artifact.enc_key_sm2,
                    enc_key_mlkem=artifact.enc_key_mlkem,
                    sender_signature=artifact.sender_signature,
                    sender_certificate_der=artifact.sender_certificate,
                    sender_cert_serial=sender_cert.serial,
                    recipient_sm2_fingerprint=resolved.sm2_fingerprint,
                    recipient_mlkem_fingerprint=resolved.mlkem_fingerprint,
                    access_code_hash=access_code_hash,
                    access_factor_salt=salt,
                    ttl_policy=ttl_policy,
                    burn_after_read=burn_after_read,
                    expires_at=expires_at,
                    filename=filename,
                    content_size=len(plaintext),
                    pqc_mode=pqc_mode,
                    status="available",
                    created_at=utc_now,
                )
                self.session.add(drop)

                # 4. Create DropIdempotency record
                req_summary = (
                    f"{operation}|{len(plaintext)}|{ttl_policy}|{pqc_mode}|"
                    f"{resolved.sm2_fingerprint.hex()}"
                ).encode("utf-8")
                req_hash = self.crypto_engine.sm3_digest(req_summary)
                idemp = DropIdempotency(
                    id=str(uuid4()),
                    owner_user_id=sender_id,
                    operation=operation,
                    key_hash=key_hash,
                    request_hash=req_hash,
                    drop_id=drop_id,
                    created_at=utc_now,
                )
                self.session.add(idemp)

                # 5. Audit log
                audit_summary = (
                    f"drop.create|{kind}|{len(plaintext)}|{ttl_policy}|{pqc_mode}|{sender_cert.serial}"
                ).encode("utf-8")
                audit_hash = self.crypto_engine.sm3_digest(audit_summary)
                audit = AuditLog(
                    actor=sender_id,
                    action="drop.create",
                    target=f"drop:{drop_id}",
                    detail_hash=audit_hash,
                )
                self.session.add(audit)

                import uuid as _uuid
                self.recorder.record(
                    event=InspectEvent(
                        operation="drop.envelope.create",
                        owner_user_id=_uuid.UUID(sender_id),
                        steps=(
                            InspectStepInput(
                                order=1,
                                name="数字信封封装",
                                algorithm="SM4-GCM" if not pqc_mode else "SM4-GCM/ML-KEM",
                                result="passed",
                                redacted_values={
                                    "content_bytes": len(plaintext),
                                    "pqc_mode": pqc_mode,
                                    "digest_prefix": self.crypto_engine.sm3_digest(plaintext)[:8].hex(),
                                    "recipient_cert_fingerprint": resolved.sm2_fingerprint.hex()[:32],
                                },
                            ),
                        ),
                        occurred_at=utc_now,
                    ),
                    session=self.session,
                )
                self.session.flush()

        except IntegrityError as ie:
            raise DropServiceError("idempotency_conflict", "幂等请求冲突") from ie
        finally:
            # Memory erasure of sensitive temporaries
            del plaintext
            del sender_private_key
            del access_factor

        return CreateDropResponse(
            id=drop_id,
            code=link_code,
            access_code=access_code,
            url=f"/d/{link_code}",
            expires_at=expires_at,
            pqc_mode=pqc_mode,
        )

    def _generate_link_code(self) -> tuple[str, bytes]:
        for _ in range(5):
            code = "".join(secrets.choice(_LINK_CODE_CHARS) for _ in range(16))
            code_hash = self.crypto_engine.sm3_digest(code.encode("utf-8"))
            if self.session.query(Drop).filter_by(link_code_hash=code_hash).first() is None:
                return code, code_hash
        raise DropServiceError("code_collision", "链接码生成冲突")

    def _generate_access_code(self) -> tuple[str, bytes]:
        code = "".join(secrets.choice(_ACCESS_CODE_CHARS) for _ in range(16))
        code_hash = self.crypto_engine.sm3_digest(code.encode("utf-8"))
        return code, code_hash

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        manager = self.session.begin_nested() if self.session.in_transaction() else self.session.begin()
        with manager:
            yield

    def get_drop_metadata(
        self,
        code: str,
        now: datetime | None = None,
    ) -> DropMetadataResponse:
        if now is None:
            now = datetime.now(timezone.utc)
        utc_now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)

        if not isinstance(code, str) or not re.fullmatch(r"^[A-Za-z0-9]{11,32}$", code):
            raise DropServiceError("not_found", "密信不存在或链接已失效")

        code_hash = self.crypto_engine.sm3_digest(code.encode("utf-8"))
        drop = self.session.query(Drop).filter_by(link_code_hash=code_hash).first()
        if drop is None:
            raise DropServiceError("not_found", "密信不存在或链接已失效")

        # Check expiry first (prevents cooling_down from being wrongly restored to available)
        if drop.expires_at is not None:
            expires_at = drop.expires_at.replace(tzinfo=timezone.utc) if drop.expires_at.tzinfo is None else drop.expires_at.astimezone(timezone.utc)
            if utc_now >= expires_at:
                with self._transaction():
                    self.destruction_service.destroy_single_expired(drop.id, now=utc_now)
                raise DropServiceError("not_found", "密信不存在或链接已失效")

        if drop.status == "cooling_down":
            try:
                self.cooldown_guard.before_attempt(drop, utc_now)
            except DropServiceError:
                raise DropServiceError("not_found", "密信不存在或链接已失效")

        if drop.status != "available":
            raise DropServiceError("not_found", "密信不存在或链接已失效")

        return DropMetadataResponse(
            code=code,
            kind=drop.kind,
            status=drop.status,
            requires_password=drop.access_factor_salt is not None,
            burn_after_read=drop.burn_after_read,
            filename=drop.filename,
            size=drop.content_size,
            expires_at=drop.expires_at,
        )

    def extract_drop(
        self,
        *,
        code: str,
        access_code: str,
        access_password: str | None = None,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> tuple[ExtractedDropResponse, bytes | None]:
        if now is None:
            now = datetime.now(timezone.utc)
        utc_now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)

        # 1. Parameter & code verification
        if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
            raise DropServiceError("invalid_idempotency_key", "幂等键长度必须在 16 至 128 之间")

        if not isinstance(code, str) or not re.fullmatch(r"^[A-Za-z0-9]{11,32}$", code):
            raise DropServiceError("not_found", "密信不存在或链接已失效")

        code_hash = self.crypto_engine.sm3_digest(code.encode("utf-8"))
        drop = self.session.query(Drop).filter_by(link_code_hash=code_hash).first()
        if drop is None:
            raise DropServiceError("not_found", "密信不存在或链接已失效")

        # 1.1 Expiry check before cooldown guard: expired drops must be destroyed and never reset to available
        if drop.expires_at is not None:
            expires_at = drop.expires_at.replace(tzinfo=timezone.utc) if drop.expires_at.tzinfo is None else drop.expires_at.astimezone(timezone.utc)
            if utc_now >= expires_at:
                with self._transaction():
                    self.destruction_service.destroy_single_expired(drop.id, now=utc_now)
                raise DropServiceError("not_found", "密信不存在或链接已失效")

        # 1.2 Cooldown guard: fail-closed before any heavy crypto/recipient operations
        self.cooldown_guard.before_attempt(drop, utc_now)

        if drop.status != "available":
            raise DropServiceError("not_found", "密信不存在或链接已失效")

        # 2. Check extract idempotency
        idemp_key_hash = self.crypto_engine.sm3_digest(idempotency_key.encode("utf-8"))
        existing_idemp = self.session.query(DropExtractIdempotency).filter_by(
            drop_id=drop.id, key_hash=idemp_key_hash
        ).first()

        pass_hash_str = ""
        if access_password:
            pass_hash_str = self.crypto_engine.sm3_digest(access_password.encode("utf-8")).hex()
        raw_access_code_bytes = access_code.encode("utf-8") if isinstance(access_code, str) else b""
        given_access_code_hash = self.crypto_engine.sm3_digest(raw_access_code_bytes)
        req_summary = f"extract|{drop.id}|{given_access_code_hash.hex()}|{pass_hash_str}".encode("utf-8")
        req_hash = self.crypto_engine.sm3_digest(req_summary)
        if existing_idemp is not None:
            if existing_idemp.request_hash != req_hash:
                raise DropServiceError("idempotency_conflict", "幂等请求冲突")

        # 3. Access code verification (constant time)
        if not isinstance(access_code, str) or not re.fullmatch(r"^[A-Z0-9-]{8,32}$", access_code):
            self.cooldown_guard.record_failure(drop.id, utc_now)
            raise DropServiceError("not_found", "密信不存在或提取码错误")

        code_valid = self.crypto_engine.constant_time_equal(given_access_code_hash, drop.access_code_hash)
        if not code_valid:
            self.cooldown_guard.record_failure(drop.id, utc_now)
            raise DropServiceError("not_found", "密信不存在或提取码错误")

        # 4. Optional password factor
        access_factor: bytes | None = None
        if drop.access_factor_salt is not None:
            if not access_password or not (1 <= len(access_password) <= 128):
                raise DropServiceError("password_required", "该密信需要提供提取口令")
            try:
                access_factor = self.crypto_engine.hkdf_sm3(
                    access_password.encode("utf-8"), drop.access_factor_salt, b"drop-access-factor", 32
                )
            except CryptoBridgeError as cbe:
                raise DropServiceError("kdf_failed", "口令因子派生失败") from cbe

        # 5. Envelope structure & lengths verification
        if drop.envelope_version != 1:
            raise DropServiceError("unsupported_envelope_version", "不支持的数字信封版本")

        if len(drop.nonce) != GCM_NONCE_SIZE or len(drop.tag) != GCM_TAG_SIZE:
            raise DropServiceError("invalid_envelope", "信封结构长度错误")

        if not drop.enc_key_sm2 or len(drop.enc_key_sm2) > MAX_SM2_ENC_KEY_SIZE:
            raise DropServiceError("invalid_envelope", "SM2 封装分量长度错误")

        if len(drop.sender_signature) != SM2_SIGNATURE_SIZE:
            raise DropServiceError("invalid_envelope", "发送者签名长度错误")

        if not drop.sender_certificate_der or len(drop.sender_certificate_der) > MAX_DER_CERTIFICATE_SIZE:
            raise DropServiceError("invalid_envelope", "证书长度超限")

        if drop.pqc_mode:
            if drop.enc_key_mlkem is None or len(drop.enc_key_mlkem) != MLKEM_ENC_KEY_SIZE:
                raise DropServiceError("invalid_envelope", "ML-KEM 封装分量缺失或长度错误")
            if drop.recipient_mlkem_fingerprint is None or len(drop.recipient_mlkem_fingerprint) != 32:
                raise DropServiceError("invalid_envelope", "收件人 ML-KEM 指纹缺失")
        else:
            if drop.enc_key_mlkem is not None:
                raise DropServiceError("invalid_envelope", "非 PQC 模式不能包含 ML-KEM 分量")

        # 6. Check recipient user status (frozen/pending_deletion cannot unseal)
        recipient = self.session.get(User, drop.recipient_user_id)
        if recipient is None or recipient.status != "active":
            raise DropServiceError("key_unavailable", "收件人状态异常或已注销")

        # 7. Retrieve recipient private key via RecipientPrivateKeyProvider
        recipient_sm2_priv = self.recipient_provider.get_unlocked_private_key(
            recipient_user_id=drop.recipient_user_id,
            key_fingerprint=drop.recipient_sm2_fingerprint,
            now=utc_now,
        )
        if recipient_sm2_priv is None or len(recipient_sm2_priv) != SM2_PRIVATE_KEY_SIZE:
            raise DropServiceError("key_unavailable", "收件人私钥未授权或不可用")

        recipient_mlkem_priv: bytes | None = None
        if drop.pqc_mode:
            recipient_mlkem_priv = self.recipient_provider.get_unlocked_private_key(
                recipient_user_id=drop.recipient_user_id,
                key_fingerprint=drop.recipient_mlkem_fingerprint,
                now=utc_now,
            )
            if recipient_mlkem_priv is None or len(recipient_mlkem_priv) != MLKEM_PRIVATE_KEY_SIZE:
                raise DropServiceError("key_unavailable", "收件人抗量子私钥未授权或不可用")

        # 8. Certificate verification (chain, validity, digitalSignature, CRL)
        cert_verification = self.ca_service.verify_certificate(
            certificate_der=drop.sender_certificate_der,
            verification_time=utc_now,
            required_key_usage=("digitalSignature",),
        )
        if not cert_verification.valid:
            raise DropServiceError("certificate_invalid", "发送者证书无效或已被吊销")

        # 9. Verify sender signature
        sender_user = self.session.get(User, drop.owner_user_id)
        sender_pubkey = sender_user.pubkey if sender_user else None
        if not sender_pubkey or len(sender_pubkey) != 65:
            raise DropServiceError("certificate_invalid", "发送者公钥不可用")

        sig_valid = self.crypto_engine.sm2_verify(
            sender_pubkey,
            self.crypto_engine.sm3_digest(drop.ciphertext),
            drop.sender_signature,
        )
        if not sig_valid:
            raise DropServiceError("signature_invalid", "发送者签名验证失败")

        # 10. Digital envelope unseal via CryptoEngine.envelope_open
        artifact = EnvelopeArtifact(
            ciphertext=drop.ciphertext,
            nonce=drop.nonce,
            tag=drop.tag,
            enc_key_sm2=drop.enc_key_sm2,
            enc_key_mlkem=drop.enc_key_mlkem,
            sender_signature=drop.sender_signature,
            sender_certificate=drop.sender_certificate_der,
        )

        plaintext: bytes | None = None
        inspect_record_id = existing_idemp.inspect_record_id if existing_idemp else str(uuid4())

        try:
            try:
                plaintext = self.crypto_engine.envelope_open(
                    envelope=artifact,
                    recipient_sm2_private_key=recipient_sm2_priv,
                    pqc_mode=drop.pqc_mode,
                    recipient_mlkem_private_key=recipient_mlkem_priv,
                    access_factor=access_factor,
                )
            except CryptoBridgeError as cbe:
                raise DropServiceError("unseal_failed", "数字信封解封失败") from cbe

            if not isinstance(plaintext, bytes) or len(plaintext) == 0 or len(plaintext) > MAX_DROP_CONTENT_SIZE:
                raise DropServiceError("payload_too_large", "明文大小超出范围")

            # 11. Transaction: Destruction (if burn_after_read), Idempotency, AuditLog & Success Reset
            with self._transaction():
                if drop.burn_after_read:
                    self.destruction_service.destroy_after_success(
                        drop.id, now=utc_now, actor_id=drop.recipient_user_id
                    )

                if existing_idemp is None:
                    import uuid as _uuid
                    owner_uid = _uuid.UUID(drop.recipient_user_id) if drop.recipient_user_id else None
                    sender_cert_fp = (
                        self.crypto_engine.sm3_digest(drop.sender_certificate_der)[:16].hex()
                        if drop.sender_certificate_der
                        else (drop.sender_cert_serial or "none")
                    )
                    inspect_open_dto = self.recorder.record(
                        event=InspectEvent(
                            operation="drop.envelope.open",
                            owner_user_id=owner_uid,
                            steps=(
                                InspectStepInput(
                                    order=1,
                                    name="数字信封解封",
                                    algorithm="SM4-GCM" if not drop.pqc_mode else "SM4-GCM/ML-KEM",
                                    result="passed",
                                    redacted_values={
                                        "pqc_mode": drop.pqc_mode,
                                        "digest_prefix": self.crypto_engine.sm3_digest(plaintext)[:8].hex(),
                                        "sender_cert_fingerprint": sender_cert_fp,
                                        "signature_valid": True,
                                    },
                                ),
                            ),
                            occurred_at=utc_now,
                        ),
                        session=self.session,
                    )
                    inspect_record_id = inspect_open_dto.id
                else:
                    inspect_record_id = existing_idemp.inspect_record_id

                if existing_idemp is None:
                    audit_summary = (
                        f"drop.extract|{drop.kind}|{len(plaintext)}|{drop.pqc_mode}|{drop.sender_cert_serial}"
                    ).encode("utf-8")
                    audit_hash = self.crypto_engine.sm3_digest(audit_summary)
                    audit = AuditLog(
                        actor=drop.recipient_user_id,
                        action="drop.extract",
                        target=f"drop:{drop.id}",
                        detail_hash=audit_hash,
                        ts=utc_now,
                    )
                    self.session.add(audit)

                    idemp = DropExtractIdempotency(
                        id=str(uuid4()),
                        drop_id=drop.id,
                        key_hash=idemp_key_hash,
                        request_hash=req_hash,
                        inspect_record_id=inspect_record_id,
                        created_at=utc_now,
                    )
                    self.session.add(idemp)
                    self.session.flush()

                    self.notification_service.create_drop_extracted(
                        owner_user_id=drop.owner_user_id,
                        drop_id=drop.id,
                        source_event_id=idemp.id,
                        created_at=utc_now,
                    )

                self.cooldown_guard.record_success(drop.id, utc_now)

            if drop.kind == "text":
                content_str = plaintext.decode("utf-8")
                return (
                    ExtractedDropResponse(
                        kind="text",
                        content=content_str,
                        download_url=None,
                        signature_valid=True,
                        certificate_valid=True,
                        inspect_record_id=inspect_record_id,
                    ),
                    None,
                )
            else:
                return (
                    ExtractedDropResponse(
                        kind="file",
                        content=None,
                        download_url=None,
                        signature_valid=True,
                        certificate_valid=True,
                        inspect_record_id=inspect_record_id,
                        filename=drop.filename,
                    ),
                    plaintext,
                )
        finally:
            # Memory erasure of sensitive temporaries
            del access_factor
            del recipient_sm2_priv
            del recipient_mlkem_priv

