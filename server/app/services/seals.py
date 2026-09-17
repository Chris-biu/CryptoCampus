import base64
import json
import os
import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile

from app.core.errors import ApiError, crypto_error_to_api_error
from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.crypto.types import MAX_DER_CERTIFICATE_SIZE, SM2_PRIVATE_KEY_SIZE
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord
from app.models.seal import Seal
from app.models.user import User
from app.pki.service import PlatformCAService
from app.schemas.seal import SealResponse
from app.security.auth_dependencies import CurrentUser
from app.security.key_cache import PrivateKeyUnlockCacheProtocol

ALLOWED_MIME_TYPES = {
    "application/pdf": b"%PDF-",
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/jpeg": b"\xff\xd8\xff",
}


def validate_and_read_file(
    file: UploadFile | bytes,
    max_bytes: int,
    mime_type: str | None = None,
) -> bytes:
    if isinstance(file, bytes):
        raw_bytes = file
        content_type = mime_type
    else:
        content_type = mime_type or file.headers.get("content-type") or file.content_type
        # Read with bounded chunks
        chunks: list[bytes] = []
        total_len = 0
        chunk_size = 65536
        while True:
            chunk = file.file.read(chunk_size)
            if not chunk:
                break
            total_len += len(chunk)
            if total_len > max_bytes:
                raise ApiError(
                    status_code=413,
                    code="PAYLOAD_TOO_LARGE",
                    message=f"文件大小超过限制（当前上限 {max_bytes} 字节）",
                )
            chunks.append(chunk)
        raw_bytes = b"".join(chunks)

    if len(raw_bytes) == 0:
        raise ApiError(status_code=422, code="VALIDATION_ERROR", message="上传文件不能为空")

    if len(raw_bytes) > max_bytes:
        raise ApiError(
            status_code=413,
            code="PAYLOAD_TOO_LARGE",
            message=f"文件大小超过限制（当前上限 {max_bytes} 字节）",
        )

    # Magic bytes check
    detected_mime: str | None = None
    if raw_bytes.startswith(b"%PDF-"):
        detected_mime = "application/pdf"
    elif raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        detected_mime = "image/png"
    elif raw_bytes.startswith(b"\xff\xd8\xff"):
        detected_mime = "image/jpeg"

    if detected_mime is None:
        raise ApiError(
            status_code=422,
            code="VALIDATION_ERROR",
            message="不支持的文件格式或文件头与类型不匹配",
        )

    if content_type and content_type.lower() != detected_mime:
        raise ApiError(
            status_code=422,
            code="VALIDATION_ERROR",
            message="声明的 MIME 类型与文件头魔数不匹配",
        )

    return raw_bytes


def encode_seal_payload(
    file_digest: bytes, certificate_der: bytes, timestamp_unix: int
) -> bytes:
    if not isinstance(file_digest, bytes) or len(file_digest) != 32:
        raise ValueError("file_digest must be exactly 32 bytes")
    if not isinstance(certificate_der, bytes) or not (0 < len(certificate_der) <= 65536):
        raise ValueError("certificate_der must be between 1 and 65536 bytes")
    if not isinstance(timestamp_unix, int) or timestamp_unix < 0:
        raise ValueError("timestamp_unix must be a non-negative integer")

    return (
        b"CryptoCampus-Seal-v1\x00"
        + struct.pack(">I", len(file_digest))
        + file_digest
        + struct.pack(">I", len(certificate_der))
        + certificate_der
        + struct.pack(">Q", timestamp_unix)
    )


def generate_sidecar_bytes(seal: Seal) -> bytes:
    ts_str = (
        seal.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if seal.timestamp.tzinfo
        else seal.timestamp.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    payload = {
        "certificate": base64.b64encode(seal.certificate_der).decode("ascii"),
        "digest": base64.b64encode(seal.digest).decode("ascii"),
        "digest_algorithm": seal.digest_algorithm,
        "id": seal.id,
        "signature": base64.b64encode(seal.signature).decode("ascii"),
        "signature_algorithm": seal.signature_algorithm,
        "timestamp": ts_str,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _seal_to_response(seal: Seal) -> SealResponse:
    ts_str = (
        seal.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if seal.timestamp.tzinfo
        else seal.timestamp.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    return SealResponse(
        id=seal.id,
        digest_algorithm="SM3",
        digest=base64.b64encode(seal.digest).decode("ascii"),
        signature_algorithm=seal.signature_algorithm,  # type: ignore[arg-type]
        signature=base64.b64encode(seal.signature).decode("ascii"),
        certificate=base64.b64encode(seal.certificate_der).decode("ascii"),
        timestamp=ts_str,
    )


@dataclass(frozen=True)
class SealSignerMaterial:
    user_id: str
    certificate_der: bytes
    private_key: bytes = field(repr=False)


@runtime_checkable
class SealSignerMaterialProvider(Protocol):
    def get_seal_material(self, profile: str) -> SealSignerMaterial | None: ...


class DefaultSealSignerMaterialProvider:
    def get_seal_material(self, profile: str) -> SealSignerMaterial | None:
        return None


class FileSealSignerMaterialProvider:
    """Load department/academic seal identities from read-only deployment files."""

    _PROFILES = frozenset({"department", "academic"})

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    def get_seal_material(self, profile: str) -> SealSignerMaterial | None:
        if profile not in self._PROFILES:
            return None
        try:
            manifest_path = self._directory / f"{profile}.json"
            certificate_path = self._directory / f"{profile}.der"
            private_key_path = self._directory / f"{profile}.key"
            if (
                not manifest_path.is_file()
                or not certificate_path.is_file()
                or not private_key_path.is_file()
                or manifest_path.stat().st_size <= 0
                or manifest_path.stat().st_size > 1024
                or certificate_path.stat().st_size <= 0
                or certificate_path.stat().st_size > MAX_DER_CERTIFICATE_SIZE
                or private_key_path.stat().st_size != SM2_PRIVATE_KEY_SIZE
            ):
                return None
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict) or set(manifest) != {"user_id"}:
                return None
            user_id = manifest["user_id"]
            if not isinstance(user_id, str) or str(UUID(user_id)) != user_id.lower():
                return None
            certificate_der = certificate_path.read_bytes()
            private_key = private_key_path.read_bytes()
            if (
                not certificate_der
                or len(certificate_der) > MAX_DER_CERTIFICATE_SIZE
                or len(private_key) != SM2_PRIVATE_KEY_SIZE
            ):
                return None
            return SealSignerMaterial(
                user_id=user_id,
                certificate_der=certificate_der,
                private_key=private_key,
            )
        except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return None


_DEFAULT_SIGNER_MATERIAL_PROVIDER = FileSealSignerMaterialProvider(
    Path(
        os.getenv(
            "CRYPTOCAMPUS_SEAL_MATERIAL_DIR",
            "/run/secrets/cryptocampus/seal_materials",
        )
    )
)


def get_default_seal_signer_material_provider() -> SealSignerMaterialProvider:
    return _DEFAULT_SIGNER_MATERIAL_PROVIDER


class SealService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        ca_service: PlatformCAService,
        key_cache: PrivateKeyUnlockCacheProtocol,
        seal_material_provider: SealSignerMaterialProvider | None = None,
        max_bytes: int = 10485760,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.ca_service = ca_service
        self.key_cache = key_cache
        self.seal_material_provider = (
            seal_material_provider or _DEFAULT_SIGNER_MATERIAL_PROVIDER
        )
        self.max_bytes = max_bytes

    def create_seal(
        self,
        current_user: CurrentUser,
        file_bytes: UploadFile | bytes,
        mime_type: str | None = None,
        seal_profile: str = "personal",
        pqc_mode: bool = False,
        output_format: str = "sidecar",
        idempotency_key: str = "",
    ) -> SealResponse:
        if current_user.status != "active":
            raise ApiError(403, "FORBIDDEN", "当前用户状态非 active")

        # PQC Gate
        if pqc_mode:
            raise ApiError(503, "CCB_UNSUPPORTED", "抗量子签章能力暂未就绪")

        if output_format not in ("sidecar", "qr", "pdf_signature_page"):
            raise ApiError(422, "VALIDATION_ERROR", "不支持的输出格式")

        if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
            raise ApiError(
                422, "VALIDATION_ERROR", "Idempotency-Key 长度必须为 16 至 128 个字符"
            )

        if seal_profile not in ("personal", "department", "academic"):
            raise ApiError(422, "VALIDATION_ERROR", "不支持的签章主体类型")

        # Role matrix check
        if seal_profile == "personal":
            if current_user.role not in ("student", "admin", "teacher"):
                raise ApiError(403, "FORBIDDEN", "无权限使用个人签章主体")
        elif seal_profile == "department":
            if current_user.role not in ("admin", "teacher"):
                raise ApiError(403, "FORBIDDEN", "无权限使用部门口径章主体")
        elif seal_profile == "academic":
            if current_user.role != "teacher":
                raise ApiError(403, "FORBIDDEN", "无权限使用教务口径章主体")

        # Read and validate uploaded file
        raw_file = validate_and_read_file(file_bytes, self.max_bytes, mime_type)

        # PDF signature page gate
        if output_format == "pdf_signature_page":
            if not raw_file.startswith(b"%PDF-"):
                raise ApiError(422, "VALIDATION_ERROR", "pdf_signature_page 只接受 PDF 文件")
            raise ApiError(503, "CCB_UNSUPPORTED", "PDF附加签章页能力暂未就绪")

        file_buf: bytes = raw_file
        signer_key: bytes = b""
        payload_buf: bytes = b""

        try:
            # 1. SM3 digest of file
            file_digest = self.crypto_engine.sm3_digest(file_buf)

            # 2. Idempotency key digest & request fingerprint
            idemp_digest = self.crypto_engine.sm3_digest(
                idempotency_key.encode("utf-8")
            )
            fingerprint_payload = (
                file_digest
                + seal_profile.encode("utf-8")
                + (b"\x01" if pqc_mode else b"\x00")
                + output_format.encode("utf-8")
            )
            req_fingerprint = self.crypto_engine.sm3_digest(fingerprint_payload)

            # 3. Resolve signer identity, certificate and private key
            now = datetime.now(timezone.utc)
            if seal_profile == "personal":
                signer_user_id = current_user.user_id
                user = self.session.get(User, current_user.user_id)
                if user is None or not user.cert_serial:
                    raise ApiError(503, "SERVICE_UNAVAILABLE", "未找到有效用户证书")
                cert_record = self.session.get(CertificateRecord, user.cert_serial)
                if (
                    cert_record is None
                    or cert_record.status != "active"
                    or cert_record.kind != "user_identity"
                ):
                    raise ApiError(503, "SERVICE_UNAVAILABLE", "用户证书非激活状态")
                certificate_der = cert_record.certificate_der
                key_from_cache = self.key_cache.get(current_user.user_id, now)
                if not key_from_cache:
                    raise ApiError(
                        503,
                        "SERVICE_UNAVAILABLE",
                        "用户私钥未解锁或已过期，请重新登录解锁",
                    )
                signer_key = key_from_cache
            else:
                material = self.seal_material_provider.get_seal_material(seal_profile)
                if (
                    material is None
                    or not material.certificate_der
                    or not material.private_key
                    or not material.user_id
                ):
                    raise ApiError(
                        503,
                        "SERVICE_UNAVAILABLE",
                        f"未配置或无法解锁{seal_profile}签章主体材料",
                    )
                signer_user_id = material.user_id
                certificate_der = material.certificate_der
                signer_key = material.private_key

            # 4. Check idempotency before signing
            existing = (
                self.session.query(Seal)
                .filter(
                    Seal.signer_user_id == signer_user_id,
                    Seal.idempotency_key_digest == idemp_digest,
                )
                .one_or_none()
            )
            if existing is not None:
                if existing.request_fingerprint == req_fingerprint:
                    return _seal_to_response(existing)
                raise ApiError(409, "CONFLICT", "同一幂等键已用于不同签章请求")

            # 5. Verify certificate chain, validity, key usage, and CRL
            verification = self.ca_service.verify_certificate(
                certificate_der, now, ("digitalSignature",)
            )
            if not verification.valid or verification.state != "active":
                if verification.state == "revoked":
                    raise ApiError(409, "CERTIFICATE_REVOKED", "签发者证书已被吊销")
                elif verification.state == "expired":
                    raise ApiError(409, "CERTIFICATE_EXPIRED", "签发者证书已过期")
                else:
                    raise ApiError(
                        409, "CERTIFICATE_INVALID", "签发者证书无效或用途不匹配"
                    )

            # 6. UTC Timestamp and deterministic seal payload
            timestamp_unix = int(now.timestamp())
            timestamp_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            payload_buf = encode_seal_payload(
                file_digest, certificate_der, timestamp_unix
            )

            # 7. SM3 digest of seal payload and SM2 sign
            signing_digest = self.crypto_engine.sm3_digest(payload_buf)
            try:
                signature = self.crypto_engine.sm2_sign(signer_key, signing_digest)
            except CryptoBridgeError as err:
                raise crypto_error_to_api_error(err) from None

            if len(signature) != 64:
                raise ApiError(
                    500, "CRYPTO_INTERNAL_ERROR", "密码引擎签名输出长度异常"
                )

            # 8. Persist Seal and AuditLog in atomic transaction
            seal_id = str(uuid.uuid4())
            seal_record = Seal(
                id=seal_id,
                signer_user_id=signer_user_id,
                seal_profile=seal_profile,
                digest_algorithm="SM3",
                digest=file_digest,
                signature_algorithm="SM3-with-SM2",
                signature=signature,
                certificate_der=certificate_der,
                timestamp=now,
                output_format=output_format,
                idempotency_key_digest=idemp_digest,
                request_fingerprint=req_fingerprint,
                created_at=now,
            )

            audit_detail = (
                f"action=verify.seal.create|seal_id={seal_id}|"
                f"file_digest={file_digest.hex()}|sig_algo=SM3-with-SM2|ts={timestamp_iso}"
            ).encode("utf-8")
            detail_hash = self.crypto_engine.sm3_digest(audit_detail)
            audit_record = AuditLog(
                actor=current_user.user_id,
                action="verify.seal.create",
                target=f"seal:{seal_id}",
                detail_hash=detail_hash,
                ts=now,
            )

            try:
                with self.session.begin_nested():
                    self.session.add(seal_record)
                    self.session.add(audit_record)
                    self.session.flush()
                self.session.commit()
            except IntegrityError:
                self.session.rollback()
                existing = (
                    self.session.query(Seal)
                    .filter(
                        Seal.signer_user_id == signer_user_id,
                        Seal.idempotency_key_digest == idemp_digest,
                    )
                    .one_or_none()
                )
                if existing and existing.request_fingerprint == req_fingerprint:
                    return _seal_to_response(existing)
                raise ApiError(409, "CONFLICT", "幂等键并发冲突") from None
            except Exception:
                self.session.rollback()
                raise

            return _seal_to_response(seal_record)

        finally:
            file_buf = b""
            signer_key = b""
            payload_buf = b""

    def get_seal(self, seal_id: str) -> SealResponse:
        seal = self.session.get(Seal, seal_id)
        if seal is None:
            raise ApiError(404, "NOT_FOUND", "签章记录不存在")
        return _seal_to_response(seal)

    def get_sidecar(self, seal_id: str) -> tuple[bytes, str]:
        seal = self.session.get(Seal, seal_id)
        if seal is None:
            raise ApiError(404, "NOT_FOUND", "签章记录不存在")
        sidecar_bytes = generate_sidecar_bytes(seal)
        filename = f"seal-{seal.id}.ccseal"
        return sidecar_bytes, filename
