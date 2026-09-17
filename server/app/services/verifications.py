import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.models.certificate import CertificateRecord, CrlSnapshot
from app.models.user import User
from app.models.verification import VerificationRecord
from app.schemas.verification import VerificationResult, VerificationStep
from app.services.seals import encode_seal_payload


_SIDECAR_FIELDS = {
    "certificate",
    "digest",
    "digest_algorithm",
    "id",
    "signature",
    "signature_algorithm",
    "timestamp",
}
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_MAX_SIDECAR_BYTES = 131072


@dataclass(frozen=True)
class ParsedSeal:
    seal_id: str
    file_digest: bytes
    signature_algorithm: str
    signature: bytes
    certificate_der: bytes
    timestamp: datetime


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError("duplicate field")
        parsed[key] = value
    return parsed


def parse_seal_sidecar(raw: bytes) -> ParsedSeal:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_SIDECAR_BYTES:
        raise ApiError(422, "VALIDATION_ERROR", "签章侧车格式不合法")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
        if not isinstance(value, dict) or set(value) != _SIDECAR_FIELDS:
            raise ValueError("fields")
        if value["digest_algorithm"] != "SM3" or value["signature_algorithm"] not in {"SM3-with-SM2", "ML-DSA-65"}:
            raise ValueError("algorithm")
        for name in ("id", "digest", "signature", "certificate", "timestamp"):
            if not isinstance(value[name], str):
                raise ValueError(name)
        if not _TIMESTAMP_PATTERN.fullmatch(value["timestamp"]):
            raise ValueError("timestamp")
        if str(UUID(value["id"])) != value["id"]:
            raise ValueError("id")
        timestamp = datetime.strptime(value["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        digest = base64.b64decode(value["digest"], validate=True)
        signature = base64.b64decode(value["signature"], validate=True)
        certificate = base64.b64decode(value["certificate"], validate=True)
        if len(digest) != 32 or len(signature) != 64 or not certificate or len(certificate) > 65536:
            raise ValueError("length")
        return ParsedSeal(value["id"], digest, value["signature_algorithm"], signature, certificate, timestamp)
    except (UnicodeDecodeError, ValueError, KeyError, TypeError) as error:
        raise ApiError(422, "VALIDATION_ERROR", "签章侧车格式不合法") from error


class FiveStepVerificationService:
    def __init__(self, session: Session, crypto_engine: CryptoEngine, max_bytes: int) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.max_bytes = max_bytes

    def verify(self, file_bytes: bytes, seal_bytes: bytes) -> VerificationResult:
        if not isinstance(file_bytes, bytes) or len(file_bytes) > self.max_bytes:
            raise ApiError(413, "PAYLOAD_TOO_LARGE", f"文件大小超过限制（当前上限 {self.max_bytes} 字节）")
        seal = parse_seal_sidecar(seal_bytes)
        try:
            actual_digest = self.crypto_engine.sm3_digest(file_bytes)
            digest_passed = self.crypto_engine.constant_time_equal(actual_digest, seal.file_digest)
            certificate_record = self.session.query(CertificateRecord).filter(CertificateRecord.certificate_der == seal.certificate_der).one_or_none()
            user = self.session.get(User, certificate_record.subject_user_id) if certificate_record else None
            signature_passed = self._verify_signature(seal, user)
            chain_passed = self._verify_chain(seal)
            timestamp_passed = self._verify_timestamp(seal, certificate_record)
            revocation_passed = self._verify_revocation(seal, certificate_record)
        except CryptoBridgeError as error:
            raise ApiError(503, "SERVICE_UNAVAILABLE", "验证服务暂不可用") from error

        steps = [
            VerificationStep(name="digest", passed=digest_passed, message="文件摘要一致" if digest_passed else "文件摘要不一致"),
            VerificationStep(name="signature", passed=signature_passed, message="签名验证通过" if signature_passed else "签名验证未通过"),
            VerificationStep(name="certificate_chain", passed=chain_passed, message="证书链可信" if chain_passed else "证书链不可信或用途不符"),
            VerificationStep(name="timestamp", passed=timestamp_passed, message="签章时间有效" if timestamp_passed else "签章时间无效"),
            VerificationStep(name="revocation", passed=revocation_passed, message="证书在签章时未吊销" if revocation_passed else "证书在签章时已吊销或吊销状态不可验证"),
        ]
        valid = all(step.passed for step in steps)
        try:
            record_digest = self._record_digest(actual_digest, seal, steps)
        except CryptoBridgeError as error:
            raise ApiError(503, "SERVICE_UNAVAILABLE", "验证服务暂不可用") from error
        self.session.add(VerificationRecord(
            record_digest=record_digest, file_digest=actual_digest, seal_id=seal.seal_id,
            signature_algorithm=seal.signature_algorithm, digest_passed=digest_passed,
            signature_passed=signature_passed, certificate_chain_passed=chain_passed,
            timestamp_passed=timestamp_passed, revocation_passed=revocation_passed, valid=valid,
        ))
        try:
            self.session.commit()
        except Exception as error:
            self.session.rollback()
            raise ApiError(503, "SERVICE_UNAVAILABLE", "验证记录暂不可用") from error
        return VerificationResult(valid=valid, steps=steps, record_digest=record_digest.hex())

    def _verify_signature(self, seal: ParsedSeal, user: User | None) -> bool:
        if seal.signature_algorithm != "SM3-with-SM2" or user is None or not user.pubkey:
            return False
        payload = encode_seal_payload(seal.file_digest, seal.certificate_der, int(seal.timestamp.timestamp()))
        return self.crypto_engine.sm2_verify(user.pubkey, self.crypto_engine.sm3_digest(payload), seal.signature)

    def _verify_chain(self, seal: ParsedSeal) -> bool:
        root = self.session.query(CertificateRecord).filter(CertificateRecord.kind == "platform_ca", CertificateRecord.status == "active").order_by(CertificateRecord.created_at.desc()).first()
        if root is None:
            return False
        return self.crypto_engine.cert_chain_verify(seal.certificate_der, (root.certificate_der,), root.certificate_der, int(seal.timestamp.timestamp()), ("digitalSignature",))

    @staticmethod
    def _verify_timestamp(seal: ParsedSeal, record: CertificateRecord | None) -> bool:
        if record is None or seal.timestamp > datetime.now(timezone.utc):
            return False
        not_before = record.not_before if record.not_before.tzinfo else record.not_before.replace(tzinfo=timezone.utc)
        not_after = record.not_after if record.not_after.tzinfo else record.not_after.replace(tzinfo=timezone.utc)
        return not_before <= seal.timestamp <= not_after

    def _verify_revocation(self, seal: ParsedSeal, record: CertificateRecord | None) -> bool:
        if record is None:
            return False
        if record.status == "revoked" and record.revoked_at is not None:
            revoked_at = record.revoked_at if record.revoked_at.tzinfo else record.revoked_at.replace(tzinfo=timezone.utc)
            if revoked_at <= seal.timestamp:
                return False
        crl = self.session.query(CrlSnapshot).filter(CrlSnapshot.issuer_serial == record.issuer_serial).order_by(CrlSnapshot.this_update.desc()).first()
        if crl is None:
            return True
        try:
            return self.crypto_engine.crl_verify(seal.certificate_der, crl.crl_der, int(seal.timestamp.timestamp()))
        except CryptoBridgeError as error:
            if error.code.name == "CERT_REVOKED":
                return False
            raise

    def _record_digest(self, file_digest: bytes, seal: ParsedSeal, steps: list[VerificationStep]) -> bytes:
        payload = b"CryptoCampus-VerificationRecord-v1\x00" + file_digest + seal.seal_id.encode("ascii") + seal.signature_algorithm.encode("ascii") + bytes(step.passed for step in steps)
        return self.crypto_engine.sm3_digest(payload)
