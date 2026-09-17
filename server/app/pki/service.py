from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, object_session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import MAX_DER_CERTIFICATE_SIZE
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord, CrlSnapshot
from app.models.user import User
from app.pki.errors import (
    PkiConfigurationError,
    PkiConflictError,
    PkiNotFoundError,
    PkiValidationError,
)
from app.pki.material import PlatformCAMaterialProvider
from app.pki.types import (
    CertificateVerification,
    IssuedUserCertificate,
    PlatformCAMaterial,
    USER_IDENTITY_KEY_USAGE,
)

_ALLOWED_ROLES = {"student", "admin", "teacher", "system"}
_CA_KEY_USAGE = ("keyCertSign", "cRLSign")


class PlatformCAService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        material_provider: PlatformCAMaterialProvider,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.material_provider = material_provider

    def register_platform_ca(self, verification_time: datetime) -> CertificateRecord:
        verification_timestamp = _timestamp(verification_time)
        with self.material_provider.unlocked() as material:
            system_user = self._require_system_user(material)
            try:
                verified = self.crypto_engine.cert_chain_verify(
                    material.certificate_der,
                    (),
                    material.certificate_der,
                    verification_timestamp,
                    _CA_KEY_USAGE,
                )
            except CryptoBridgeError as error:
                if error.code is BridgeErrorCode.CERT_INVALID:
                    raise PkiConfigurationError("ca_certificate_invalid") from None
                raise
            if not verified:
                raise PkiConfigurationError("ca_certificate_invalid")

            existing = self.session.get(CertificateRecord, material.certificate_serial)
            if existing is not None:
                if (
                    existing.kind == "platform_ca"
                    and existing.certificate_der == material.certificate_der
                ):
                    return existing
                raise PkiConflictError("certificate_serial_conflict")

            try:
                with self.session.begin_nested():
                    record = CertificateRecord(
                        serial=material.certificate_serial,
                        subject_user_id=system_user.id,
                        issuer_serial=material.certificate_serial,
                        kind="platform_ca",
                        certificate_der=material.certificate_der,
                        key_usage=",".join(_CA_KEY_USAGE),
                        not_before=_utc_datetime(material.not_before),
                        not_after=_utc_datetime(material.not_after),
                        status="active",
                    )
                    self.session.add(record)
                    detail_hash = self._detail_hash(
                        "pki.ca.register", material.certificate_serial, system_user.id
                    )
                    self.session.add(
                        AuditLog(
                            actor=system_user.id,
                            action="pki.ca.register",
                            target=f"certificate:{material.certificate_serial}",
                            detail_hash=detail_hash,
                        )
                    )
                    self.session.flush()
                    return record
            except IntegrityError:
                raise PkiConflictError("certificate_serial_conflict") from None

    def issue_user_certificate(
        self,
        user_id: str,
        role: str,
        private_key: bytes,
        public_key: bytes,
        not_before: datetime,
        not_after: datetime,
    ) -> IssuedUserCertificate:
        _require_uuid(user_id)
        if not isinstance(role, str) or role not in _ALLOWED_ROLES:
            raise PkiValidationError("role_invalid")
        not_before_timestamp = _timestamp(not_before)
        not_after_timestamp = _timestamp(not_after)
        if not_after_timestamp <= not_before_timestamp:
            raise PkiValidationError("validity_invalid")

        with self.material_provider.unlocked() as material:
            ca_record = self._require_active_ca(material)
            csr_der = self.crypto_engine.csr_create(
                private_key, public_key, common_name=user_id, role=role
            )
            certificate = self.crypto_engine.cert_sign(
                csr_der,
                ca_record.certificate_der,
                material.private_key,
                not_before_timestamp,
                not_after_timestamp,
                USER_IDENTITY_KEY_USAGE,
            )
            try:
                verified = self.crypto_engine.cert_chain_verify(
                    certificate.der,
                    (ca_record.certificate_der,),
                    ca_record.certificate_der,
                    not_before_timestamp,
                    USER_IDENTITY_KEY_USAGE,
                )
            except CryptoBridgeError as error:
                if error.code is BridgeErrorCode.CERT_INVALID:
                    raise PkiValidationError("certificate_invalid") from None
                raise
            if not verified:
                raise PkiValidationError("certificate_invalid")
            return IssuedUserCertificate(
                subject_user_id=user_id,
                role=role,
                issuer_serial=material.certificate_serial,
                key_usage=USER_IDENTITY_KEY_USAGE,
                certificate=certificate,
            )

    def record_issued_certificate(
        self, user: User, issued: IssuedUserCertificate
    ) -> CertificateRecord:
        if object_session(user) is not self.session:
            raise PkiValidationError("user_not_in_session")
        if user.id != issued.subject_user_id or user.role != issued.role:
            raise PkiValidationError("certificate_subject_mismatch")
        if issued.key_usage != USER_IDENTITY_KEY_USAGE:
            raise PkiValidationError("key_usage_invalid")
        ca_record = self.session.query(CertificateRecord).filter(
            CertificateRecord.serial == issued.issuer_serial,
            CertificateRecord.kind == "platform_ca",
            CertificateRecord.status == "active",
        ).one_or_none()
        if ca_record is None:
            raise PkiConfigurationError("ca_not_registered")
        system_user = self.session.get(User, ca_record.subject_user_id)
        if system_user is None or system_user.role != "system":
            raise PkiConfigurationError("ca_system_user_invalid")

        try:
            with self.session.begin_nested():
                record = CertificateRecord(
                    serial=issued.certificate.serial,
                    subject_user_id=user.id,
                    issuer_serial=issued.issuer_serial,
                    kind="user_identity",
                    certificate_der=issued.certificate.der,
                    key_usage=",".join(issued.key_usage),
                    not_before=_utc_datetime(issued.certificate.not_before),
                    not_after=_utc_datetime(issued.certificate.not_after),
                    status="active",
                )
                self.session.add(record)
                user.cert_serial = issued.certificate.serial
                self.session.add(
                    AuditLog(
                        actor=system_user.id,
                        action="pki.certificate.issue",
                        target=f"user:{user.id}",
                        detail_hash=self._detail_hash(
                            "pki.certificate.issue", issued.certificate.serial, user.id
                        ),
                    )
                )
                self.session.flush()
                return record
        except IntegrityError:
            raise PkiConflictError("certificate_serial_conflict") from None

    def verify_certificate(
        self,
        certificate_der: bytes,
        verification_time: datetime,
        required_key_usage: tuple[str, ...],
    ) -> CertificateVerification:
        if not isinstance(certificate_der, bytes) or not certificate_der or len(certificate_der) > MAX_DER_CERTIFICATE_SIZE:
            raise PkiValidationError("certificate_der_invalid")
        _require_key_usage(required_key_usage)
        verification_timestamp = _timestamp(verification_time)
        ca_record = self.session.query(CertificateRecord).filter(
            CertificateRecord.kind == "platform_ca",
            CertificateRecord.status == "active",
        ).order_by(CertificateRecord.created_at.desc()).first()
        if ca_record is None:
            raise PkiConfigurationError("ca_not_registered")
        record = self.session.query(CertificateRecord).filter(
            CertificateRecord.certificate_der == certificate_der
        ).one_or_none()

        try:
            chain_valid = self.crypto_engine.cert_chain_verify(
                certificate_der,
                (ca_record.certificate_der,),
                ca_record.certificate_der,
                verification_timestamp,
                required_key_usage,
            )
        except CryptoBridgeError as error:
            if error.code is BridgeErrorCode.CERT_INVALID:
                return self._invalid_or_expired(record, verification_time)
            raise
        if not chain_valid:
            return self._invalid_or_expired(record, verification_time)

        snapshot = self._latest_crl(ca_record.serial)
        if snapshot is not None:
            try:
                crl_valid = self.crypto_engine.crl_verify(
                    certificate_der, snapshot.crl_der, verification_timestamp
                )
            except CryptoBridgeError as error:
                if error.code is BridgeErrorCode.CERT_REVOKED:
                    return CertificateVerification(False, "revoked", record.serial if record else None)
                raise
            if not crl_valid:
                return CertificateVerification(False, "revoked", record.serial if record else None)
        if record is not None:
            if record.status == "revoked":
                return CertificateVerification(False, "revoked", record.serial)
            if _is_before(record.not_after, verification_time):
                return CertificateVerification(False, "expired", record.serial)
        return CertificateVerification(True, "active", record.serial if record else None)

    def revoke_certificate(
        self,
        serial: str,
        reason: str,
        operator_user_id: str,
        this_update: datetime,
        next_update: datetime,
    ) -> CrlSnapshot:
        record = self.session.get(CertificateRecord, serial)
        if record is None or record.kind != "user_identity":
            raise PkiNotFoundError("certificate_not_found")
        if record.status == "revoked":
            snapshot = self._latest_crl(record.issuer_serial)
            if snapshot is None:
                raise PkiConfigurationError("crl_not_found")
            return snapshot
        operator = self.session.get(User, operator_user_id)
        if operator is None:
            raise PkiNotFoundError("operator_not_found")
        normalized_reason = reason.strip() if isinstance(reason, str) else ""
        if not 1 <= len(normalized_reason) <= 500:
            raise PkiValidationError("reason_invalid")
        this_timestamp = _timestamp(this_update)
        next_timestamp = _timestamp(next_update)
        if next_timestamp <= this_timestamp:
            raise PkiValidationError("crl_validity_invalid")

        with self.material_provider.unlocked() as material:
            ca_record = self._require_active_ca(material)
            if ca_record.serial != record.issuer_serial:
                raise PkiConfigurationError("ca_mismatch")
            revoked_serials = {
                value
                for (value,) in self.session.query(CertificateRecord.serial).filter(
                    CertificateRecord.issuer_serial == record.issuer_serial,
                    CertificateRecord.status == "revoked",
                ).all()
            }
            revoked_serials.add(record.serial)
            revoked_tuple = tuple(sorted(revoked_serials))
            try:
                artifact = self.crypto_engine.crl_create(
                    revoked_tuple,
                    ca_record.certificate_der,
                    material.private_key,
                    this_timestamp,
                    next_timestamp,
                )
                try:
                    confirmed = self.crypto_engine.crl_verify(
                        record.certificate_der, artifact.der, this_timestamp
                    )
                except CryptoBridgeError as error:
                    if error.code is BridgeErrorCode.CERT_REVOKED:
                        confirmed = False
                    else:
                        raise
                if confirmed:
                    raise PkiValidationError("revocation_not_confirmed")
                with self.session.begin_nested():
                    record.status = "revoked"
                    record.revoked_at = this_update
                    record.revocation_reason = normalized_reason
                    snapshot = CrlSnapshot(
                        issuer_serial=record.issuer_serial,
                        crl_der=artifact.der,
                        this_update=this_update,
                        next_update=next_update,
                    )
                    self.session.add(snapshot)
                    self.session.add(
                        AuditLog(
                            actor=operator.id,
                            action="pki.certificate.revoke",
                            target=f"certificate:{record.serial}",
                            detail_hash=self._detail_hash(
                                "pki.certificate.revoke", record.serial, operator.id
                            ),
                        )
                    )
                    self.session.flush()
                    return snapshot
            except IntegrityError:
                raise PkiConflictError("certificate_revocation_conflict") from None

    def _require_system_user(self, material: PlatformCAMaterial) -> User:
        user = self.session.get(User, material.system_user_id)
        if user is None or user.role != "system" or user.cert_serial != material.certificate_serial:
            raise PkiConfigurationError("ca_system_user_invalid")
        return user

    def _require_active_ca(self, material: PlatformCAMaterial) -> CertificateRecord:
        self._require_system_user(material)
        record = self.session.get(CertificateRecord, material.certificate_serial)
        if (
            record is None
            or record.kind != "platform_ca"
            or record.status != "active"
            or record.certificate_der != material.certificate_der
        ):
            raise PkiConfigurationError("ca_not_registered")
        return record

    def _latest_crl(self, issuer_serial: str) -> CrlSnapshot | None:
        return self.session.query(CrlSnapshot).filter(
            CrlSnapshot.issuer_serial == issuer_serial
        ).order_by(CrlSnapshot.this_update.desc()).first()

    def _detail_hash(self, action: str, serial: str, actor: str) -> bytes:
        return self.crypto_engine.sm3_digest(
            "|".join((action, serial, actor)).encode("utf-8")
        )

    @staticmethod
    def _invalid_or_expired(
        record: CertificateRecord | None, verification_time: datetime
    ) -> CertificateVerification:
        if record is not None and _is_before(record.not_after, verification_time):
            return CertificateVerification(False, "expired", record.serial)
        return CertificateVerification(False, "invalid", record.serial if record else None)


def _require_uuid(value: str) -> None:
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError, TypeError):
        raise PkiValidationError("user_id_invalid") from None
    if str(parsed) != value:
        raise PkiValidationError("user_id_invalid")


def _timestamp(value: datetime) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PkiValidationError("datetime_timezone_required")
    return int(value.timestamp())


def _utc_datetime(value: int) -> datetime:
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _is_before(value: datetime, comparison: datetime) -> bool:
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    return value < comparison


def _require_key_usage(value: tuple[str, ...]) -> None:
    if not isinstance(value, tuple) or not value or not all(
        isinstance(item, str) and item for item in value
    ):
        raise PkiValidationError("key_usage_invalid")
