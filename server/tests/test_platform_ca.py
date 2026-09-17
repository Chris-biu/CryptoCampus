from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import CrlArtifact, SignedCertificate
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord, CrlSnapshot
from app.models.audit import RevocationLog
from app.models.user import User
from app.pki.errors import PkiConfigurationError, PkiConflictError, PkiValidationError
from app.pki.material import UnavailablePlatformCAMaterialProvider
from app.pki.service import PlatformCAService
from app.pki.types import PlatformCAMaterial, USER_IDENTITY_KEY_USAGE


def test_default_ca_material_provider_fails_closed() -> None:
    provider = UnavailablePlatformCAMaterialProvider()

    with pytest.raises(CryptoBridgeError) as raised:
        with provider.unlocked():
            pass

    assert raised.value.code is BridgeErrorCode.PROVIDER_UNAVAILABLE


def test_platform_ca_material_rejects_invalid_private_key() -> None:
    with pytest.raises(CryptoBridgeError) as raised:
        PlatformCAMaterial(
            system_user_id="system-user",
            certificate_serial="ca-1",
            certificate_der=b"certificate",
            not_before=1,
            not_after=2,
            private_key=b"short",
        )

    assert raised.value.code is BridgeErrorCode.INVALID_ARGUMENT


def test_platform_ca_material_repr_hides_private_key() -> None:
    material = PlatformCAMaterial(
        system_user_id="system-user",
        certificate_serial="ca-1",
        certificate_der=b"certificate",
        not_before=1,
        not_after=2,
        private_key=b"p" * 32,
    )

    assert "p" * 32 not in repr(material)


class FakePlatformCAMaterialProvider:
    def __init__(self, material: PlatformCAMaterial) -> None:
        self.material = material

    @contextmanager
    def unlocked(self):
        yield self.material


def make_user(email: str, cert_serial: str, *, role: str = "student") -> User:
    return User(
        email=email,
        role=role,
        salt_a=b"authentication-salt",
        auth_hash=b"authentication-hash",
        salt_k=b"key-encryption-salt",
        enc_sk=b"encrypted-private-key",
        pubkey=b"public-key",
        cert_serial=cert_serial,
    )


def make_material(system_user_id: str, serial: str = "ca-1") -> PlatformCAMaterial:
    return PlatformCAMaterial(
        system_user_id=system_user_id,
        certificate_serial=serial,
        certificate_der=b"ca-certificate",
        not_before=1,
        not_after=2_000_000_000,
        private_key=b"k" * 32,
    )


def make_service(db_session, material, engine=None) -> PlatformCAService:
    return PlatformCAService(
        db_session,
        engine or MockCryptoEngine(),
        FakePlatformCAMaterialProvider(material),
    )


def test_platform_ca_service_registers_system_ca_and_audits(db_session) -> None:
    system_user = make_user("system@example.edu", "ca-1", role="system")
    db_session.add(system_user)
    db_session.commit()
    material = make_material(system_user.id)
    engine = MockCryptoEngine()
    engine.set_result("cert_chain_verify", True)
    engine.set_result("sm3_digest", b"d" * 32)
    service = make_service(db_session, material, engine)

    record = service.register_platform_ca(datetime(2026, 1, 1, tzinfo=timezone.utc))

    assert record.kind == "platform_ca"
    assert record.serial == "ca-1"
    assert db_session.query(AuditLog).filter_by(action="pki.ca.register").count() == 1


def test_issue_user_certificate_does_not_write_before_user_exists(db_session) -> None:
    system_user = make_user("system-issue@example.edu", "ca-issue", role="system")
    db_session.add(system_user)
    db_session.commit()
    material = make_material(system_user.id, "ca-issue")
    engine = MockCryptoEngine()
    engine.set_result("csr_create", b"csr")
    engine.set_result(
        "cert_sign", SignedCertificate(b"user-certificate", "user-1", 10, 20)
    )
    engine.set_result("cert_chain_verify", True)
    engine.set_result("sm3_digest", b"d" * 32)
    service = make_service(db_session, material, engine)
    service.register_platform_ca(datetime(2026, 1, 1, tzinfo=timezone.utc))
    issued = service.issue_user_certificate(
        str(uuid4()),
        "student",
        b"u" * 32,
        b"\x04" + b"p" * 64,
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2027, 1, 1, tzinfo=timezone.utc),
    )

    assert issued.key_usage == USER_IDENTITY_KEY_USAGE
    assert db_session.query(CertificateRecord).filter_by(kind="user_identity").count() == 0


def test_record_issued_certificate_updates_user_certificate_and_audit(db_session) -> None:
    system_user = make_user("system-record@example.edu", "ca-record", role="system")
    user = make_user("record@example.edu", "old-cert")
    db_session.add_all([system_user, user])
    db_session.commit()
    material = make_material(system_user.id, "ca-record")
    engine = MockCryptoEngine()
    engine.set_result("cert_chain_verify", True)
    engine.set_result("sm3_digest", b"d" * 32)
    service = make_service(db_session, material, engine)
    service.register_platform_ca(datetime(2026, 1, 1, tzinfo=timezone.utc))
    from app.pki.types import IssuedUserCertificate

    certificate = SignedCertificate(b"user-certificate", "user-2", 10, 20)
    issued_value = IssuedUserCertificate(
        user.id, user.role, material.certificate_serial, USER_IDENTITY_KEY_USAGE, certificate
    )

    record = service.record_issued_certificate(user, issued_value)

    assert record.serial == "user-2"
    assert user.cert_serial == "user-2"
    assert db_session.query(AuditLog).filter_by(action="pki.certificate.issue").count() == 1


def test_verify_certificate_maps_engine_invalid_to_invalid(db_session) -> None:
    system_user = make_user("system-verify@example.edu", "ca-verify", role="system")
    db_session.add(system_user)
    db_session.commit()
    material = make_material(system_user.id, "ca-verify")
    engine = MockCryptoEngine()
    engine.set_result("cert_chain_verify", True)
    engine.set_result("sm3_digest", b"d" * 32)
    service = make_service(db_session, material, engine)
    service.register_platform_ca(datetime(2026, 1, 1, tzinfo=timezone.utc))
    engine.set_result("cert_chain_verify", False)

    result = service.verify_certificate(
        b"unknown-certificate",
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        USER_IDENTITY_KEY_USAGE,
    )

    assert result.valid is False
    assert result.state == "invalid"


def test_revoke_certificate_atomically_creates_crl_and_audit(db_session) -> None:
    system_user = make_user("system-revoke@example.edu", "ca-revoke", role="system")
    operator = make_user("operator@example.edu", "operator-cert", role="admin")
    user = make_user("revoke@example.edu", "user-revoke")
    db_session.add_all([system_user, operator, user])
    db_session.commit()
    material = make_material(system_user.id, "ca-revoke")
    engine = MockCryptoEngine()
    engine.set_result("cert_chain_verify", True)
    engine.set_result("sm3_digest", b"d" * 32)
    service = make_service(db_session, material, engine)
    service.register_platform_ca(datetime(2026, 1, 1, tzinfo=timezone.utc))
    db_session.add(
        CertificateRecord(
            serial="user-revoke",
            subject_user_id=user.id,
            issuer_serial="ca-revoke",
            kind="user_identity",
            certificate_der=b"user-certificate",
            key_usage=",".join(USER_IDENTITY_KEY_USAGE),
            not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
            status="active",
        )
    )
    db_session.commit()
    engine.set_result("crl_create", CrlArtifact(b"crl", 10, 20))
    engine.set_result("crl_verify", False)

    snapshot = service.revoke_certificate(
        "user-revoke",
        "compromised",
        operator.id,
        datetime(2026, 2, 1, tzinfo=timezone.utc),
        datetime(2026, 3, 1, tzinfo=timezone.utc),
    )

    assert snapshot.issuer_serial == "ca-revoke"
    assert db_session.get(CertificateRecord, "user-revoke").status == "revoked"
    assert db_session.query(CrlSnapshot).count() == 1
    assert db_session.query(AuditLog).filter_by(action="pki.certificate.revoke").count() == 1


def test_register_platform_ca_requires_system_role(db_session) -> None:
    user = make_user("not-system@example.edu", "ca-role", role="student")
    db_session.add(user)
    db_session.commit()
    service = make_service(db_session, make_material(user.id, "ca-role"), MockCryptoEngine())

    with pytest.raises(PkiConfigurationError):
        service.register_platform_ca(datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_register_platform_ca_is_idempotent_for_same_der(db_session) -> None:
    user = make_user("system-idempotent@example.edu", "ca-idempotent", role="system")
    db_session.add(user)
    db_session.commit()
    engine = MockCryptoEngine()
    engine.set_result("cert_chain_verify", True)
    engine.set_result("sm3_digest", b"d" * 32)
    service = make_service(db_session, make_material(user.id, "ca-idempotent"), engine)

    first = service.register_platform_ca(datetime(2026, 1, 1, tzinfo=timezone.utc))
    second = service.register_platform_ca(datetime(2026, 1, 1, tzinfo=timezone.utc))

    assert first.serial == second.serial
    assert db_session.query(AuditLog).filter_by(action="pki.ca.register").count() == 1


def test_record_issued_certificate_rejects_subject_mismatch_without_writes(db_session) -> None:
    system_user = make_user("system-mismatch@example.edu", "ca-mismatch", role="system")
    user = make_user("mismatch@example.edu", "old-mismatch")
    db_session.add_all([system_user, user])
    db_session.commit()
    engine = MockCryptoEngine()
    engine.set_result("cert_chain_verify", True)
    engine.set_result("sm3_digest", b"d" * 32)
    service = make_service(db_session, make_material(system_user.id, "ca-mismatch"), engine)
    service.register_platform_ca(datetime(2026, 1, 1, tzinfo=timezone.utc))
    from app.pki.types import IssuedUserCertificate

    issued = IssuedUserCertificate(
        str(uuid4()),
        user.role,
        "ca-mismatch",
        USER_IDENTITY_KEY_USAGE,
        SignedCertificate(b"mismatch-certificate", "mismatch-1", 10, 20),
    )

    with pytest.raises(PkiValidationError):
        service.record_issued_certificate(user, issued)

    assert db_session.query(CertificateRecord).filter_by(kind="user_identity").count() == 0
    assert db_session.query(AuditLog).filter_by(action="pki.certificate.issue").count() == 0


def test_revoke_engine_failure_keeps_certificate_active(db_session) -> None:
    system_user = make_user("system-revoke-fail@example.edu", "ca-revoke-fail", role="system")
    operator = make_user("operator-revoke-fail@example.edu", "operator-revoke-fail", role="admin")
    user = make_user("revoke-fail@example.edu", "user-revoke-fail")
    db_session.add_all([system_user, operator, user])
    db_session.commit()
    material = make_material(system_user.id, "ca-revoke-fail")
    engine = MockCryptoEngine()
    engine.set_result("cert_chain_verify", True)
    engine.set_result("sm3_digest", b"d" * 32)
    service = make_service(db_session, material, engine)
    service.register_platform_ca(datetime(2026, 1, 1, tzinfo=timezone.utc))
    db_session.add(
        CertificateRecord(
            serial="user-revoke-fail",
            subject_user_id=user.id,
            issuer_serial="ca-revoke-fail",
            kind="user_identity",
            certificate_der=b"user-revoke-fail-certificate",
            key_usage=",".join(USER_IDENTITY_KEY_USAGE),
            not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
            status="active",
        )
    )
    db_session.commit()
    engine.set_result("crl_create", CrlArtifact(b"crl-fail", 10, 20))
    engine.set_result("crl_verify", True)

    with pytest.raises(PkiValidationError):
        service.revoke_certificate(
            "user-revoke-fail",
            "failure",
            operator.id,
            datetime(2026, 2, 1, tzinfo=timezone.utc),
            datetime(2026, 3, 1, tzinfo=timezone.utc),
        )

    db_session.expire_all()
    assert db_session.get(CertificateRecord, "user-revoke-fail").status == "active"
    assert db_session.query(CrlSnapshot).count() == 0
    assert db_session.query(AuditLog).filter_by(action="pki.certificate.revoke").count() == 0
    assert db_session.query(RevocationLog).count() == 0


def test_revoke_certificate_is_idempotent_without_duplicate_audit(db_session) -> None:
    system_user = make_user("system-revoke-idempotent@example.edu", "ca-revoke-idempotent", role="system")
    operator = make_user("operator-revoke-idempotent@example.edu", "operator-revoke-idempotent", role="admin")
    user = make_user("revoke-idempotent@example.edu", "user-revoke-idempotent")
    db_session.add_all([system_user, operator, user])
    db_session.commit()
    material = make_material(system_user.id, "ca-revoke-idempotent")
    engine = MockCryptoEngine()
    engine.set_result("cert_chain_verify", True)
    engine.set_result("sm3_digest", b"d" * 32)
    service = make_service(db_session, material, engine)
    service.register_platform_ca(datetime(2026, 1, 1, tzinfo=timezone.utc))
    db_session.add(
        CertificateRecord(
            serial="user-revoke-idempotent",
            subject_user_id=user.id,
            issuer_serial="ca-revoke-idempotent",
            kind="user_identity",
            certificate_der=b"user-revoke-idempotent-certificate",
            key_usage=",".join(USER_IDENTITY_KEY_USAGE),
            not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
            status="active",
        )
    )
    db_session.commit()
    engine.set_result("crl_create", CrlArtifact(b"crl-idempotent", 10, 20))
    engine.set_result("crl_verify", False)
    first = service.revoke_certificate(
        "user-revoke-idempotent", "first", operator.id,
        datetime(2026, 2, 1, tzinfo=timezone.utc), datetime(2026, 3, 1, tzinfo=timezone.utc)
    )
    second = service.revoke_certificate(
        "user-revoke-idempotent", "different", operator.id,
        datetime(2026, 4, 1, tzinfo=timezone.utc), datetime(2026, 5, 1, tzinfo=timezone.utc)
    )

    assert first.id == second.id
    assert db_session.query(CrlSnapshot).count() == 1
    assert db_session.query(AuditLog).filter_by(action="pki.certificate.revoke").count() == 1
