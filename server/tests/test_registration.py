from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SignedCertificate, Sm2KeyPair, Sm4GcmCiphertext
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.pki.service import PlatformCAService
from app.pki.types import PlatformCAMaterial
from app.services.registration import AuthSession, RegistrationService, RegistrationError


class Provider:
    def __init__(self, material): self.material = material
    @contextmanager
    def unlocked(self): yield self.material


class Codes:
    def consume(self, email, code, now=None): return True


class Tokens:
    def issue(self, user):
        return AuthSession(access_token="injected", token_type="bearer", expires_in=7200,
                           user={"id": user.id, "email": user.email, "role": user.role,
                                 "status": user.status, "pqc_mode": False,
                                 "created_at": user.created_at})


def test_registration_persists_user_certificate_and_audit_atomically(db_session) -> None:
    system_id = str(uuid4())
    material = PlatformCAMaterial(system_id, "ca-1", b"ca", 1, 2_000_000_000, b"k" * 32)
    system = User(id=system_id, email="ca@campus.edu", role="system", cert_serial="ca-1",
                  salt_a=b"a" * 16, auth_hash=b"h" * 32, salt_k=b"k" * 16,
                  enc_sk=b"e", pubkey=b"p")
    db_session.add(system); db_session.commit()
    engine = MockCryptoEngine()
    engine.set_result("cert_chain_verify", True)
    engine.set_result("sm3_digest", b"d" * 32)
    engine.set_result("sm3_hash_password", b"h" * 32)
    engine.set_result("hkdf_sm3", b"x" * 16)
    engine.set_result("sm2_generate_keypair", Sm2KeyPair(b"s" * 32, b"p" * 65))
    engine.set_result("sm4_gcm_encrypt", Sm4GcmCiphertext(b"cipher", b"n" * 12, b"t" * 16))
    engine.set_result("csr_create", b"csr")
    engine.set_result("cert_sign", SignedCertificate(b"cert", "user-cert", 1, 2_000_000_000))
    ca = PlatformCAService(db_session, engine, Provider(material))
    ca.register_platform_ca(datetime.now(timezone.utc))
    service = RegistrationService(db_session, engine, ca, Codes(), Tokens())

    result = service.register("new@campus.edu", "Password123", "123456")

    assert result.access_token == "injected"
    user = db_session.query(User).filter_by(email="new@campus.edu").one()
    assert user.role == "student" and user.pqc_pubkey is None
    assert user.enc_sk.startswith(b"v1")
    assert db_session.query(CertificateRecord).filter_by(subject_user_id=user.id).count() == 1
    assert db_session.query(AuditLog).filter_by(action="auth.register").count() == 1


def test_registration_duplicate_email_short_circuits_crypto(db_session) -> None:
    existing = User(email="new@campus.edu", role="student", cert_serial="old",
                    salt_a=b"a" * 16, auth_hash=b"h" * 32, salt_k=b"k" * 16,
                    enc_sk=b"e", pubkey=b"p")
    db_session.add(existing); db_session.commit()
    engine = MockCryptoEngine()
    service = RegistrationService(db_session, engine, object(), Codes(), Tokens())
    with pytest.raises(RegistrationError) as raised:
        service.register(" NEW@Campus.edu ", "Password123", "123456")
    assert raised.value.code == "EMAIL_EXISTS"
    assert engine.calls == ()


def test_pqc_mode_fails_closed_before_key_generation(db_session) -> None:
    service = RegistrationService(db_session, MockCryptoEngine(), object(), Codes(), Tokens(), pqc_mode=True)
    with pytest.raises(RegistrationError) as raised:
        service.register("pqc@campus.edu", "Password123", "123456")
    assert raised.value.code == "UNSUPPORTED" and raised.value.status_code == 503
    assert db_session.query(User).filter_by(email="pqc@campus.edu").count() == 0


def test_engine_failure_rolls_back_user_and_audit(db_session) -> None:
    engine = MockCryptoEngine()
    from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
    engine.set_error("sm3_hash_password", CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))
    service = RegistrationService(db_session, engine, object(), Codes(), Tokens())
    with pytest.raises(RegistrationError) as raised:
        service.register("failed@campus.edu", "Password123", "123456")
    assert raised.value.status_code == 503
    assert db_session.query(User).filter_by(email="failed@campus.edu").count() == 0
    assert db_session.query(AuditLog).filter_by(action="auth.register").count() == 0
