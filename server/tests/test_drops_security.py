from datetime import datetime, timedelta, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import (
    EnvelopeArtifact,
    SM2_PRIVATE_KEY_SIZE,
    SM2_PUBLIC_KEY_SIZE,
    MLKEM_PUBLIC_KEY_SIZE,
)
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord
from app.models.credential import CredentialLedger
from app.models.drop import Drop, DropIdempotency
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.recipient_resolver import ConfiguredRecipientKeyResolver
from app.crypto.dependencies import get_crypto_engine
from app.api.routes.auth import get_private_key_cache
from app.api.routes.drops import get_recipient_key_resolver


def _create_sqlite_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


class MonitoredMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0
        self.forbidden_calls: list[str] = []

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            self._digests[message] = f"mock-digest-{self._counter:020d}".encode("ascii")
        return self._digests[message]

    def envelope_open(self, *args, **kwargs):
        self.forbidden_calls.append("envelope_open")
        raise AssertionError("Security violation: envelope_open must never be called during drop creation")

    def sm2_decrypt(self, *args, **kwargs):
        self.forbidden_calls.append("sm2_decrypt")
        raise AssertionError("Security violation: sm2_decrypt must never be called during drop creation")

    def ml_kem_decapsulate(self, *args, **kwargs):
        self.forbidden_calls.append("ml_kem_decapsulate")
        raise AssertionError("Security violation: ml_kem_decapsulate must never be called during drop creation")


def _setup_mock_crypto(pqc: bool = False) -> MonitoredMockCryptoEngine:
    crypto = MonitoredMockCryptoEngine()
    crypto.set_result("hkdf_sm3", b"\xbb" * 32)
    artifact = EnvelopeArtifact(
        ciphertext=b"encrypted_ciphertext_protected_content_non_plaintext",
        nonce=b"\x01" * 12,
        tag=b"\x02" * 16,
        enc_key_sm2=b"\x03" * 96,
        enc_key_mlkem=b"\x05" * 1088 if pqc else None,
        sender_signature=b"\x04" * 64,
        sender_certificate=b"\x30\x82\x01\x00" + b"\x55" * 100,
    )
    crypto.set_result("envelope_seal", artifact)
    return crypto


def _setup_fixture_data(session: Session) -> tuple[User, User, CertificateRecord, bytes]:
    sender_id = str(uuid.uuid4())
    recipient_id = str(uuid.uuid4())
    sender_sk = b"\x33" * SM2_PRIVATE_KEY_SIZE

    sender = User(
        id=sender_id,
        email="sender@stu.edu.cn",
        role="student",
        status="active",
        pubkey=b"\x04" + b"\x11" * 64,
        cert_serial="CERT-SENDER-001",
    )
    recipient = User(
        id=recipient_id,
        email="recipient@stu.edu.cn",
        role="student",
        status="active",
        pubkey=b"\x04" + b"\x22" * 64,
        pqc_pubkey=b"\x44" * MLKEM_PUBLIC_KEY_SIZE,
        enc_pqc_sk=b"\x55" * 32,
    )
    session.add_all([sender, recipient])

    cert = CertificateRecord(
        serial="CERT-SENDER-001",
        subject_user_id=sender_id,
        issuer_serial="CA-ROOT-001",
        kind="user_identity",
        certificate_der=b"\x30\x82\x01\x00" + b"\x55" * 200,
        key_usage="digitalSignature",
        status="active",
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    session.add(cert)
    session.commit()
    return sender, recipient, cert, sender_sk


def test_zero_sensitive_data_in_database_or_response() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    crypto = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, sender_sk, datetime.now(timezone.utc) + timedelta(hours=1))
    resolver = ConfiguredRecipientKeyResolver(recipient.id, crypto)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(sender.id, "student", "active")
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_private_key_cache] = lambda: key_cache
    app.dependency_overrides[get_recipient_key_resolver] = lambda: resolver

    client = TestClient(app)

    sensitive_content = "SuperSensitiveClassifiedPlaintext12345!"
    sensitive_password = "MyCustomUltraSecretPassword987!"

    response = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-security-test-0000001"},
        json={
            "content": sensitive_content,
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
            "access_password": sensitive_password,
        },
    )

    assert response.status_code == 201
    resp_data = response.json()
    access_code = resp_data["access_code"]
    raw_response_text = response.text

    # 1. Response must NOT contain password, private key, or content plaintext
    assert sensitive_password not in raw_response_text
    assert sensitive_content not in raw_response_text
    assert "private_key" not in resp_data
    assert "session_key" not in resp_data

    # 2. Database Drop table must NOT contain password, access_code plaintext, or content plaintext
    drop = session.query(Drop).filter_by(id=resp_data["id"]).one()
    assert drop.ciphertext != sensitive_content.encode("utf-8")
    assert sensitive_content.encode("utf-8") not in drop.ciphertext
    assert access_code.encode("utf-8") != drop.access_code_hash
    assert access_code not in str(drop.__dict__)
    assert sensitive_password not in str(drop.__dict__)
    assert sensitive_content not in str(drop.__dict__)

    # 3. Audit table must NOT contain password, access_code, or plaintext
    audits = session.query(AuditLog).filter_by(target=f"drop:{drop.id}").all()
    for a in audits:
        audit_str = f"{a.actor}:{a.action}:{a.target}:{a.detail_hash}"
        assert sensitive_password not in audit_str
        assert access_code not in audit_str
        assert sensitive_content not in audit_str

    # 4. Prohibited operations must never have been called
    assert crypto.forbidden_calls == []


def test_prohibited_crypto_methods_never_called() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    crypto = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, sender_sk, datetime.now(timezone.utc) + timedelta(hours=1))
    resolver = ConfiguredRecipientKeyResolver(recipient.id, crypto)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(sender.id, "student", "active")
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_private_key_cache] = lambda: key_cache
    app.dependency_overrides[get_recipient_key_resolver] = lambda: resolver

    client = TestClient(app)

    # 1. Text drop
    resp_text = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-prohibited-check-text-01"},
        json={
            "content": "Checking operations",
            "ttl_policy": "hours_24",
            "pqc_mode": False,
        },
    )
    assert resp_text.status_code == 201

    # 2. File drop
    resp_file = client.post(
        "/api/v1/drops/file",
        headers={"Idempotency-Key": "idemp-prohibited-check-file-01"},
        data={"ttl_policy": "days_7", "pqc_mode": "false"},
        files={"file": ("notes.txt", b"Checking file operations", "text/plain")},
    )
    assert resp_file.status_code == 201

    # Assert zero forbidden calls
    assert "envelope_open" not in crypto.forbidden_calls
    assert "sm2_decrypt" not in crypto.forbidden_calls
    assert "ml_kem_decapsulate" not in crypto.forbidden_calls
