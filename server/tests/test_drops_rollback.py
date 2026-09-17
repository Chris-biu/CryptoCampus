from datetime import datetime, timedelta, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
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


class RollbackMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0
        self.should_fail_seal = False

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            self._digests[message] = f"mock-digest-{self._counter:020d}".encode("ascii")
        return self._digests[message]

    def envelope_seal(self, *args, **kwargs):
        if self.should_fail_seal:
            raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE)
        return super().envelope_seal(*args, **kwargs)


def _setup_mock_crypto(pqc: bool = False) -> RollbackMockCryptoEngine:
    crypto = RollbackMockCryptoEngine()
    crypto.set_result("hkdf_sm3", b"\xbb" * 32)
    artifact = EnvelopeArtifact(
        ciphertext=b"encrypted_ciphertext",
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


def test_atomic_rollback_on_crypto_engine_failure() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    crypto = _setup_mock_crypto()
    crypto.should_fail_seal = True  # Inject failure in seal

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

    response = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-rollback-test-0001"},
        json={
            "content": "Will fail during seal",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )

    assert response.status_code == 503

    # Verify atomic rollback:
    # 1. No Drop created
    assert session.query(Drop).count() == 0
    # 2. No DropIdempotency created
    assert session.query(DropIdempotency).count() == 0
    # 3. No AuditLog created
    assert session.query(AuditLog).filter_by(action="drop.create").count() == 0
    # 4. No Quota consumed
    ledger = session.query(CredentialLedger).filter_by(user_id=sender.id, service="drop").first()
    assert ledger is None or ledger.issued_count == 0


def test_atomic_rollback_on_missing_certificate() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    # Invalidate certificate
    cert.status = "expired"
    session.commit()

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

    response = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-cert-invalid-0001"},
        json={
            "content": "Will fail due to revoked cert",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )

    assert response.status_code in (401, 422, 500)
    assert session.query(Drop).count() == 0
    assert session.query(DropIdempotency).count() == 0
    assert session.query(AuditLog).filter_by(action="drop.create").count() == 0
