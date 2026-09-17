from datetime import datetime, timedelta, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

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
from app.models.certificate import CertificateRecord
from app.models.drop import Drop, DropIdempotency
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.recipient_resolver import ConfiguredRecipientKeyResolver
from app.crypto.dependencies import get_crypto_engine
from app.api.routes.auth import get_private_key_cache
from app.api.routes.drops import get_recipient_key_resolver


from sqlalchemy.pool import StaticPool


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


class DynamicMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            seed = f"hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]


def _setup_mock_crypto(pqc: bool = False) -> DynamicMockCryptoEngine:
    crypto = DynamicMockCryptoEngine()
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


def test_text_drop_idempotency_replay_conflict_409() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    mock_engine = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, sender_sk, datetime.now(timezone.utc) + timedelta(hours=1))
    resolver = ConfiguredRecipientKeyResolver(recipient.id, mock_engine)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(sender.id, "student", "active")
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: mock_engine
    app.dependency_overrides[get_private_key_cache] = lambda: key_cache
    app.dependency_overrides[get_recipient_key_resolver] = lambda: resolver

    client = TestClient(app)
    idemp_key = "idemp-text-replay-conflict-key-001"

    # First request
    resp1 = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": idemp_key},
        json={
            "content": "Secret note 1",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )
    assert resp1.status_code == 201

    # Second request with identical Idempotency-Key
    resp2 = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": idemp_key},
        json={
            "content": "Secret note 1 (replay)",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )
    assert resp2.status_code == 409
    assert resp2.json()["code"] == "CONFLICT"


def test_file_drop_idempotency_replay_conflict_409() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    mock_engine = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, sender_sk, datetime.now(timezone.utc) + timedelta(hours=1))
    resolver = ConfiguredRecipientKeyResolver(recipient.id, mock_engine)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(sender.id, "student", "active")
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: mock_engine
    app.dependency_overrides[get_private_key_cache] = lambda: key_cache
    app.dependency_overrides[get_recipient_key_resolver] = lambda: resolver

    client = TestClient(app)
    idemp_key = "idemp-file-replay-conflict-key-001"

    # First request
    resp1 = client.post(
        "/api/v1/drops/file",
        headers={"Idempotency-Key": idemp_key},
        data={
            "ttl_policy": "hours_24",
            "pqc_mode": "false",
        },
        files={
            "file": ("test.txt", b"Hello File", "text/plain"),
        },
    )
    assert resp1.status_code == 201

    # Second request with identical Idempotency-Key
    resp2 = client.post(
        "/api/v1/drops/file",
        headers={"Idempotency-Key": idemp_key},
        data={
            "ttl_policy": "hours_24",
            "pqc_mode": "false",
        },
        files={
            "file": ("test.txt", b"Hello File", "text/plain"),
        },
    )
    assert resp2.status_code == 409
    assert resp2.json()["code"] == "CONFLICT"


def test_different_idempotency_keys_create_separate_drops() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    mock_engine = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, sender_sk, datetime.now(timezone.utc) + timedelta(hours=1))
    resolver = ConfiguredRecipientKeyResolver(recipient.id, mock_engine)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(sender.id, "student", "active")
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: mock_engine
    app.dependency_overrides[get_private_key_cache] = lambda: key_cache
    app.dependency_overrides[get_recipient_key_resolver] = lambda: resolver

    client = TestClient(app)

    resp1 = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-unique-key-0000000001"},
        json={
            "content": "Secret note A",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )
    assert resp1.status_code == 201

    resp2 = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-unique-key-0000000002"},
        json={
            "content": "Secret note B",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )
    assert resp2.status_code == 201

    assert resp1.json()["id"] != resp2.json()["id"]
    assert resp1.json()["code"] != resp2.json()["code"]
