from datetime import datetime, timedelta, timezone
import io
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import (
    EnvelopeArtifact,
    MAX_DROP_CONTENT_SIZE,
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


def test_create_file_drop_success_201() -> None:
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
    fake_pdf = b"%PDF-1.4\n" + b"A" * 1024 + b"\n%%EOF"

    response = client.post(
        "/api/v1/drops/file",
        headers={"Idempotency-Key": "idemp-file-drop-000000001"},
        data={
            "ttl_policy": "hours_24",
            "pqc_mode": "false",
            "access_password": "file-secret-password-123",
        },
        files={
            "file": ("campus_report.pdf", fake_pdf, "application/pdf"),
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert "code" in data and len(data["code"]) == 16
    assert "access_code" in data and len(data["access_code"]) == 16
    assert data["url"] == f"/d/{data['code']}"
    assert data["expires_at"] is not None
    assert data["pqc_mode"] is False

    # Check Drop record in DB
    drop = session.query(Drop).filter_by(id=data["id"]).one()
    assert drop.kind == "file"
    assert drop.filename == "campus_report.pdf"
    assert drop.content_size == len(fake_pdf)
    assert drop.access_factor_salt is not None
    assert drop.burn_after_read is False
    assert drop.owner_user_id == sender.id
    assert drop.recipient_user_id == recipient.id


def test_create_file_drop_exceeds_100_mib_413() -> None:
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

    # 100 MiB + 1 byte = 104,857,601 bytes
    # Create an in-memory stream of 104,857,601 bytes
    oversized_len = MAX_DROP_CONTENT_SIZE + 1
    # Use a chunked stream to avoid physical memory overhead in test
    class BoundedChunkStream(io.RawIOBase):
        def __init__(self, size: int):
            self._size = size
            self._sent = 0

        def readable(self):
            return True

        def readinto(self, b):
            remaining = self._size - self._sent
            if remaining <= 0:
                return 0
            to_read = min(len(b), remaining)
            b[:to_read] = b"\x00" * to_read
            self._sent += to_read
            return to_read

    stream = BoundedChunkStream(oversized_len)

    response = client.post(
        "/api/v1/drops/file",
        headers={"Idempotency-Key": "idemp-file-oversized-0001"},
        data={
            "ttl_policy": "burn_after_read",
            "pqc_mode": "false",
        },
        files={
            "file": ("too_large.bin", stream, "application/octet-stream"),
        },
    )

    assert response.status_code == 413
    assert response.json()["code"] == "PAYLOAD_TOO_LARGE"


def test_create_file_drop_filename_truncation_and_sanitization() -> None:
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

    # Filename with path elements and length > 300
    dangerous_filename = "folder/subfolder/../../" + "a" * 300 + ".txt"

    response = client.post(
        "/api/v1/drops/file",
        headers={"Idempotency-Key": "idemp-file-filename-0001"},
        data={
            "ttl_policy": "days_7",
            "pqc_mode": "false",
        },
        files={
            "file": (dangerous_filename, b"safe file content", "text/plain"),
        },
    )

    assert response.status_code == 201
    drop_id = response.json()["id"]
    drop = session.query(Drop).filter_by(id=drop_id).one()
    assert "/" not in drop.filename
    assert "\\" not in drop.filename
    assert len(drop.filename) <= 255


def test_create_file_drop_pqc_mode_201() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    mock_engine = _setup_mock_crypto(pqc=True)
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

    response = client.post(
        "/api/v1/drops/file",
        headers={"Idempotency-Key": "idemp-file-pqc-000000001"},
        data={
            "ttl_policy": "burn_after_read",
            "pqc_mode": "true",
        },
        files={
            "file": ("quantum_research.bin", b"PQC protected file", "application/octet-stream"),
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["pqc_mode"] is True
    drop = session.query(Drop).filter_by(id=data["id"]).one()
    assert drop.pqc_mode is True
