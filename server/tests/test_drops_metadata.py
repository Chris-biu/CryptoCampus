from datetime import datetime, timedelta, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.dependencies import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.drop import Drop
from app.models.user import User


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

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


def _create_test_db() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


@pytest.fixture
def test_setup():
    db_session = _create_test_db()
    crypto = DynamicMockCryptoEngine()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto

    client = TestClient(app)

    now = datetime.now(timezone.utc)

    # Insert test users
    sender = User(
        id=str(uuid.uuid4()),
        email="sender@campus.edu.cn",
        role="student",
        status="active",
        created_at=now,
    )
    recipient = User(
        id=str(uuid.uuid4()),
        email="recipient@campus.edu.cn",
        role="student",
        status="active",
        created_at=now,
    )
    db_session.add_all([sender, recipient])
    db_session.flush()

    yield {
        "client": client,
        "db": db_session,
        "crypto": crypto,
        "sender": sender,
        "recipient": recipient,
        "now": now,
    }

    app.dependency_overrides.clear()


def test_get_drop_metadata_available_text(test_setup):
    client = test_setup["client"]
    db = test_setup["db"]
    crypto = test_setup["crypto"]
    now = test_setup["now"]

    code = "ValidCode123456"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=test_setup["sender"].id,
        recipient_user_id=test_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"ciphertext",
        nonce=b"\x01" * 12,
        tag=b"\x02" * 16,
        enc_key_sm2=b"\x03" * 96,
        enc_key_mlkem=None,
        sender_signature=b"\x04" * 64,
        sender_certificate_der=b"\x05" * 100,
        sender_cert_serial="CERT-SERIAL-001",
        recipient_sm2_fingerprint=b"\x06" * 32,
        recipient_mlkem_fingerprint=None,
        access_code_hash=crypto.sm3_digest(b"AC-12345678"),
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=10,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.get(f"/api/v1/drops/{code}")
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # Exact contract fields
    assert data["code"] == code
    assert data["kind"] == "text"
    assert data["status"] == "available"
    assert data["requires_password"] is False
    assert data["burn_after_read"] is False
    assert data["filename"] is None
    assert data["size"] == 10
    assert data["expires_at"] is not None

    # Privacy check: no envelope or security fields leaked
    forbidden_keys = {
        "ciphertext", "nonce", "tag", "enc_key_sm2", "enc_key_mlkem",
        "sender_signature", "sender_certificate_der", "access_code_hash",
        "owner_user_id", "recipient_user_id", "recipient_sm2_fingerprint",
    }
    assert not any(k in data for k in forbidden_keys)


def test_get_drop_metadata_available_file_with_password(test_setup):
    client = test_setup["client"]
    db = test_setup["db"]
    crypto = test_setup["crypto"]
    now = test_setup["now"]

    code = "FileCodeWithPass12"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=test_setup["sender"].id,
        recipient_user_id=test_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="file",
        envelope_version=1,
        ciphertext=b"fileciphertext",
        nonce=b"\x01" * 12,
        tag=b"\x02" * 16,
        enc_key_sm2=b"\x03" * 96,
        enc_key_mlkem=None,
        sender_signature=b"\x04" * 64,
        sender_certificate_der=b"\x05" * 100,
        sender_cert_serial="CERT-SERIAL-002",
        recipient_sm2_fingerprint=b"\x06" * 32,
        recipient_mlkem_fingerprint=None,
        access_code_hash=crypto.sm3_digest(b"AC-FILE-1234"),
        access_factor_salt=b"\x99" * 16,
        ttl_policy="burn_after_read",
        burn_after_read=True,
        expires_at=None,
        filename="confidential.pdf",
        content_size=1024,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.get(f"/api/v1/drops/{code}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["code"] == code
    assert data["kind"] == "file"
    assert data["status"] == "available"
    assert data["requires_password"] is True
    assert data["burn_after_read"] is True
    assert data["filename"] == "confidential.pdf"
    assert data["size"] == 1024
    assert data["expires_at"] is None


def test_get_drop_metadata_not_found(test_setup):
    client = test_setup["client"]
    resp = client.get("/api/v1/drops/NonExistentCode123")
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"


def test_get_drop_metadata_expired_returns_404(test_setup):
    client = test_setup["client"]
    db = test_setup["db"]
    crypto = test_setup["crypto"]
    now = test_setup["now"]

    code = "ExpiredCode12345"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=test_setup["sender"].id,
        recipient_user_id=test_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"ciphertext",
        nonce=b"\x01" * 12,
        tag=b"\x02" * 16,
        enc_key_sm2=b"\x03" * 96,
        enc_key_mlkem=None,
        sender_signature=b"\x04" * 64,
        sender_certificate_der=b"\x05" * 100,
        sender_cert_serial="CERT-SERIAL-003",
        recipient_sm2_fingerprint=b"\x06" * 32,
        recipient_mlkem_fingerprint=None,
        access_code_hash=crypto.sm3_digest(b"AC-12345678"),
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now - timedelta(seconds=10),  # expired
        filename=None,
        content_size=10,
        pqc_mode=False,
        status="available",
        created_at=now - timedelta(hours=25),
    )
    db.add(drop)
    db.commit()

    resp = client.get(f"/api/v1/drops/{code}")
    assert resp.status_code == 404


@pytest.mark.parametrize("status_val", ["consumed", "destroyed", "cooling_down", "expired"])
def test_get_drop_metadata_unavailable_status_returns_404(test_setup, status_val):
    client = test_setup["client"]
    db = test_setup["db"]
    crypto = test_setup["crypto"]
    now = test_setup["now"]

    code = f"StatusCode{status_val[:6]}123"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=test_setup["sender"].id,
        recipient_user_id=test_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"ciphertext",
        nonce=b"\x01" * 12,
        tag=b"\x02" * 16,
        enc_key_sm2=b"\x03" * 96,
        enc_key_mlkem=None,
        sender_signature=b"\x04" * 64,
        sender_certificate_der=b"\x05" * 100,
        sender_cert_serial="CERT-SERIAL-004",
        recipient_sm2_fingerprint=b"\x06" * 32,
        recipient_mlkem_fingerprint=None,
        access_code_hash=crypto.sm3_digest(b"AC-12345678"),
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=10,
        pqc_mode=False,
        status=status_val,
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.get(f"/api/v1/drops/{code}")
    assert resp.status_code == 404


def test_get_drop_metadata_invalid_code_format_returns_404(test_setup):
    client = test_setup["client"]
    # Too short (<11)
    resp = client.get("/api/v1/drops/short")
    assert resp.status_code == 404

    # Special characters
    resp = client.get("/api/v1/drops/Invalid@Code!123")
    assert resp.status_code == 404
