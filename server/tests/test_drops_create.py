from datetime import datetime, timedelta, timezone
import io
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.errors import ApiError
from app.crypto.engine import CryptoEngine
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
from app.models.drop import Drop, DropIdempotency
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user, require_roles
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.drop import DropService
from app.services.quota import QuotaService
from app.services.recipient_resolver import (
    ConfiguredRecipientKeyResolver,
    DefaultRecipientKeyResolver,
    RecipientKeyResolver,
)
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


def test_create_text_drop_success_201() -> None:
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
    response = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-text-drop-000000001"},
        json={
            "content": "Secret campus announcement text",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
            "access_password": "custom-password-123",
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert "code" in data and len(data["code"]) == 16
    assert "access_code" in data and len(data["access_code"]) == 16
    assert data["url"] == f"/d/{data['code']}"
    assert data["expires_at"] is None
    assert data["pqc_mode"] is False

    # Verify database persistence
    drop = session.query(Drop).filter_by(id=data["id"]).one()
    assert drop.kind == "text"
    assert drop.owner_user_id == sender.id
    assert drop.recipient_user_id == recipient.id
    assert drop.access_factor_salt is not None
    assert drop.burn_after_read is True
    assert drop.expires_at is None
    assert drop.status == "available"
    assert mock_engine.sm3_digest(data["code"].encode("ascii")) == drop.link_code_hash
    assert len(drop.ciphertext) > 0
    assert len(drop.enc_key_sm2) > 0

    # Verify idempotency recorded
    idemp = session.query(DropIdempotency).filter_by(drop_id=data["id"]).one()
    assert idemp.owner_user_id == sender.id

    # Verify audit log recorded
    audit = session.query(AuditLog).filter_by(target=f"drop:{data['id']}").one()
    assert audit.actor == sender.id
    assert audit.action == "drop.create"


def test_create_text_drop_different_ttl_policies() -> None:
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

    # 1. hours_24
    resp_24 = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-text-drop-000000002"},
        json={
            "content": "Drop 24h",
            "ttl_policy": "hours_24",
            "pqc_mode": False,
        },
    )
    assert resp_24.status_code == 201
    assert resp_24.json()["expires_at"] is not None

    # 2. days_7
    resp_7d = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-text-drop-000000003"},
        json={
            "content": "Drop 7d",
            "ttl_policy": "days_7",
            "pqc_mode": False,
        },
    )
    assert resp_7d.status_code == 201
    assert resp_7d.json()["expires_at"] is not None


def test_create_text_drop_roles_allowed() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)
    mock_engine = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, sender_sk, datetime.now(timezone.utc) + timedelta(hours=1))
    resolver = ConfiguredRecipientKeyResolver(recipient.id, mock_engine)

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: mock_engine
    app.dependency_overrides[get_private_key_cache] = lambda: key_cache
    app.dependency_overrides[get_recipient_key_resolver] = lambda: resolver

    client = TestClient(app)

    for idx, role in enumerate(["student", "admin", "teacher"]):
        # Update user's role in DB
        sender.role = role
        session.commit()
        app.dependency_overrides[require_authenticated_user] = lambda r=role: CurrentUser(sender.id, r, "active")

        resp = client.post(
            "/api/v1/drops/text",
            headers={"Idempotency-Key": f"idemp-role-check-{idx:010d}"},
            json={
                "content": f"Drop role {role}",
                "ttl_policy": "burn_after_read",
                "pqc_mode": False,
            },
        )
        assert resp.status_code == 201, f"Role {role} should succeed, got {resp.status_code}"


def test_create_text_drop_forbidden_role_403() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    app = create_app()
    # Mock user with system role (not student, admin, teacher)
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(sender.id, "system", "active")
    client = TestClient(app)

    resp = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-forbidden-role-01"},
        json={
            "content": "Secret text",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )
    assert resp.status_code == 403


def test_create_text_drop_missing_idempotency_key_422() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(sender.id, "student", "active")
    client = TestClient(app)

    # Missing header
    resp1 = client.post(
        "/api/v1/drops/text",
        json={
            "content": "Secret text",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )
    assert resp1.status_code == 422

    # Key too short (< 16)
    resp2 = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "short"},
        json={
            "content": "Secret text",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )
    assert resp2.status_code == 422


def test_create_text_drop_validation_errors_422() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(sender.id, "student", "active")
    client = TestClient(app)

    # Empty content
    resp_empty = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-val-000000001"},
        json={
            "content": "",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )
    assert resp_empty.status_code == 422

    # Invalid TTL policy
    resp_ttl = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-val-000000002"},
        json={
            "content": "Hello",
            "ttl_policy": "invalid_policy",
            "pqc_mode": False,
        },
    )
    assert resp_ttl.status_code == 422


def test_create_text_drop_recipient_resolution_fail_closed_422() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    mock_engine = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, sender_sk, datetime.now(timezone.utc) + timedelta(hours=1))

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(sender.id, "student", "active")
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: mock_engine
    app.dependency_overrides[get_private_key_cache] = lambda: key_cache
    # Use default resolver which returns None
    app.dependency_overrides[get_recipient_key_resolver] = lambda: DefaultRecipientKeyResolver()

    client = TestClient(app)
    resp = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-fail-closed-00001"},
        json={
            "content": "Fail closed test",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )
    assert resp.status_code == 422
    assert resp.json()["code"] == "VALIDATION_ERROR"


def test_create_text_drop_quota_exhausted_429() -> None:
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

    for i in range(20):
        resp = client.post(
            "/api/v1/drops/text",
            headers={"Idempotency-Key": f"idemp-quota-drain-{i:010d}"},
            json={
                "content": f"Drain {i}",
                "ttl_policy": "burn_after_read",
                "pqc_mode": False,
            },
        )
        assert resp.status_code == 201

    # 21st attempt should be rejected with 429
    resp_over = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-quota-drain-0000000021"},
        json={
            "content": "Over limit",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )
    assert resp_over.status_code == 429
    assert resp_over.json()["code"] == "RATE_LIMITED"


def test_create_text_drop_engine_unavailable_503() -> None:
    session = _create_sqlite_session()
    sender, recipient, cert, sender_sk = _setup_fixture_data(session)

    class FailingCryptoEngine(MockCryptoEngine):
        def envelope_seal(self, *args, **kwargs):
            raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE)

    failing_engine = FailingCryptoEngine()
    failing_engine.set_result("sm3_digest", b"\xaa" * 32)
    failing_engine.set_result("hkdf_sm3", b"\xbb" * 32)
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, sender_sk, datetime.now(timezone.utc) + timedelta(hours=1))
    resolver = ConfiguredRecipientKeyResolver(recipient.id, failing_engine)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(sender.id, "student", "active")
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: failing_engine
    app.dependency_overrides[get_private_key_cache] = lambda: key_cache
    app.dependency_overrides[get_recipient_key_resolver] = lambda: resolver

    client = TestClient(app)
    resp = client.post(
        "/api/v1/drops/text",
        headers={"Idempotency-Key": "idemp-engine-down-00001"},
        json={
            "content": "Engine down test",
            "ttl_policy": "burn_after_read",
            "pqc_mode": False,
        },
    )
    assert resp.status_code == 503
    assert resp.json()["code"] == "PROVIDER_UNAVAILABLE"
