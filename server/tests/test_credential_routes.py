import base64
from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import create_engine

from app.crypto.dependencies import get_crypto_engine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user
from app.services.signer_provider import get_signer_key_provider


class MockServerSignerKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x44" * SM2_PRIVATE_KEY_SIZE)

    def get_signer_private_key(self, service: str) -> bytes | None:
        return self.key


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


def _setup_route_test():
    session = _create_sqlite_session()
    user = User(
        id=str(uuid.uuid4()),
        email="route_student@campus.edu.cn",
        role="student",
        status="active",
    )
    session.add(user)
    session.commit()

    crypto = DynamicMockCryptoEngine()
    crypto.set_result("blind_sign", b"\x66" * 64)
    signer_provider = MockServerSignerKeyProvider()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_signer_key_provider] = lambda: signer_provider
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=user.id,
        role="student",
        status="active",
    )

    client = TestClient(app)
    today = datetime.now(timezone.utc).date().isoformat()
    return client, session, user, crypto, signer_provider, today


def test_route_issue_credential_success_201():
    client, session, user, crypto, signer_provider, today = _setup_route_test()

    blinded_b64 = base64.b64encode(b"blinded-route-test-message").decode("ascii")
    idemp_key = "idemp-route-key-001"

    response = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": idemp_key},
        json={
            "service": "hole_post",
            "period": today,
            "blinded_message": blinded_b64,
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert "blind_signature" in data
    assert data["algorithm"] == "SM2-BLIND-PROTOCOL-V1"
    # Strict OpenAPI schema boundary: no extra fields allowed
    assert set(data.keys()) == {"blind_signature", "algorithm"}
    assert base64.b64decode(data["blind_signature"]) == b"\x66" * 64


def test_route_issue_credential_missing_auth_401():
    app = create_app()
    client = TestClient(app)

    response = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "idemp-no-auth-0001"},
        json={
            "service": "hole_post",
            "period": "2026-09-09",
            "blinded_message": base64.b64encode(b"msg").decode("ascii"),
        },
    )
    assert response.status_code == 401


def test_route_issue_credential_unauthorized_role_403():
    client, session, user, crypto, signer_provider, today = _setup_route_test()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=user.id,
        role="guest",  # guest not allowed
        status="active",
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "idemp-guest-0001"},
        json={
            "service": "hole_post",
            "period": today,
            "blinded_message": base64.b64encode(b"msg").decode("ascii"),
        },
    )
    assert response.status_code == 403


def test_route_issue_credential_validation_errors_422():
    client, session, user, crypto, signer_provider, today = _setup_route_test()

    blinded_b64 = base64.b64encode(b"msg").decode("ascii")

    # Missing Idempotency-Key header
    resp1 = client.post(
        "/api/v1/hole/credentials",
        json={"service": "hole_post", "period": today, "blinded_message": blinded_b64},
    )
    assert resp1.status_code == 422

    # Idempotency-Key too short (<16)
    resp2 = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "short"},
        json={"service": "hole_post", "period": today, "blinded_message": blinded_b64},
    )
    assert resp2.status_code == 422

    # Invalid service enum
    resp3 = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "valid-idemp-key-16"},
        json={"service": "unsupported", "period": today, "blinded_message": blinded_b64},
    )
    assert resp3.status_code == 422

    # Invalid base64
    resp4 = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "valid-idemp-key-16"},
        json={"service": "hole_post", "period": today, "blinded_message": "!!!not-b64!!!"},
    )
    assert resp4.status_code == 422

    # Wrong period
    resp5 = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "valid-idemp-key-16"},
        json={"service": "hole_post", "period": "2099-01-01", "blinded_message": blinded_b64},
    )
    assert resp5.status_code == 422

    # Extra prohibited field
    resp6 = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "valid-idemp-key-16"},
        json={
            "service": "hole_post",
            "period": today,
            "blinded_message": blinded_b64,
            "sn": "illegal-field",
        },
    )
    assert resp6.status_code == 422


def test_route_issue_credential_quota_exhausted_429():
    client, session, user, crypto, signer_provider, today = _setup_route_test()

    for i in range(1, 6):
        blinded_b64 = base64.b64encode(f"msg-{i}".encode("utf-8")).decode("ascii")
        resp = client.post(
            "/api/v1/hole/credentials",
            headers={"Idempotency-Key": f"idemp-key-route-{i:03d}"},
            json={"service": "hole_post", "period": today, "blinded_message": blinded_b64},
        )
        assert resp.status_code == 201

    # 6th attempt returns 429
    resp_exhausted = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "idemp-key-route-006"},
        json={
            "service": "hole_post",
            "period": today,
            "blinded_message": base64.b64encode(b"msg-6").decode("ascii"),
        },
    )
    assert resp_exhausted.status_code == 429
    assert resp_exhausted.json()["code"] == "RATE_LIMITED"


def test_route_issue_credential_idempotency_conflict_409():
    client, session, user, crypto, signer_provider, today = _setup_route_test()

    shared_key = "idemp-conflict-route-key"
    msg_a = base64.b64encode(b"message-A").decode("ascii")
    msg_b = base64.b64encode(b"message-B").decode("ascii")

    resp_a = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": shared_key},
        json={"service": "hole_post", "period": today, "blinded_message": msg_a},
    )
    assert resp_a.status_code == 201

    resp_b = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": shared_key},
        json={"service": "hole_post", "period": today, "blinded_message": msg_b},
    )
    assert resp_b.status_code == 409
    assert resp_b.json()["code"] == "CONFLICT"


def test_route_issue_credential_engine_unavailable_503():
    client, session, user, crypto, signer_provider, today = _setup_route_test()

    crypto.set_error("blind_sign", CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))

    resp = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "idemp-key-engine-503"},
        json={
            "service": "hole_post",
            "period": today,
            "blinded_message": base64.b64encode(b"msg-503").decode("ascii"),
        },
    )
    assert resp.status_code == 503
    assert resp.json()["code"] == "PROVIDER_UNAVAILABLE"
