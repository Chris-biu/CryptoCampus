import pytest
from fastapi.testclient import TestClient

from app.api.routes.system import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import ProviderStatus
from app.db.session import get_db
from app.main import create_app
from app.models.provider_reload import ProviderReloadIdempotency
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user


def test_reload_requires_authentication() -> None:
    app = create_app()
    client = TestClient(app)
    response = client.post("/api/v1/admin/providers/reload", headers={"Idempotency-Key": "a" * 16})
    assert response.status_code == 401


def test_reload_forbids_student_role() -> None:
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        "student-1", "student", "active"
    )
    client = TestClient(app)
    response = client.post("/api/v1/admin/providers/reload", headers={"Idempotency-Key": "a" * 16})
    assert response.status_code == 403


def test_reload_requires_idempotency_key() -> None:
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        "admin-1", "admin", "active"
    )
    client = TestClient(app)
    response = client.post("/api/v1/admin/providers/reload")
    assert response.status_code == 422


def test_reload_rejects_invalid_idempotency_key_length() -> None:
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        "admin-1", "admin", "active"
    )
    client = TestClient(app)
    response = client.post("/api/v1/admin/providers/reload", headers={"Idempotency-Key": "short"})
    assert response.status_code == 422


def test_reload_default_engine_returns_503(db_session) -> None:
    admin = User(id="admin-reload-0", email="admin0@campus.edu", role="admin")
    db_session.add(admin)
    db_session.commit()

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        admin.id, "admin", "active"
    )
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    response = client.post("/api/v1/admin/providers/reload", headers={"Idempotency-Key": "k" * 16})
    assert response.status_code == 503
    assert response.json()["code"] == "PROVIDER_UNAVAILABLE"


def test_reload_success_for_admin(db_session) -> None:
    admin = User(id="admin-reload-1", email="admin1@campus.edu", role="admin")
    db_session.add(admin)
    db_session.commit()

    engine = MockCryptoEngine(
        status=ProviderStatus(
            state="online",
            version="v1",
            provider="mock",
            capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
        )
    )
    engine.set_result(
        "reload_pqc_provider",
        ProviderStatus(
            state="online",
            version="v2",
            provider="mock-pqc",
            capabilities={"sm2": True, "sm3": True, "sm4_gcm": True, "ml_kem_768": True},
        ),
    )
    engine.set_result("sm3_digest", b"\x55" * 32)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        admin.id, "admin", "active"
    )
    app.dependency_overrides[get_crypto_engine] = lambda: engine
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    response = client.post("/api/v1/admin/providers/reload", headers={"Idempotency-Key": "x" * 20})
    assert response.status_code == 200
    data = response.json()
    assert data["api"] == "ok"
    assert data["engine"] == "online"
    assert data["providers"]["ml_kem_768"] is True


def test_reload_same_key_replays_cached_response(db_session) -> None:
    admin = User(id="admin-reload-2", email="admin2@campus.edu", role="admin")
    db_session.add(admin)
    db_session.commit()

    engine = MockCryptoEngine(
        status=ProviderStatus(
            state="online",
            version="v1",
            provider="mock",
            capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
        )
    )
    engine.set_result("sm3_digest", b"\x66" * 32)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        admin.id, "admin", "active"
    )
    app.dependency_overrides[get_crypto_engine] = lambda: engine
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    headers = {"Idempotency-Key": "replay-key-000001"}

    first = client.post("/api/v1/admin/providers/reload", headers=headers)
    assert first.status_code == 200

    second = client.post("/api/v1/admin/providers/reload", headers=headers)
    assert second.status_code == 200
    assert first.json() == second.json()


def test_reload_conflict_returns_409(db_session) -> None:
    admin = User(id="admin-reload-3", email="admin3@campus.edu", role="admin")
    db_session.add(admin)
    db_session.commit()

    # Pre-insert a conflicting record
    record = ProviderReloadIdempotency(
        actor_id=admin.id,
        key_hash=b"\x77" * 32,
        request_hash=b"\x88" * 32,
        response_json='{"api":"ok","engine":"online","version":"1.0.0","tlcp":"unknown","providers":{}}',
        outcome="success",
    )
    db_session.add(record)
    db_session.commit()

    engine = MockCryptoEngine()
    engine.set_result("sm3_digest", b"\x77" * 32)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        admin.id, "admin", "active"
    )
    app.dependency_overrides[get_crypto_engine] = lambda: engine
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    response = client.post(
        "/api/v1/admin/providers/reload",
        headers={"Idempotency-Key": "conflict-key-00001"},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "CONFLICT"
