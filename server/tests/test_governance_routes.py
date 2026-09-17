from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.api.routes.admin import get_governance_service, get_quota_service
from app.api.routes.me import get_account_governance_service, get_me_quota_service
from app.api.routes.system import get_crypto_engine
from app.db.session import get_db
from app.main import create_app
from app.models.user import User
from app.schemas.quota import Quota
from app.security.auth_dependencies import CurrentUser, require_authenticated_user


class Quotas:
    def get(self, user_id, now):
        assert user_id == "user-1"
        return [Quota(resource="drop", used=1, limit=20)]

    def resets_at(self, now):
        return datetime(2026, 9, 8, tzinfo=timezone.utc)

    def reset(self, user_id, actor_id, key, now):
        assert (user_id, actor_id, key) == ("target-1", "admin-1", "a" * 16)
        return [Quota(resource="drop", used=0, limit=20)]


class Governance:
    def update_status(self, actor_id, target_id, status, reason, now):
        assert (actor_id, target_id, status, reason) == ("admin-1", "target-1", "frozen", "reason")
        return type("User", (), {"id": target_id, "email": "target@campus.edu", "role": "student", "status": status, "pqc_pubkey": None, "created_at": datetime(2026, 9, 7, tzinfo=timezone.utc)})()

    def delete_account(self, user_id, password, confirm, now):
        assert (user_id, password, confirm) == ("user-1", "CorrectPassword1", "DELETE_MY_ACCOUNT")


def test_me_quotas_returns_current_user_usage_without_sensitive_fields() -> None:
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser("user-1", "student", "active")
    app.dependency_overrides[get_me_quota_service] = lambda: Quotas()

    response = TestClient(app).get("/api/v1/me/quotas")

    assert response.status_code == 200
    assert response.json()["items"] == [{"resource": "drop", "used": 1, "limit": 20}]
    assert "password" not in response.text.lower()


def test_admin_reset_and_freeze_require_governance_dependencies() -> None:
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser("admin-1", "admin", "active")
    app.dependency_overrides[get_quota_service] = lambda: Quotas()
    app.dependency_overrides[get_governance_service] = lambda: Governance()
    client = TestClient(app)

    reset = client.post("/api/v1/admin/users/target-1/quotas/reset", headers={"Idempotency-Key": "a" * 16})
    freeze = client.patch("/api/v1/admin/users/target-1/status", json={"status": "frozen", "reason": "reason"})

    assert reset.status_code == 200
    assert reset.json()["items"][0]["used"] == 0
    assert freeze.status_code == 200
    assert freeze.json()["status"] == "frozen"


def test_delete_account_returns_accepted_without_password_echo() -> None:
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser("user-1", "student", "active")
    app.dependency_overrides[get_account_governance_service] = lambda: Governance()

    response = TestClient(app).request(
        "DELETE",
        "/api/v1/me/account",
        json={"password": "CorrectPassword1", "confirm": "DELETE_MY_ACCOUNT"},
    )

    assert response.status_code == 202
    assert response.json() == {"accepted": True}
    assert "CorrectPassword1" not in response.text


def test_admin_quota_reset_rejects_reused_idempotency_key(db_session) -> None:
    admin = User(email="route-admin@campus.edu", role="admin")
    target = User(email="route-target@campus.edu")
    db_session.add_all([admin, target])
    db_session.commit()
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(admin.id, "admin", "active")
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: type("Engine", (), {"sm3_digest": lambda self, value: b"d" * 32})()
    client = TestClient(app)
    headers = {"Idempotency-Key": "b" * 16}

    first = client.post(f"/api/v1/admin/users/{target.id}/quotas/reset", headers=headers)
    repeated = client.post(f"/api/v1/admin/users/{target.id}/quotas/reset", headers=headers)

    assert first.status_code == 200
    assert repeated.status_code == 200
    assert repeated.json() == first.json()

    target2 = User(email="route-target2@campus.edu")
    db_session.add(target2)
    db_session.commit()
    conflict = client.post(f"/api/v1/admin/users/{target2.id}/quotas/reset", headers=headers)
    assert conflict.status_code == 409
