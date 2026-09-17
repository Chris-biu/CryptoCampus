from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.api.routes.auth import get_registration_service, get_verification_service
from app.main import create_app
from app.schemas.auth import AuthSession


class Verification:
    def __init__(self): self.emails = []
    def issue(self, email): self.emails.append(email)


class Registration:
    def register(self, email, password, verification_code):
        return AuthSession(access_token="injected", user={
            "id": "00000000-0000-0000-0000-000000000001", "email": email,
            "role": "student", "status": "active", "pqc_mode": False,
            "created_at": datetime.now(timezone.utc),
        })


def test_request_code_returns_accepted_without_code() -> None:
    app = create_app(); verification = Verification()
    app.dependency_overrides[get_verification_service] = lambda: verification
    response = TestClient(app).post("/api/v1/auth/register/request-code", json={"email": " A@campus.edu "})
    assert response.status_code == 202
    assert response.json() == {"accepted": True}
    assert verification.emails == ["a@campus.edu"]


def test_register_returns_injected_auth_session_only() -> None:
    app = create_app()
    app.dependency_overrides[get_registration_service] = Registration
    response = TestClient(app).post("/api/v1/auth/register", json={
        "email": "a@campus.edu", "password": "Password123", "verification_code": "123456"
    })
    assert response.status_code == 201
    body = response.json()
    assert body["access_token"] == "injected"
    assert "password" not in str(body)
    assert "verification_code" not in str(body)
