from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas.auth import AuthSession, UserSummary
from app.services.login import LoginError
from app.api.routes.auth import get_login_service


class Login:
    def __init__(self, result: AuthSession | None = None, error: LoginError | None = None) -> None:
        self.result = result
        self.error = error
        self.received: tuple[str, str, datetime] | None = None

    def login(self, email: str, password: str, now: datetime) -> AuthSession:
        self.received = (email, password, now)
        if self.error:
            raise self.error
        assert self.result is not None
        return self.result


def session() -> AuthSession:
    return AuthSession(
        access_token="opaque-token",
        user=UserSummary(
            id="user-1",
            email="student@campus.edu",
            role="student",
            status="active",
            pqc_mode=False,
            created_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        ),
    )


def test_login_route_returns_auth_session_and_normalized_input() -> None:
    app = create_app()
    service = Login(result=session())
    app.dependency_overrides[get_login_service] = lambda: service

    response = TestClient(app).post(
        "/api/v1/auth/login",
        json={"email": " Student@Campus.edu ", "password": "Password123"},
    )

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["expires_in"] == 7200
    assert "password" not in response.text
    assert service.received is not None
    assert service.received[0] == "student@campus.edu"


def test_login_route_maps_auth_errors_to_contract_shape() -> None:
    app = create_app()
    app.dependency_overrides[get_login_service] = lambda: Login(
        error=LoginError("RATE_LIMITED")
    )

    response = TestClient(app).post(
        "/api/v1/auth/login",
        json={"email": "student@campus.edu", "password": "wrong"},
    )

    assert response.status_code == 429
    assert set(response.json()) == {"code", "message", "request_id", "details"}
    assert "wrong" not in response.text


def test_login_route_rejects_invalid_request_with_validation_error() -> None:
    app = create_app()
    response = TestClient(app).post(
        "/api/v1/auth/login", json={"email": "bad", "password": ""}
    )

    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"
