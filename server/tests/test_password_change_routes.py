from fastapi.testclient import TestClient

from app.api.routes.password import CurrentIdentity, get_current_identity, get_password_change_service
from app.core.errors import install_exception_handlers
from app.main import create_app
from app.services.password_change import PasswordChangeError


class PasswordChanger:
    def __init__(self, error: PasswordChangeError | None = None) -> None:
        self.error = error
        self.received: tuple[str, str, str] | None = None

    def change(self, user_id: str, current_password: str, new_password: str) -> None:
        self.received = (user_id, current_password, new_password)
        if self.error is not None:
            raise self.error


def test_change_password_requires_authentication() -> None:
    response = TestClient(create_app()).patch(
        "/api/v1/me/password",
        json={"current_password": "Current123", "new_password": "NewPassword123"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


def test_change_password_returns_204_and_does_not_return_sensitive_values() -> None:
    app = create_app()
    changer = PasswordChanger()
    app.dependency_overrides[get_current_identity] = lambda: CurrentIdentity("user-1")
    app.dependency_overrides[get_password_change_service] = lambda: changer

    response = TestClient(app).patch(
        "/api/v1/me/password",
        json={"current_password": "Current123", "new_password": "NewPassword123"},
    )

    assert response.status_code == 204
    assert response.content == b""
    assert changer.received == ("user-1", "Current123", "NewPassword123")
    assert "Current123" not in response.text
    assert "NewPassword123" not in response.text


def test_change_password_maps_authentication_failure_to_401() -> None:
    app = create_app()
    app.dependency_overrides[get_current_identity] = lambda: CurrentIdentity("user-1")
    app.dependency_overrides[get_password_change_service] = lambda: PasswordChanger(
        PasswordChangeError("INVALID_CREDENTIALS")
    )

    response = TestClient(app).patch(
        "/api/v1/me/password",
        json={"current_password": "Wrong123", "new_password": "NewPassword123"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_INVALID_CREDENTIALS"
    assert "Wrong123" not in response.text


def test_change_password_rejects_invalid_payload() -> None:
    app = create_app()
    app.dependency_overrides[get_current_identity] = lambda: CurrentIdentity("user-1")
    app.dependency_overrides[get_password_change_service] = lambda: PasswordChanger()

    response = TestClient(app).patch(
        "/api/v1/me/password",
        json={"current_password": "Current123", "new_password": "weak", "user_id": "other"},
    )

    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"


def test_change_password_maps_provider_failure_to_503() -> None:
    app = create_app()
    app.dependency_overrides[get_current_identity] = lambda: CurrentIdentity("user-1")
    app.dependency_overrides[get_password_change_service] = lambda: PasswordChanger(
        PasswordChangeError("PROVIDER_UNAVAILABLE")
    )

    response = TestClient(app).patch(
        "/api/v1/me/password",
        json={"current_password": "Current123", "new_password": "NewPassword123"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "PROVIDER_UNAVAILABLE"
