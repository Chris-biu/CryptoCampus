import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.errors import ApiError, install_exception_handlers
from app.security.auth_dependencies import CurrentUser, require_authenticated_user, require_roles


def create_role_app(current_user: CurrentUser, *allowed_roles: str) -> FastAPI:
    app = FastAPI()
    install_exception_handlers(app)
    app.dependency_overrides[require_authenticated_user] = lambda: current_user

    @app.get("/role-protected")
    def protected(user: CurrentUser = Depends(require_roles(*allowed_roles))):
        return {"role": user.role}

    return app


@pytest.mark.parametrize("role", ["student", "admin", "teacher"])
def test_require_roles_allows_each_declared_http_role(role: str) -> None:
    app = create_role_app(CurrentUser("user-1", role, "active"), role)

    response = TestClient(app).get("/role-protected")

    assert response.status_code == 200
    assert response.json() == {"role": role}


@pytest.mark.parametrize(
    ("allowed", "actual"),
    [
        (("student",), "admin"),
        (("admin", "teacher"), "student"),
        (("admin", "teacher"), "system"),
    ],
)
def test_require_roles_rejects_disallowed_role_with_403(allowed, actual: str) -> None:
    app = create_role_app(CurrentUser("user-1", actual, "active"), *allowed)

    response = TestClient(app).get("/role-protected")

    assert response.status_code == 403
    assert response.json()["code"] == "FORBIDDEN"
    assert response.json()["message"] == "无权限"
    assert actual not in response.text


@pytest.mark.parametrize("allowed", [(), ("guest",), ("system",), ("student", "guest")])
def test_require_roles_rejects_empty_or_non_http_roles(allowed) -> None:
    with pytest.raises(ValueError):
        require_roles(*allowed)


def test_require_roles_preserves_401_for_unauthenticated_request() -> None:
    app = FastAPI()
    install_exception_handlers(app)

    def reject_unauthenticated() -> CurrentUser:
        raise ApiError(401, "UNAUTHORIZED", "未授权")

    app.dependency_overrides[require_authenticated_user] = reject_unauthenticated

    @app.get("/role-protected")
    def protected(user: CurrentUser = Depends(require_roles("admin"))):
        return {"role": user.role}

    response = TestClient(app).get("/role-protected")

    assert response.status_code == 401
