from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.errors import install_exception_handlers
from app.security.auth_dependencies import CurrentUser, require_roles


def create_route_app() -> FastAPI:
    app = FastAPI()
    install_exception_handlers(app)
    personal_access = require_roles("student", "admin", "teacher")

    @app.get("/personal")
    def personal(user: CurrentUser = Depends(personal_access)):
        return {"user_id": user.user_id}

    @app.get("/public")
    def public() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_protected_test_route_declares_roles_and_ignores_identity_parameters() -> None:
    app = create_route_app()

    response = TestClient(app).get("/personal?user_id=attacker")

    assert response.status_code == 401


def test_public_test_route_does_not_require_jwt() -> None:
    response = TestClient(create_route_app()).get("/public")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
