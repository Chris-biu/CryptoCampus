from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.api.routes.auth import get_session_service, get_access_token_issuer
from app.main import create_app
from app.models.user import User
from app.models.session import UserSession


class Service:
    def __init__(self):
        self.revoked = None

    def revoke(self, token, now):
        self.revoked = token


class Issuer:
    def issue_access_token(self, user_id, role, now, sid=None):
        return "access-token"


def test_logout_revokes_cookie_and_clears_it():
    app = create_app()
    service = Service()
    app.dependency_overrides[get_session_service] = lambda: service
    response = TestClient(app).post(
        "/api/v1/auth/logout",
        headers={"Cookie": "refresh_token=opaque-refresh-token"},
    )
    assert response.status_code == 204
    assert service.revoked == "opaque-refresh-token"
    assert 'refresh_token=""' in response.headers["set-cookie"]
