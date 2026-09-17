from datetime import datetime, timedelta, timezone

from app.models.user import User
from app.security.cookies import REFRESH_COOKIE_NAME, build_refresh_cookie, parse_refresh_token
from app.services.sessions import SessionService
from app.security.tokens import TokenIssuerError
from fastapi.testclient import TestClient
from app.api.routes.auth import get_session_service, get_access_token_issuer
from app.main import create_app


NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


class DigestEngine:
    def sm3_digest(self, message: bytes) -> bytes:
        assert message
        return (message[:1] * 32).ljust(32, b"d")


class Issuer:
    def issue_access_token(self, user_id, role, now, sid=None):
        return f"access-{sid}"


class FailingIssuer:
    def issue_access_token(self, *args, **kwargs):
        raise TokenIssuerError()


def test_refresh_cookie_is_validated_and_has_secure_attributes():
    cookie = build_refresh_cookie("token-value")
    assert cookie.name == REFRESH_COOKIE_NAME
    assert cookie.httponly is True
    assert cookie.secure is True
    assert cookie.samesite == "lax"
    assert cookie.path == "/api/v1/auth"
    assert cookie.max_age == 604800
    assert parse_refresh_token("token-value") == "token-value"


def test_create_session_stores_only_sm3_digest(db_session):
    user = User(
        email="session@example.edu",
        salt_a=b"a",
        auth_hash=b"h",
        salt_k=b"k",
        enc_sk=b"e",
        pubkey=b"p",
        cert_serial="session-cert",
    )
    db_session.add(user)
    db_session.commit()

    service = SessionService(db_session, DigestEngine(), token_factory=lambda: "opaque-refresh")
    token, session = service.create(user.id, "browser", "192.168.1.42", NOW)

    assert token == "opaque-refresh"
    assert session.refresh_token_hash == b"o" * 32
    assert session.expires_at == NOW + timedelta(days=7)
    assert "opaque-refresh" not in repr(session)


def test_refresh_atomically_rotates_and_rejects_replay(db_session):
    user = User(email="rotate@example.edu", salt_a=b"a", auth_hash=b"h", salt_k=b"k", enc_sk=b"e", pubkey=b"p", cert_serial="rotate-cert")
    db_session.add(user)
    db_session.commit()
    tokens = iter(["initial-token", "replacement-token"])
    service = SessionService(db_session, DigestEngine(), token_factory=lambda: next(tokens))
    old_token, old_record = service.create(user.id, "browser", "192.168.1.42", NOW)
    new_token, new_record, rotated_user, access_token = service.refresh(old_token, NOW, "browser", "192.168.1.43", Issuer())
    assert new_token == "replacement-token"
    assert old_record.revoked is True
    assert new_record.revoked is False
    assert rotated_user.id == user.id
    assert access_token == f"access-{new_record.id}"
    try:
        service.refresh(old_token, NOW, "browser", "192.168.1.43", Issuer())
    except Exception as error:
        assert getattr(error, "code", None) == "invalid"
    else:
        raise AssertionError("replay unexpectedly succeeded")


def test_refresh_rolls_back_when_access_token_issuer_fails(db_session):
    user = User(email="rollback@example.edu", salt_a=b"a", auth_hash=b"h", salt_k=b"k", enc_sk=b"e", pubkey=b"p", cert_serial="rollback-cert")
    db_session.add(user)
    db_session.commit()
    tokens = iter(["initial-token", "replacement-token"])
    service = SessionService(db_session, DigestEngine(), token_factory=lambda: next(tokens))
    old_token, old_record = service.create(user.id, "browser", "192.168.1.42", NOW)
    try:
        service.refresh(old_token, NOW, "browser", "192.168.1.43", FailingIssuer())
    except Exception as error:
        assert getattr(error, "code", None) == "internal"
    assert db_session.get(type(old_record), old_record.id).revoked is False


def test_refresh_route_returns_auth_session_and_replacement_cookie():
    class RouteService:
        def refresh(self, token, now, device, ip, issuer):
            user = User(id="route-user", email="route@example.edu", role="student", status="active", salt_a=b"a", auth_hash=b"h", salt_k=b"k", enc_sk=b"e", pubkey=b"p", cert_serial="route-cert", created_at=NOW)
            record = type("Record", (), {"id": "session-1"})()
            return "replacement-token", record, user, "access-token"

    app = create_app()
    app.dependency_overrides[get_session_service] = lambda: RouteService()
    app.dependency_overrides[get_access_token_issuer] = lambda: Issuer()
    response = TestClient(app).post(
        "/api/v1/auth/refresh",
        headers={"Cookie": "refresh_token=opaque-refresh-token"},
    )
    assert response.status_code == 200
    assert response.json()["access_token"] == "access-token"
    assert "refresh_token=replacement-token" in response.headers["set-cookie"]
