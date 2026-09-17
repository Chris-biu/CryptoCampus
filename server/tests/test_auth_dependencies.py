from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.errors import ApiError, install_exception_handlers
from app.db.session import get_db
from app.models.user import User
from app.security.auth_dependencies import (
    CurrentUser,
    get_current_user,
    get_token_verifier,
    require_authenticated_user,
)


class FakeVerifier:
    def __init__(self, claims=None, error: Exception | None = None) -> None:
        self.claims = claims
        self.error = error

    def verify_access_token(self, token: str, now: datetime) -> dict[str, object]:
        del token, now
        if self.error is not None:
            raise self.error
        return self.claims or {}


def make_user(db_session, *, role="student", status="active") -> User:
    user = User(
        id=str(uuid4()),
        email=f"{uuid4()}@campus.edu",
        role=role,
        status=status,
        salt_a=b"salt-a",
        auth_hash=b"auth-hash",
        salt_k=b"salt-k",
        enc_sk=b"encrypted-sk",
        pubkey=b"pubkey",
        cert_serial=str(uuid4()),
    )
    db_session.add(user)
    db_session.commit()
    return user


def create_protected_app(db_session, verifier) -> FastAPI:
    app = FastAPI()
    install_exception_handlers(app)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_token_verifier] = lambda: verifier

    @app.get("/protected")
    def protected(user: CurrentUser = Depends(require_authenticated_user)):
        return {"user_id": user.user_id, "role": user.role}

    return app


@pytest.mark.parametrize("authorization", [None, "Basic abc", "Bearer", "Bearer   "])
def test_protected_route_rejects_missing_or_malformed_bearer(authorization, db_session) -> None:
    app = create_protected_app(db_session, FakeVerifier())
    headers = {} if authorization is None else {"Authorization": authorization}

    response = TestClient(app).get("/protected", headers=headers)

    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"
    assert "Bearer" not in response.text
    assert "Authorization" not in response.text


def test_protected_route_rejects_verifier_failure(db_session) -> None:
    app = create_protected_app(db_session, FakeVerifier(error=ValueError("jwt details")))

    response = TestClient(app).get("/protected", headers={"Authorization": "Bearer opaque"})

    assert response.status_code == 401
    body = response.json()
    assert body == {
        "code": "UNAUTHORIZED",
        "message": "未授权",
        "request_id": body["request_id"],
        "details": {},
    }
    assert "jwt details" not in response.text


def test_default_verifier_dependency_fails_closed(db_session) -> None:
    app = FastAPI()
    install_exception_handlers(app)
    app.dependency_overrides[get_db] = lambda: db_session

    @app.get("/protected")
    def protected(user: CurrentUser = Depends(require_authenticated_user)):
        return {"user_id": user.user_id}

    response = TestClient(app).get("/protected", headers={"Authorization": "Bearer opaque"})

    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


def test_current_user_uses_database_role_and_returns_safe_identity(db_session) -> None:
    user = make_user(db_session, role="student")
    verifier = FakeVerifier({"sub": user.id, "role": "student", "sid": "session-1"})

    current = get_current_user("Bearer opaque", verifier, db_session)

    assert current == CurrentUser(user_id=user.id, role="student", status="active", session_id="session-1")
    assert "salt_a" not in repr(current)
    assert "auth_hash" not in repr(current)


@pytest.mark.parametrize("status", ["frozen", "pending_deletion"])
def test_current_user_rejects_unavailable_account(status, db_session) -> None:
    user = make_user(db_session, status=status)
    verifier = FakeVerifier({"sub": user.id, "role": "student"})

    with pytest.raises(ApiError) as raised:
        get_current_user("Bearer opaque", verifier, db_session)

    assert getattr(raised.value, "status_code", None) == 401


def test_current_user_rejects_role_claim_mismatch(db_session) -> None:
    user = make_user(db_session, role="admin")
    verifier = FakeVerifier({"sub": user.id, "role": "student"})

    with pytest.raises(ApiError) as raised:
        get_current_user("Bearer opaque", verifier, db_session)

    assert getattr(raised.value, "status_code", None) == 401


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"sub": "not-a-uuid", "role": "student"},
        {"sub": str(uuid4()), "role": "unknown"},
    ],
)
def test_current_user_rejects_invalid_claims_or_missing_user(claims, db_session) -> None:
    with pytest.raises(ApiError) as raised:
        get_current_user("Bearer opaque", FakeVerifier(claims), db_session)

    assert getattr(raised.value, "status_code", None) == 401


def test_role_change_is_checked_on_every_request(db_session) -> None:
    user = make_user(db_session, role="student")
    verifier = FakeVerifier({"sub": user.id, "role": "student"})

    assert get_current_user("Bearer opaque", verifier, db_session).role == "student"
    user.role = "admin"
    db_session.commit()

    with pytest.raises(ApiError) as raised:
        get_current_user("Bearer opaque", verifier, db_session)

    assert getattr(raised.value, "status_code", None) == 401


def test_current_user_rejects_system_role_for_http(db_session) -> None:
    user = make_user(db_session, role="system")
    verifier = FakeVerifier({"sub": user.id, "role": "system"})

    with pytest.raises(ApiError) as raised:
        get_current_user("Bearer opaque", verifier, db_session)

    assert getattr(raised.value, "status_code", None) == 401
