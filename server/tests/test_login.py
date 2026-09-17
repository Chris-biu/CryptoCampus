from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models.user import User
from app.schemas.auth import LoginRequest


def test_login_request_normalizes_email() -> None:
    request = LoginRequest(email="  Student@Campus.edu ", password="x")

    assert request.email == "student@campus.edu"


@pytest.mark.parametrize(
    "payload",
    [
        {"password": "x"},
        {"email": "student@campus.edu"},
        {"email": "not-an-email", "password": "x"},
        {"email": "student@campus.edu", "password": ""},
        {"email": "student@campus.edu", "password": "x" * 129},
        {"email": "student@campus.edu", "password": "x", "extra": True},
    ],
)
def test_login_request_rejects_invalid_payload(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        LoginRequest.model_validate(payload)


def test_user_login_lockout_fields_persist_with_safe_defaults(db_session) -> None:
    user = User(
        email="student@campus.edu",
        role="student",
        cert_serial="cert-login",
        salt_a=b"a" * 16,
        auth_hash=b"h" * 32,
        salt_k=b"k" * 16,
        enc_sk=b"e",
        pubkey=b"p",
    )
    db_session.add(user)
    db_session.commit()
    db_session.expire_all()

    persisted = db_session.query(User).filter_by(email="student@campus.edu").one()

    assert persisted.failed_login_count == 0
    assert persisted.locked_until is None

    persisted.failed_login_count = 4
    persisted.locked_until = datetime(2030, 1, 1, tzinfo=timezone.utc)
    db_session.commit()
    db_session.expire_all()

    updated = db_session.query(User).filter_by(email="student@campus.edu").one()
    assert updated.failed_login_count == 4
    assert updated.locked_until is not None
