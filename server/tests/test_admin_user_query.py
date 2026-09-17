from datetime import datetime, timezone
import uuid
import pytest

from app.models.user import User
from app.services.admin_users import AdminUserQueryService


def _user(db_session, email: str, role: str = "student", status: str = "active") -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        role=role,
        status=status,
        salt_a=b"salt_a_secret",
        auth_hash=b"auth_hash_secret",
        salt_k=b"salt_k_secret",
        enc_sk=b"enc_sk_secret",
        pubkey=b"pubkey",
        cert_serial=f"cert-{email}",
        pqc_pubkey=b"pqc_pub",
        enc_pqc_sk=b"enc_pqc_sk_secret",
    )
    db_session.add(u)
    db_session.commit()
    return u


def test_list_users_pagination_and_ordering(db_session) -> None:
    service = AdminUserQueryService(db_session)
    u1 = _user(db_session, "user1@campus.edu")
    u2 = _user(db_session, "user2@campus.edu")
    u3 = _user(db_session, "user3@campus.edu")

    result = service.list_users(page=1, page_size=2)
    assert result.page == 1
    assert result.page_size == 2
    assert result.total >= 3
    assert len(result.items) == 2
    # Check ordering: created_at DESC, id DESC
    assert result.items[0].created_at >= result.items[1].created_at


def test_list_users_filters_out_system_user(db_session) -> None:
    service = AdminUserQueryService(db_session)
    sys_user = _user(db_session, "system@campus.edu", role="system")
    normal_user = _user(db_session, "normal@campus.edu", role="student")

    result = service.list_users(page=1, page_size=50)
    user_ids = [item.id for item in result.items]
    assert normal_user.id in user_ids
    assert sys_user.id not in user_ids


def test_list_users_sensitivities_omitted(db_session) -> None:
    service = AdminUserQueryService(db_session)
    u = _user(db_session, "sensitive_check@campus.edu")

    result = service.list_users(page=1, page_size=10)
    found = next(item for item in result.items if item.id == u.id)

    dumped = found.model_dump() if hasattr(found, "model_dump") else found.__dict__
    # Sensitive fields must not be present in the user item DTO
    for field in ("salt_a", "auth_hash", "salt_k", "enc_sk", "enc_pqc_sk", "cert_serial"):
        assert field not in dumped
