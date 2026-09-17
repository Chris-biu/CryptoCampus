from datetime import datetime, timezone

import pytest

from app.models.audit import AuditLog
from app.models.session import UserSession
from app.models.user import User
from app.db.session import create_session_factory, init_database
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.account_lifecycle import AccountGovernanceError, AccountGovernanceService


def _user(db_session, email: str, *, role: str = "student") -> User:
    user = User(
        email=email,
        role=role,
        salt_a=b"a",
        auth_hash=b"h",
        salt_k=b"k",
        enc_sk=b"e",
        pubkey=b"p",
        cert_serial=f"{email}-cert",
    )
    db_session.add(user)
    db_session.commit()
    return user


def test_freeze_revokes_all_sessions_invalidates_cache_and_audits(db_session) -> None:
    actor = _user(db_session, "admin@campus.edu", role="admin")
    target = _user(db_session, "target@campus.edu")
    db_session.add_all(
        [
            UserSession(user_id=target.id, device="one", ip="1.1.1.1", refresh_token_hash=b"1" * 32, expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc), last_active_at=datetime(2026, 9, 7, tzinfo=timezone.utc)),
            UserSession(user_id=target.id, device="two", ip="1.1.1.2", refresh_token_hash=b"2" * 32, expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc), last_active_at=datetime(2026, 9, 7, tzinfo=timezone.utc)),
        ]
    )
    db_session.commit()
    cache = PrivateKeyUnlockCache()
    cache.put(target.id, b"private", datetime(2026, 9, 8, tzinfo=timezone.utc))

    result = AccountGovernanceService(db_session, lambda value: b"d" * 32, cache).update_status(
        actor.id, target.id, "frozen", "policy violation", datetime(2026, 9, 7, tzinfo=timezone.utc)
    )

    assert result.status == "frozen"
    assert all(session.revoked for session in db_session.query(UserSession).filter_by(user_id=target.id))
    assert cache.get(target.id, datetime(2026, 9, 7, tzinfo=timezone.utc)) is None
    assert db_session.query(AuditLog).filter_by(action="user.freeze").count() == 1


def test_status_change_is_idempotent_and_never_changes_system_user(db_session) -> None:
    actor = _user(db_session, "teacher@campus.edu", role="teacher")
    target = _user(db_session, "student@campus.edu")
    system = _user(db_session, "system@campus.edu", role="system")
    service = AccountGovernanceService(db_session, lambda value: b"d" * 32, PrivateKeyUnlockCache())
    now = datetime(2026, 9, 7, tzinfo=timezone.utc)

    service.update_status(actor.id, target.id, "frozen", "reason", now)
    service.update_status(actor.id, target.id, "frozen", "reason", now)

    assert db_session.query(AuditLog).filter_by(action="user.freeze").count() == 1
    try:
        service.update_status(actor.id, system.id, "frozen", "reason", now)
    except Exception as error:
        assert getattr(error, "code", None) == "system_user"
    else:
        raise AssertionError("system account was changed")


def test_status_change_rejects_pending_deletion_user(db_session) -> None:
    actor = _user(db_session, "admin-pending@campus.edu", role="admin")
    target = _user(db_session, "pending@campus.edu")
    target.status = "pending_deletion"
    target.email = None
    target.salt_a = None
    target.auth_hash = None
    target.salt_k = None
    target.enc_sk = None
    target.pubkey = None
    target.cert_serial = None
    db_session.commit()
    service = AccountGovernanceService(db_session, lambda value: b"d" * 32, PrivateKeyUnlockCache())

    with pytest.raises(AccountGovernanceError, match="pending_deletion"):
        service.update_status(actor.id, target.id, "active", "reason", datetime(2026, 9, 7, tzinfo=timezone.utc))

    db_session.refresh(target)
    assert target.status == "pending_deletion"
    assert db_session.query(AuditLog).filter_by(target=f"user:{target.id}").count() == 0


def test_freeze_persists_after_service_reads_target(db_engine) -> None:
    init_database(db_engine)
    session_factory = create_session_factory(db_engine)
    with session_factory() as session:
        actor = _user(session, "persist-freeze-admin@campus.edu", role="admin")
        target = _user(session, "persist-freeze-target@campus.edu")
        session.add(UserSession(user_id=target.id, device="one", ip="1.1.1.1", refresh_token_hash=b"f" * 32, expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc), last_active_at=datetime(2026, 9, 7, tzinfo=timezone.utc)))
        session.commit()
        actor_id, target_id = actor.id, target.id
    with session_factory() as session:
        AccountGovernanceService(session, lambda value: b"d" * 32, PrivateKeyUnlockCache()).update_status(actor_id, target_id, "frozen", "reason", datetime(2026, 9, 7, tzinfo=timezone.utc))
    with session_factory() as session:
        assert session.get(User, target_id).status == "frozen"
        assert session.query(UserSession).filter_by(user_id=target_id).one().revoked is True
