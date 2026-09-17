from datetime import datetime, timezone

import pytest

from app.models.credential import CredentialLedger
from app.models.user import User
from app.db.session import create_session_factory
from app.services.quota import QuotaError, QuotaService


def _user(db_session) -> User:
    user = User(
        email="quota@campus.edu",
        salt_a=b"a",
        auth_hash=b"h",
        salt_k=b"k",
        enc_sk=b"e",
        pubkey=b"p",
        cert_serial="quota-cert",
    )
    db_session.add(user)
    db_session.commit()
    return user


def test_reserve_uses_utc_period_and_never_exceeds_limit(db_session) -> None:
    user = _user(db_session)
    service = QuotaService(db_session)
    now = datetime(2026, 9, 7, 23, 59, tzinfo=timezone.utc)

    for _ in range(5):
        service.reserve(user.id, "hole_credential", now)

    with pytest.raises(QuotaError, match="exhausted"):
        service.reserve(user.id, "hole_credential", now)

    record = db_session.query(CredentialLedger).one()
    assert (record.user_id, record.service, record.period, record.issued_count) == (
        user.id,
        "hole_credential",
        "2026-09-07",
        5,
    )


def test_reserve_rejects_unknown_service_and_uses_vote_id_period(db_session) -> None:
    user = _user(db_session)
    service = QuotaService(db_session)
    now = datetime(2026, 9, 7, tzinfo=timezone.utc)

    with pytest.raises(QuotaError, match="resource_invalid"):
        service.reserve(user.id, "made_up", now)

    service.reserve(user.id, "vote_ballot", now, period="vote-1")
    with pytest.raises(QuotaError, match="exhausted"):
        service.reserve(user.id, "vote_ballot", now, period="vote-1")
    service.reserve(user.id, "vote_ballot", now, period="vote-2")


def test_get_and_reset_current_period_are_scoped_to_user_and_audited(db_session) -> None:
    user = _user(db_session)
    admin = User(
        email="admin@campus.edu",
        role="admin",
        salt_a=b"a",
        auth_hash=b"h",
        salt_k=b"k",
        enc_sk=b"e",
        pubkey=b"p",
        cert_serial="admin-cert",
    )
    db_session.add(admin)
    db_session.commit()
    service = QuotaService(db_session, digest=lambda value: b"q" * 32)
    now = datetime(2026, 9, 7, tzinfo=timezone.utc)
    service.reserve(user.id, "drop", now)

    result = service.reset(user.id, admin.id, "r" * 16, now)

    assert next(item for item in result if item.resource == "drop").used == 0
    assert db_session.query(CredentialLedger).filter_by(user_id=user.id).one().issued_count == 0


def test_reset_rejects_pending_deletion_user(db_session) -> None:
    user = _user(db_session)
    user.status = "pending_deletion"
    admin = User(email="pending-reset-admin@campus.edu", role="admin")
    db_session.add(admin)
    db_session.commit()

    with pytest.raises(QuotaError, match="pending_deletion"):
        QuotaService(db_session).reset(user.id, admin.id, "p" * 16, datetime(2026, 9, 7, tzinfo=timezone.utc))


def test_reset_persists_after_service_performs_existence_lookups(db_engine) -> None:
    from app.db.session import init_database

    init_database(db_engine)
    session_factory = create_session_factory(db_engine)
    with session_factory() as session:
        user = _user(session)
        admin = User(email="persist-reset-admin@campus.edu", role="admin")
        session.add(admin)
        session.add(CredentialLedger(user_id=user.id, service="drop", period="2026-09-07", issued_count=1))
        session.commit()
        user_id, admin_id = user.id, admin.id
    with session_factory() as session:
        QuotaService(session, digest=lambda value: b"d" * 32).reset(user_id, admin_id, "s" * 16, datetime(2026, 9, 7, tzinfo=timezone.utc))
    with session_factory() as session:
        assert session.query(CredentialLedger).filter_by(user_id=user_id).one().issued_count == 0
