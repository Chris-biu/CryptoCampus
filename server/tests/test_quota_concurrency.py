from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier

import pytest

from app.db.session import create_db_engine, create_session_factory, init_database
from app.models.credential import CredentialLedger
from app.models.user import User
from app.services.quota import QuotaError, QuotaService


def _create_user(session_factory) -> str:
    with session_factory() as session:
        user = User(
            email="concurrent-quota@campus.edu",
            salt_a=b"a",
            auth_hash=b"h",
            salt_k=b"k",
            enc_sk=b"e",
            pubkey=b"p",
            cert_serial="concurrent-quota-cert",
        )
        session.add(user)
        session.commit()
        return user.id


def test_concurrent_reservations_never_exceed_resource_limit(tmp_path) -> None:
    engine = create_db_engine(f"sqlite+pysqlite:///{(tmp_path / 'quota.db').as_posix()}")
    init_database(engine)
    session_factory = create_session_factory(engine)
    user_id = _create_user(session_factory)
    barrier = Barrier(7)
    now = datetime(2026, 9, 7, tzinfo=timezone.utc)

    def reserve_once() -> str:
        with session_factory() as session:
            barrier.wait()
            try:
                QuotaService(session).reserve(user_id, "hole_credential", now)
                return "reserved"
            except QuotaError as error:
                return error.code

    try:
        with ThreadPoolExecutor(max_workers=7) as executor:
            outcomes = list(executor.map(lambda _: reserve_once(), range(7)))
        with session_factory() as session:
            record = session.query(CredentialLedger).one()
            assert record.issued_count == 5
        assert outcomes.count("reserved") == 5
        assert outcomes.count("exhausted") == 2
    finally:
        engine.dispose()


def test_reservation_rolls_back_with_outer_business_transaction(tmp_path) -> None:
    engine = create_db_engine(f"sqlite+pysqlite:///{(tmp_path / 'quota-rollback.db').as_posix()}")
    init_database(engine)
    session_factory = create_session_factory(engine)
    user_id = _create_user(session_factory)
    now = datetime(2026, 9, 7, tzinfo=timezone.utc)

    try:
        with session_factory() as session:
            with pytest.raises(RuntimeError, match="business operation failed"):
                with session.begin():
                    QuotaService(session).reserve(user_id, "drop", now)
                    raise RuntimeError("business operation failed")

            assert session.query(CredentialLedger).count() == 0
    finally:
        engine.dispose()
