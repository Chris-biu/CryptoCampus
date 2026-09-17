from datetime import datetime, timezone
import pytest
from sqlalchemy.exc import IntegrityError

from app.models.provider_reload import ProviderReloadIdempotency
from app.models.user import User


def test_provider_reload_idempotency_model_persists_and_queries(db_session) -> None:
    admin = User(id="admin-idemp-1", email="admin_idemp@campus.edu", role="admin")
    db_session.add(admin)
    db_session.commit()

    record = ProviderReloadIdempotency(
        actor_id=admin.id,
        key_hash=b"\x01" * 32,
        request_hash=b"\x02" * 32,
        response_json='{"api":"ok","engine":"online","version":"1.0.0","tlcp":"unknown","providers":{"sm2":true}}',
        outcome="success",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(record)
    db_session.commit()

    fetched = (
        db_session.query(ProviderReloadIdempotency)
        .filter_by(actor_id=admin.id, key_hash=b"\x01" * 32)
        .first()
    )
    assert fetched is not None
    assert fetched.actor_id == admin.id
    assert fetched.key_hash == b"\x01" * 32
    assert fetched.request_hash == b"\x02" * 32
    assert fetched.outcome == "success"
    assert "online" in fetched.response_json


def test_provider_reload_idempotency_enforces_unique_actor_key(db_session) -> None:
    admin = User(id="admin-idemp-2", email="admin_idemp2@campus.edu", role="admin")
    db_session.add(admin)
    db_session.commit()

    rec1 = ProviderReloadIdempotency(
        actor_id=admin.id,
        key_hash=b"\x11" * 32,
        request_hash=b"\x22" * 32,
        response_json='{"api":"ok","engine":"online"}',
        outcome="success",
    )
    db_session.add(rec1)
    db_session.commit()

    rec2 = ProviderReloadIdempotency(
        actor_id=admin.id,
        key_hash=b"\x11" * 32,
        request_hash=b"\x33" * 32,
        response_json='{"api":"degraded","engine":"degraded"}',
        outcome="success",
    )
    db_session.add(rec2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
