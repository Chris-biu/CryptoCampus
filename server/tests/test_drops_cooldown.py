from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.drop import Drop
from app.models.user import User
from app.services.drop import DropServiceError
from app.services.extract_cooldown import ExtractAttemptGuard, SqlAlchemyExtractCooldownGuard


def _create_test_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def _create_dummy_drop(session: Session, status: str = "available", failed_attempts: int = 0, cooldown_until: datetime | None = None) -> Drop:
    owner = User(id=str(uuid.uuid4()), email="owner@campus.edu", role="student", status="active")
    recipient = User(id=str(uuid.uuid4()), email="recv@campus.edu", role="student", status="active")
    session.add_all([owner, recipient])
    session.commit()

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=owner.id,
        recipient_user_id=recipient.id,
        link_code_hash=b"\x01" * 32,
        kind="text",
        envelope_version=1,
        ciphertext=b"enc",
        nonce=b"\x02" * 12,
        tag=b"\x03" * 16,
        enc_key_sm2=b"\x04" * 96,
        sender_signature=b"\x05" * 64,
        sender_certificate_der=b"\x30\x82\x01\x00" + b"\x06" * 50,
        sender_cert_serial="CERT-001",
        recipient_sm2_fingerprint=b"\x07" * 32,
        access_code_hash=b"\x08" * 32,
        ttl_policy="hours_24",
        burn_after_read=False,
        content_size=10,
        pqc_mode=False,
        status=status,
        failed_attempts=failed_attempts,
        cooldown_until=cooldown_until,
    )
    session.add(drop)
    session.commit()
    return drop


def test_guard_protocol_runtime_checkable() -> None:
    session = _create_test_session()
    guard = SqlAlchemyExtractCooldownGuard(session)
    assert isinstance(guard, ExtractAttemptGuard)


def test_before_attempt_available_drop_passes() -> None:
    session = _create_test_session()
    drop = _create_dummy_drop(session, status="available", failed_attempts=0)
    guard = SqlAlchemyExtractCooldownGuard(session)
    now = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)

    # Should not raise
    guard.before_attempt(drop, now)
    assert drop.status == "available"


def test_before_attempt_cooling_down_active_fails_closed() -> None:
    session = _create_test_session()
    now = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    cooldown_until = now + timedelta(minutes=10)
    drop = _create_dummy_drop(session, status="cooling_down", failed_attempts=5, cooldown_until=cooldown_until)
    guard = SqlAlchemyExtractCooldownGuard(session)

    # Attempt during cooldown (e.g. 5 minutes in)
    attempt_time = now + timedelta(minutes=5)
    with pytest.raises(DropServiceError) as exc_info:
        guard.before_attempt(drop, attempt_time)

    assert exc_info.value.code == "cooling_down"
    assert "密信不存在或链接已失效" in exc_info.value.message


def test_before_attempt_cooling_down_expired_resets_to_available() -> None:
    session = _create_test_session()
    now = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    cooldown_until = now + timedelta(minutes=10)
    drop = _create_dummy_drop(session, status="cooling_down", failed_attempts=5, cooldown_until=cooldown_until)
    guard = SqlAlchemyExtractCooldownGuard(session)

    # Attempt exactly at or after cooldown_until (e.g. 10 minutes in)
    attempt_time = now + timedelta(minutes=10)
    guard.before_attempt(drop, attempt_time)

    # Must be reset
    assert drop.status == "available"
    assert drop.failed_attempts == 0
    assert drop.cooldown_until is None

    # Check persistence in DB
    refreshed = session.get(Drop, drop.id)
    assert refreshed.status == "available"
    assert refreshed.failed_attempts == 0
    assert refreshed.cooldown_until is None


@pytest.mark.parametrize("status", ["consumed", "expired", "destroyed"])
def test_before_attempt_unavailable_statuses_raise_not_found(status: str) -> None:
    session = _create_test_session()
    drop = _create_dummy_drop(session, status=status)
    guard = SqlAlchemyExtractCooldownGuard(session)
    now = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)

    with pytest.raises(DropServiceError) as exc_info:
        guard.before_attempt(drop, now)
    assert exc_info.value.code == "not_found"


def test_record_failure_increments_attempts_until_threshold() -> None:
    session = _create_test_session()
    drop = _create_dummy_drop(session, status="available", failed_attempts=0)
    guard = SqlAlchemyExtractCooldownGuard(session)
    now = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)

    # Failures 1 through 4
    for i in range(1, 5):
        attempts = guard.record_failure(drop.id, now)
        assert attempts == i
        refreshed = session.get(Drop, drop.id)
        assert refreshed.failed_attempts == i
        assert refreshed.status == "available"
        assert refreshed.cooldown_until is None

    # 5th failure enters cooling_down
    attempts = guard.record_failure(drop.id, now)
    assert attempts == 5
    refreshed = session.get(Drop, drop.id)
    assert refreshed.failed_attempts == 5
    assert refreshed.status == "cooling_down"
    assert refreshed.cooldown_until == now + timedelta(minutes=10)

    # 6th failure while already in cooldown does not exceed 5
    attempts = guard.record_failure(drop.id, now)
    assert attempts == 5
    refreshed = session.get(Drop, drop.id)
    assert refreshed.failed_attempts == 5
    assert refreshed.status == "cooling_down"


def test_record_failure_after_cooldown_expired_resets_and_counts_as_one() -> None:
    session = _create_test_session()
    start = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    cooldown_until = start + timedelta(minutes=10)
    drop = _create_dummy_drop(session, status="cooling_down", failed_attempts=5, cooldown_until=cooldown_until)
    guard = SqlAlchemyExtractCooldownGuard(session)

    # Now is 11 minutes later (cooldown expired)
    now = start + timedelta(minutes=11)
    attempts = guard.record_failure(drop.id, now)
    assert attempts == 1
    refreshed = session.get(Drop, drop.id)
    assert refreshed.status == "available"
    assert refreshed.failed_attempts == 1
    assert refreshed.cooldown_until is None


def test_record_success_resets_failed_attempts_and_cooldown() -> None:
    session = _create_test_session()
    now = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    drop = _create_dummy_drop(session, status="available", failed_attempts=3)
    guard = SqlAlchemyExtractCooldownGuard(session)

    guard.record_success(drop.id, now)
    refreshed = session.get(Drop, drop.id)
    assert refreshed.failed_attempts == 0
    assert refreshed.cooldown_until is None
