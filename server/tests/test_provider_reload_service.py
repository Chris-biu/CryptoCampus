import asyncio
from datetime import datetime, timezone
import pytest

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import ProviderStatus
from app.models.audit import AuditLog
from app.models.provider_reload import ProviderReloadIdempotency
from app.models.user import User
from app.services.provider_reload import (
    ProviderOperationLock,
    ProviderReloadConflictError,
    ProviderReloadService,
    ProviderReloadTimeoutError,
    ProviderReloadUnavailableError,
    ProviderReloadValidationError,
)


@pytest.fixture
def admin_user(db_session):
    user = User(id="admin-service-1", email="admin_srv@campus.edu", role="admin")
    db_session.add(user)
    db_session.commit()
    return user


def test_reload_validates_idempotency_key_length(db_session, admin_user) -> None:
    engine = MockCryptoEngine()
    lock = ProviderOperationLock()
    service = ProviderReloadService(engine=engine, session_factory=lambda: db_session, lock=lock)
    now = datetime.now(timezone.utc)

    with pytest.raises(ProviderReloadValidationError) as exc:
        asyncio.run(service.reload(actor_id=admin_user.id, idempotency_key="short", now=now))
    assert exc.value.status_code == 422

    with pytest.raises(ProviderReloadValidationError) as exc2:
        asyncio.run(service.reload(actor_id=admin_user.id, idempotency_key="x" * 129, now=now))
    assert exc2.value.status_code == 422


def test_reload_success_flow(db_session, admin_user) -> None:
    initial_status = ProviderStatus(
        state="online",
        version="v1",
        provider="mock",
        capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
    )
    new_status = ProviderStatus(
        state="online",
        version="v2",
        provider="mock",
        capabilities={"sm2": True, "sm3": True, "sm4_gcm": True, "ml_kem_768": True},
    )
    engine = MockCryptoEngine(status=initial_status)
    engine.set_result("reload_pqc_provider", new_status)
    engine.set_result("sm3_digest", b"\x55" * 32)
    lock = ProviderOperationLock()
    service = ProviderReloadService(engine=engine, session_factory=lambda: db_session, lock=lock)
    now = datetime.now(timezone.utc)
    key = "valid-idempotency-key-01"

    result = asyncio.run(service.reload(actor_id=admin_user.id, idempotency_key=key, now=now))

    assert result.api == "ok"
    assert result.engine == "online"
    assert result.providers["ml_kem_768"] is True

    # Verify idempotency record
    record = (
        db_session.query(ProviderReloadIdempotency)
        .filter_by(actor_id=admin_user.id)
        .first()
    )
    assert record is not None
    assert record.outcome == "success"
    assert "ml_kem_768" in record.response_json

    # Verify audit log
    audit = (
        db_session.query(AuditLog)
        .filter_by(actor=admin_user.id, action="provider.reload")
        .first()
    )
    assert audit is not None
    assert audit.target == "provider:pqc"
    assert len(audit.detail_hash) == 32


def test_reload_idempotency_returns_cached_without_re_executing(db_session, admin_user) -> None:
    status = ProviderStatus(
        state="online",
        version="v1",
        provider="mock",
        capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
    )
    engine = MockCryptoEngine(status=status)
    engine.set_result("sm3_digest", b"\x66" * 32)
    lock = ProviderOperationLock()
    service = ProviderReloadService(engine=engine, session_factory=lambda: db_session, lock=lock)
    now = datetime.now(timezone.utc)
    key = "valid-idempotency-key-02"

    first = asyncio.run(service.reload(actor_id=admin_user.id, idempotency_key=key, now=now))
    call_count_first = len([call for call in engine.calls if call[0] == "reload_pqc_provider"])
    assert call_count_first == 1

    second = asyncio.run(service.reload(actor_id=admin_user.id, idempotency_key=key, now=now))
    call_count_second = len([call for call in engine.calls if call[0] == "reload_pqc_provider"])
    assert call_count_second == 1  # Not re-executed!
    assert first == second


def test_reload_idempotency_conflict(db_session, admin_user) -> None:
    status = ProviderStatus(
        state="online",
        version="v1",
        provider="mock",
        capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
    )
    engine = MockCryptoEngine(status=status)
    engine.set_result("sm3_digest", b"\x77" * 32)
    lock = ProviderOperationLock()
    service = ProviderReloadService(engine=engine, session_factory=lambda: db_session, lock=lock)
    now = datetime.now(timezone.utc)
    key = "valid-idempotency-key-03"

    # Pre-insert idempotency record with a different request_hash
    record = ProviderReloadIdempotency(
        actor_id=admin_user.id,
        key_hash=b"\x77" * 32,
        request_hash=b"\x99" * 32,  # Conflicting request hash
        response_json='{"api":"ok","engine":"online","version":"1.0.0","tlcp":"unknown","providers":{}}',
        outcome="success",
    )
    db_session.add(record)
    db_session.commit()

    with pytest.raises(ProviderReloadConflictError) as exc:
        asyncio.run(service.reload(actor_id=admin_user.id, idempotency_key=key, now=now))
    assert exc.value.status_code == 409


def test_reload_fails_when_engine_raises_unavailable(db_session, admin_user) -> None:
    engine = MockCryptoEngine()
    engine.set_error("reload_pqc_provider", CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))
    engine.set_result("sm3_digest", b"\x88" * 32)
    lock = ProviderOperationLock()
    service = ProviderReloadService(engine=engine, session_factory=lambda: db_session, lock=lock)
    now = datetime.now(timezone.utc)
    key = "valid-idempotency-key-04"

    with pytest.raises(ProviderReloadUnavailableError) as exc:
        asyncio.run(service.reload(actor_id=admin_user.id, idempotency_key=key, now=now))
    assert exc.value.status_code == 503

    # Idempotency success must NOT be recorded on failure
    record = (
        db_session.query(ProviderReloadIdempotency)
        .filter_by(actor_id=admin_user.id, key_hash=b"\x88" * 32)
        .first()
    )
    assert record is None
