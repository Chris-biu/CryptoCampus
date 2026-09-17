import asyncio
from datetime import datetime, timezone
import pytest

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import ProviderStatus
from app.models.provider_reload import ProviderReloadIdempotency
from app.models.user import User
from app.services.provider_reload import (
    ProviderOperationLock,
    ProviderReloadService,
    ProviderReloadTimeoutError,
)


@pytest.fixture
def admin_user(db_session):
    user = User(id="admin-conc-1", email="admin_conc@campus.edu", role="admin")
    db_session.add(user)
    db_session.commit()
    return user


def test_concurrent_identical_keys_execute_reload_only_once(db_session, admin_user) -> None:
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
    engine.set_result("sm3_digest", b"\x33" * 32)
    lock = ProviderOperationLock(timeout=2.0)
    service = ProviderReloadService(engine=engine, session_factory=lambda: db_session, lock=lock)
    now = datetime.now(timezone.utc)
    key = "concurrent-idempotency-key-01"

    async def run_concurrent():
        res1, res2 = await asyncio.gather(
            service.reload(actor_id=admin_user.id, idempotency_key=key, now=now),
            service.reload(actor_id=admin_user.id, idempotency_key=key, now=now),
        )
        return res1, res2

    res1, res2 = asyncio.run(run_concurrent())
    assert res1 == res2
    assert res1.api == "ok"
    assert res1.engine == "online"

    # Only one call to reload_pqc_provider should have occurred
    reload_calls = [call for call in engine.calls if call[0] == "reload_pqc_provider"]
    assert len(reload_calls) == 1


def test_lock_timeout_raises_provider_unavailable(db_session, admin_user) -> None:
    engine = MockCryptoEngine()
    engine.set_result("sm3_digest", b"\x44" * 32)
    lock = ProviderOperationLock(timeout=0.05)
    service = ProviderReloadService(engine=engine, session_factory=lambda: db_session, lock=lock)
    now = datetime.now(timezone.utc)

    async def run_timeout():
        # Acquire lock in advance and hold it
        await lock.acquire()
        try:
            await service.reload(
                actor_id=admin_user.id,
                idempotency_key="timeout-test-key-001",
                now=now,
            )
        finally:
            lock.release()

    with pytest.raises(ProviderReloadTimeoutError) as exc:
        asyncio.run(run_timeout())
    assert exc.value.status_code == 503
