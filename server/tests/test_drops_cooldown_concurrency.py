from datetime import datetime, timedelta, timezone
import os
import tempfile
import threading
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.errors import DropServiceError
from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.models.drop import Drop
from app.models.user import User
from app.services.extract_cooldown import SqlAlchemyExtractCooldownGuard

VALID_NONCE = b"\x01" * 12
VALID_TAG = b"\x02" * 16
VALID_SM2_ENC = b"\x03" * 96
VALID_SIG = b"\x05" * 64
VALID_CERT = b"\x30\x82\x01\x00" + b"\x06" * 100


class CooldownConcurrencyMockCrypto(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            seed = f"hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


@pytest.fixture
def concurrency_db_env():
    # Use a file-based SQLite database with a busy timeout so multiple threads get their own connections
    db_file = os.path.join(tempfile.gettempdir(), f"cooldown_concurrency_{uuid.uuid4().hex}.db")
    engine = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"check_same_thread": False, "timeout": 30.0},
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    SessionMaker = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    crypto = CooldownConcurrencyMockCrypto()
    now = datetime.now(timezone.utc)

    # Initialize sender and recipient
    with SessionMaker() as session:
        sender = User(
            id=str(uuid.uuid4()),
            email="sender@campus.edu.cn",
            role="student",
            status="active",
            created_at=now,
        )
        recipient = User(
            id=str(uuid.uuid4()),
            email="recipient@campus.edu.cn",
            role="student",
            status="active",
            created_at=now,
        )
        session.add_all([sender, recipient])
        session.commit()
        sender_id = sender.id
        recipient_id = recipient.id

    yield {
        "engine": engine,
        "SessionMaker": SessionMaker,
        "crypto": crypto,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "now": now,
    }

    engine.dispose()
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except OSError:
            pass


def _create_concurrency_drop(SessionMaker, crypto, sender_id, recipient_id, now) -> str:
    code = f"Code-{uuid.uuid4().hex[:8]}"
    access_code = f"ACCESS-{uuid.uuid4().hex[:8]}"
    drop_id = str(uuid.uuid4())
    with SessionMaker() as session:
        drop = Drop(
            id=drop_id,
            owner_user_id=sender_id,
            recipient_user_id=recipient_id,
            link_code_hash=crypto.sm3_digest(code.encode("utf-8")),
            kind="text",
            envelope_version=1,
            ciphertext=b"encrypted payload",
            nonce=VALID_NONCE,
            tag=VALID_TAG,
            enc_key_sm2=VALID_SM2_ENC,
            enc_key_mlkem=None,
            sender_signature=VALID_SIG,
            sender_certificate_der=VALID_CERT,
            sender_cert_serial="SENDER-CERT-001",
            recipient_sm2_fingerprint=b"\x33" * 32,
            recipient_mlkem_fingerprint=None,
            access_code_hash=crypto.sm3_digest(access_code.encode("utf-8")),
            access_factor_salt=None,
            ttl_policy="hours_24",
            burn_after_read=False,
            expires_at=now + timedelta(hours=24),
            filename=None,
            content_size=20,
            pqc_mode=False,
            status="available",
            failed_attempts=0,
            cooldown_until=None,
            created_at=now,
        )
        session.add(drop)
        session.commit()
    return drop_id


def _norm(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def test_ten_concurrent_failed_attempts_transition_exactly_once(concurrency_db_env):
    """
    Test 10 concurrent wrong access code attempts on the same available drop.
    Assert:
    1. All 10 operations complete without exceptions.
    2. Final failed_attempts is strictly 5 (never exceeds 5).
    3. Final status is 'cooling_down'.
    4. cooldown_until is set to ~10 minutes in the future.
    """
    SessionMaker = concurrency_db_env["SessionMaker"]
    crypto = concurrency_db_env["crypto"]
    sender_id = concurrency_db_env["sender_id"]
    recipient_id = concurrency_db_env["recipient_id"]
    now = concurrency_db_env["now"]

    drop_id = _create_concurrency_drop(SessionMaker, crypto, sender_id, recipient_id, now)

    barrier = threading.Barrier(10)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait()
            with SessionMaker() as session:
                guard = SqlAlchemyExtractCooldownGuard(session)
                res = guard.record_failure(drop_id, now)
                results.append(res)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Unexpected worker exceptions: {errors}"
    assert len(results) == 10
    # Every returned attempt count must be between 1 and 5
    assert all(1 <= r <= 5 for r in results)

    # Check database final state
    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        assert drop.status == "cooling_down"
        assert drop.failed_attempts == 5
        assert drop.cooldown_until is not None
        assert _norm(drop.cooldown_until) == now + timedelta(minutes=10)


def test_cooldown_boundary_one_second_before_rejects(concurrency_db_env):
    """
    Test cooldown boundary: exactly 1 second before expiry, request is still rejected.
    """
    SessionMaker = concurrency_db_env["SessionMaker"]
    crypto = concurrency_db_env["crypto"]
    sender_id = concurrency_db_env["sender_id"]
    recipient_id = concurrency_db_env["recipient_id"]
    now = concurrency_db_env["now"]

    drop_id = _create_concurrency_drop(SessionMaker, crypto, sender_id, recipient_id, now)
    cooldown_expiry = now + timedelta(minutes=10)

    # Set drop to cooling_down
    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        drop.status = "cooling_down"
        drop.failed_attempts = 5
        drop.cooldown_until = cooldown_expiry
        session.commit()

    # Query 1 second before expiry
    one_second_before = cooldown_expiry - timedelta(seconds=1)
    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        guard = SqlAlchemyExtractCooldownGuard(session)
        with pytest.raises(DropServiceError) as exc_info:
            guard.before_attempt(drop, one_second_before)
        assert exc_info.value.code == "cooling_down"
        assert exc_info.value.message == "密信不存在或链接已失效"

    # Ensure drop remains cooling_down
    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        assert drop.status == "cooling_down"
        assert drop.failed_attempts == 5
        assert _norm(drop.cooldown_until) == cooldown_expiry


def test_cooldown_boundary_at_and_after_expiry_recovers_once(concurrency_db_env):
    """
    Test cooldown boundary:
    1. At the exact expiry moment (now == cooldown_until), the drop recovers to available and resets count.
    2. Immediately subsequent attempts see it already available without repeated recovery mutations.
    """
    SessionMaker = concurrency_db_env["SessionMaker"]
    crypto = concurrency_db_env["crypto"]
    sender_id = concurrency_db_env["sender_id"]
    recipient_id = concurrency_db_env["recipient_id"]
    now = concurrency_db_env["now"]

    drop_id = _create_concurrency_drop(SessionMaker, crypto, sender_id, recipient_id, now)
    cooldown_expiry = now + timedelta(minutes=10)

    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        drop.status = "cooling_down"
        drop.failed_attempts = 5
        drop.cooldown_until = cooldown_expiry
        session.commit()

    # Exactly at expiry
    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        guard = SqlAlchemyExtractCooldownGuard(session)
        # Should not raise
        guard.before_attempt(drop, cooldown_expiry)

    # Check drop is now available and count is 0
    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        assert drop.status == "available"
        assert drop.failed_attempts == 0
        assert drop.cooldown_until is None

    # Subsequent attempt 1 second after expiry
    one_sec_after = cooldown_expiry + timedelta(seconds=1)
    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        guard = SqlAlchemyExtractCooldownGuard(session)
        # Should not raise
        guard.before_attempt(drop, one_sec_after)
        assert drop.status == "available"
        assert drop.failed_attempts == 0


def test_concurrent_before_attempt_at_cooldown_expiry(concurrency_db_env):
    """
    Test 10 concurrent requests at the exact moment of cooldown expiry.
    Assert all requests are allowed (no exception raised), drop status is 'available', and count is 0.
    """
    SessionMaker = concurrency_db_env["SessionMaker"]
    crypto = concurrency_db_env["crypto"]
    sender_id = concurrency_db_env["sender_id"]
    recipient_id = concurrency_db_env["recipient_id"]
    now = concurrency_db_env["now"]

    drop_id = _create_concurrency_drop(SessionMaker, crypto, sender_id, recipient_id, now)
    cooldown_expiry = now + timedelta(minutes=10)

    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        drop.status = "cooling_down"
        drop.failed_attempts = 5
        drop.cooldown_until = cooldown_expiry
        session.commit()

    barrier = threading.Barrier(10)
    success_count = 0
    errors = []
    lock = threading.Lock()

    def worker():
        nonlocal success_count
        try:
            barrier.wait()
            with SessionMaker() as session:
                drop = session.get(Drop, drop_id)
                guard = SqlAlchemyExtractCooldownGuard(session)
                guard.before_attempt(drop, cooldown_expiry)
                with lock:
                    success_count += 1
        except Exception as e:
            with lock:
                errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Unexpected worker exceptions: {errors}"
    assert success_count == 10

    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        assert drop.status == "available"
        assert drop.failed_attempts == 0
        assert drop.cooldown_until is None


def test_ten_concurrent_api_extract_wrong_code_reaches_cooldown(concurrency_db_env):
    """
    Test 10 concurrent API requests to /api/v1/drops/{code}/extract with wrong access code.
    Assert:
    1. All 10 requests receive HTTP 404 NOT_FOUND.
    2. Final drop status in DB is 'cooling_down'.
    3. Final failed_attempts is strictly 5 (never exceeds 5).
    """
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.db.session import get_db
    from app.crypto.dependencies import get_crypto_engine
    from app.api.routes.drops import get_recipient_private_key_provider
    from app.services.recipient_provider import MockRecipientPrivateKeyProvider

    SessionMaker = concurrency_db_env["SessionMaker"]
    crypto = concurrency_db_env["crypto"]
    sender_id = concurrency_db_env["sender_id"]
    recipient_id = concurrency_db_env["recipient_id"]
    now = concurrency_db_env["now"]

    code = f"ApiConcCode{uuid.uuid4().hex[:8]}"
    access_code = "SECRET-CODE-API"
    drop_id = str(uuid.uuid4())

    with SessionMaker() as session:
        drop = Drop(
            id=drop_id,
            owner_user_id=sender_id,
            recipient_user_id=recipient_id,
            link_code_hash=crypto.sm3_digest(code.encode("utf-8")),
            kind="text",
            envelope_version=1,
            ciphertext=b"encrypted payload",
            nonce=VALID_NONCE,
            tag=VALID_TAG,
            enc_key_sm2=VALID_SM2_ENC,
            enc_key_mlkem=None,
            sender_signature=VALID_SIG,
            sender_certificate_der=VALID_CERT,
            sender_cert_serial="SENDER-CERT-001",
            recipient_sm2_fingerprint=b"\x33" * 32,
            recipient_mlkem_fingerprint=None,
            access_code_hash=crypto.sm3_digest(access_code.encode("utf-8")),
            access_factor_salt=None,
            ttl_policy="hours_24",
            burn_after_read=False,
            expires_at=now + timedelta(hours=24),
            filename=None,
            content_size=20,
            pqc_mode=False,
            status="available",
            failed_attempts=0,
            cooldown_until=None,
            created_at=now,
        )
        session.add(drop)
        session.commit()

    key_provider = MockRecipientPrivateKeyProvider()
    app = create_app()

    def _get_db_override():
        db = SessionMaker()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _get_db_override
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_recipient_private_key_provider] = lambda: key_provider

    barrier = threading.Barrier(10)
    status_codes = []
    responses = []
    lock = threading.Lock()

    def worker():
        client = TestClient(app)
        try:
            barrier.wait()
            resp = client.post(
                f"/api/v1/drops/{code}/extract",
                headers={"Idempotency-Key": f"IDEMP-{uuid.uuid4().hex}"},
                json={"access_code": "WRONG-CODE-9999"},
            )
            with lock:
                status_codes.append(resp.status_code)
                responses.append(resp.json())
        except Exception as e:
            with lock:
                responses.append({"error": str(e)})

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    app.dependency_overrides.clear()

    assert not any("error" in r for r in responses), f"Responses had errors: {responses}"
    assert len(status_codes) == 10, f"Status codes: {status_codes}, responses: {responses}"
    # Every request should receive 404 NOT_FOUND
    assert all(c == 404 for c in status_codes), f"Status codes: {status_codes}, responses: {responses}"
    for r in responses:
        assert r.get("code") == "NOT_FOUND"

    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        assert drop.status == "cooling_down"
        assert drop.failed_attempts == 5
        assert drop.cooldown_until is not None
