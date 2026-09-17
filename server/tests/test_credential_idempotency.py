import base64
from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy.orm import sessionmaker

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.db.session import create_db_engine, init_database
from app.models.credential import CredentialIssueIdempotency, CredentialLedger
from app.models.user import User
from app.services.credential_issuance import (
    CredentialIssuanceError,
    CredentialIssuanceService,
)


class MockServerSignerKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x66" * SM2_PRIVATE_KEY_SIZE)

    def get_signer_private_key(self, service: str) -> bytes | None:
        return self.key


class DynamicMockCryptoEngine(MockCryptoEngine):
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


def _setup_idempotency_env():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    crypto_engine = DynamicMockCryptoEngine()
    crypto_engine.set_result("blind_sign", b"\x99" * 64)

    signer_key_provider = MockServerSignerKeyProvider()
    service = CredentialIssuanceService(
        session=session,
        crypto_engine=crypto_engine,
        signer_key_provider=signer_key_provider,
    )

    now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    today_period = "2026-09-09"

    user = User(
        id=str(uuid.uuid4()),
        email="idemp_student@campus.edu.cn",
        role="student",
        status="active",
    )
    session.add(user)
    session.commit()

    return session, crypto_engine, signer_key_provider, service, user, now, today_period


def test_same_key_same_request_replay_returns_same_signature_without_deducting_quota():
    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_idempotency_env()

    blinded_b64 = base64.b64encode(b"blinded-msg-replay-test").decode("ascii")
    idemp_key = "idemp-key-replay-001"

    # First issuance
    res1 = service.issue(
        user_id=user.id,
        service="hole_post",
        period=today_period,
        blinded_message_b64=blinded_b64,
        idempotency_key=idemp_key,
        now=now,
    )
    assert res1.blind_signature == b"\x99" * 64
    assert res1.algorithm == "SM2-BLIND-PROTOCOL-V1"

    ledger1 = session.query(CredentialLedger).filter_by(
        user_id=user.id,
        service="hole_credential",
        period=today_period,
    ).one()
    assert ledger1.issued_count == 1

    calls_after_first = [c for c in crypto_engine.calls if c[0] == "blind_sign"]
    assert len(calls_after_first) == 1

    # Second issuance (replay with identical key and identical request)
    res2 = service.issue(
        user_id=user.id,
        service="hole_post",
        period=today_period,
        blinded_message_b64=blinded_b64,
        idempotency_key=idemp_key,
        now=now,
    )

    # Must return exact same signature and algorithm
    assert res2.blind_signature == res1.blind_signature
    assert res2.blind_signature_b64 == res1.blind_signature_b64
    assert res2.algorithm == res1.algorithm

    # Quota must NOT be deducted again
    ledger2 = session.query(CredentialLedger).filter_by(
        user_id=user.id,
        service="hole_credential",
        period=today_period,
    ).one()
    assert ledger2.issued_count == 1

    # CryptoEngine blind_sign must NOT be called again
    calls_after_second = [c for c in crypto_engine.calls if c[0] == "blind_sign"]
    assert len(calls_after_second) == 1

    # Only one idempotency record exists
    idemp_count = session.query(CredentialIssueIdempotency).filter_by(
        user_id=user.id,
        service="hole_post",
        period=today_period,
    ).count()
    assert idemp_count == 1


def test_same_key_different_request_returns_conflict_409():
    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_idempotency_env()

    blinded_b64_a = base64.b64encode(b"blinded-msg-A").decode("ascii")
    blinded_b64_b = base64.b64encode(b"blinded-msg-B").decode("ascii")
    idemp_key = "idemp-key-conflict-001"

    # First issuance with msg A
    res_a = service.issue(
        user_id=user.id,
        service="hole_post",
        period=today_period,
        blinded_message_b64=blinded_b64_a,
        idempotency_key=idemp_key,
        now=now,
    )
    assert res_a.blind_signature == b"\x99" * 64

    # Second issuance with SAME key but DIFFERENT blinded message
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64=blinded_b64_b,
            idempotency_key=idemp_key,
            now=now,
        )
    assert exc_info.value.code == "idempotency_conflict"

    # Verify quota remains 1
    ledger = session.query(CredentialLedger).filter_by(
        user_id=user.id,
        service="hole_credential",
        period=today_period,
    ).one()
    assert ledger.issued_count == 1


def test_same_key_different_user_and_period_isolation():
    session, crypto_engine, signer_key_provider, service, user_a, now, today_period = _setup_idempotency_env()

    # Create second user
    user_b = User(
        id=str(uuid.uuid4()),
        email="idemp_student_b@campus.edu.cn",
        role="student",
        status="active",
    )
    session.add(user_b)
    session.commit()

    shared_idemp_key = "idemp-shared-key-001"
    blinded_b64 = base64.b64encode(b"blinded-msg-shared").decode("ascii")

    # User A issues with shared_idemp_key
    res_a = service.issue(
        user_id=user_a.id,
        service="hole_post",
        period=today_period,
        blinded_message_b64=blinded_b64,
        idempotency_key=shared_idemp_key,
        now=now,
    )
    assert res_a.algorithm == "SM2-BLIND-PROTOCOL-V1"

    # User B issues with same shared_idemp_key -> Must succeed independently
    res_b = service.issue(
        user_id=user_b.id,
        service="hole_post",
        period=today_period,
        blinded_message_b64=blinded_b64,
        idempotency_key=shared_idemp_key,
        now=now,
    )
    assert res_b.algorithm == "SM2-BLIND-PROTOCOL-V1"

    # Both users have their own ledger count 1
    ledger_a = session.query(CredentialLedger).filter_by(
        user_id=user_a.id, service="hole_credential", period=today_period
    ).one()
    assert ledger_a.issued_count == 1

    ledger_b = session.query(CredentialLedger).filter_by(
        user_id=user_b.id, service="hole_credential", period=today_period
    ).one()
    assert ledger_b.issued_count == 1

    # Both idempotency records exist
    assert session.query(CredentialIssueIdempotency).count() == 2

    # Different period for user A with same key
    tomorrow = now + timedelta(days=1)
    tomorrow_period = tomorrow.date().isoformat()
    res_tomorrow = service.issue(
        user_id=user_a.id,
        service="hole_post",
        period=tomorrow_period,
        blinded_message_b64=blinded_b64,
        idempotency_key=shared_idemp_key,
        now=tomorrow,
    )
    assert res_tomorrow.algorithm == "SM2-BLIND-PROTOCOL-V1"

    ledger_tomorrow = session.query(CredentialLedger).filter_by(
        user_id=user_a.id, service="hole_credential", period=tomorrow_period
    ).one()
    assert ledger_tomorrow.issued_count == 1
