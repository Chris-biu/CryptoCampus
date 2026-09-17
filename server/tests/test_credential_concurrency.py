import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier
import uuid
import pytest

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.db.session import create_db_engine, create_session_factory, init_database
from app.models.audit import AuditLog
from app.models.credential import CredentialIssueIdempotency, CredentialLedger
from app.models.user import User
from app.services.credential_issuance import (
    CredentialIssuanceError,
    CredentialIssuanceService,
)


class MockServerSignerKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x55" * SM2_PRIVATE_KEY_SIZE)

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


def _create_test_user(session_factory) -> str:
    with session_factory() as session:
        user = User(
            id=str(uuid.uuid4()),
            email="concurrent_student@campus.edu.cn",
            role="student",
            status="active",
        )
        session.add(user)
        session.commit()
        return user.id


def test_concurrent_issuance_never_exceeds_daily_quota(tmp_path):
    db_file = tmp_path / "credential_concurrency.db"
    engine = create_db_engine(f"sqlite+pysqlite:///{db_file.as_posix()}")
    init_database(engine)
    session_factory = create_session_factory(engine)

    user_id = _create_test_user(session_factory)
    num_threads = 10
    barrier = Barrier(num_threads)
    now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    today_period = "2026-09-09"

    crypto_engine = DynamicMockCryptoEngine()
    crypto_engine.set_result("blind_sign", b"\xaa" * 64)
    signer_key_provider = MockServerSignerKeyProvider()

    def run_issuance(idx: int) -> str:
        with session_factory() as session:
            service = CredentialIssuanceService(
                session=session,
                crypto_engine=crypto_engine,
                signer_key_provider=signer_key_provider,
            )
            blinded_b64 = base64.b64encode(f"concurrent-msg-{idx}".encode("utf-8")).decode("ascii")
            idemp_key = f"idemp-key-conc-{idx:03d}-12345"
            barrier.wait()
            try:
                res = service.issue(
                    user_id=user_id,
                    service="hole_post",
                    period=today_period,
                    blinded_message_b64=blinded_b64,
                    idempotency_key=idemp_key,
                    now=now,
                )
                return "success"
            except CredentialIssuanceError as err:
                return err.code

    try:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            outcomes = list(executor.map(run_issuance, range(num_threads)))

        assert outcomes.count("success") == 5
        assert outcomes.count("quota_exhausted") == 5

        with session_factory() as session:
            ledger = session.query(CredentialLedger).filter_by(
                user_id=user_id,
                service="hole_credential",
                period=today_period,
            ).one()
            assert ledger.issued_count == 5

            idemp_records = session.query(CredentialIssueIdempotency).filter_by(
                user_id=user_id,
                service="hole_post",
                period=today_period,
            ).all()
            assert len(idemp_records) == 5

            audit_records = session.query(AuditLog).filter_by(
                actor=user_id,
                action="credential.issue",
            ).all()
            assert len(audit_records) == 5
    finally:
        engine.dispose()


def test_concurrent_identical_replay_returns_same_result_and_single_deduction(tmp_path):
    db_file = tmp_path / "credential_replay_concurrency.db"
    engine = create_db_engine(f"sqlite+pysqlite:///{db_file.as_posix()}")
    init_database(engine)
    session_factory = create_session_factory(engine)

    user_id = _create_test_user(session_factory)
    num_threads = 10
    barrier = Barrier(num_threads)
    now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    today_period = "2026-09-09"

    crypto_engine = DynamicMockCryptoEngine()
    crypto_engine.set_result("blind_sign", b"\xbb" * 64)
    signer_key_provider = MockServerSignerKeyProvider()

    shared_idemp_key = "idemp-key-replay-shared-12345"
    shared_blinded_b64 = base64.b64encode(b"shared-blinded-message").decode("ascii")

    def run_replay(idx: int) -> tuple[str, bytes]:
        with session_factory() as session:
            service = CredentialIssuanceService(
                session=session,
                crypto_engine=crypto_engine,
                signer_key_provider=signer_key_provider,
            )
            barrier.wait()
            try:
                res = service.issue(
                    user_id=user_id,
                    service="hole_post",
                    period=today_period,
                    blinded_message_b64=shared_blinded_b64,
                    idempotency_key=shared_idemp_key,
                    now=now,
                )
                return ("success", res.blind_signature)
            except CredentialIssuanceError as err:
                return (err.code, b"")

    try:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            outcomes = list(executor.map(run_replay, range(num_threads)))

        # All 10 concurrent requests must succeed and return the exact same blind signature
        statuses = [s for s, _ in outcomes]
        signatures = [sig for _, sig in outcomes]

        assert statuses == ["success"] * num_threads
        assert all(sig == b"\xbb" * 64 for sig in signatures)

        with session_factory() as session:
            ledger = session.query(CredentialLedger).filter_by(
                user_id=user_id,
                service="hole_credential",
                period=today_period,
            ).one()
            # Must only be deducted ONCE
            assert ledger.issued_count == 1

            idemp_records = session.query(CredentialIssueIdempotency).filter_by(
                user_id=user_id,
                service="hole_post",
                period=today_period,
            ).all()
            assert len(idemp_records) == 1
    finally:
        engine.dispose()
