import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import threading
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE, SM2_SIGNATURE_SIZE
from app.db.base import Base
from app.models.credential import ConsumedSN
from app.models.hole import HolePost, HolePostIdempotency
from app.schemas.credential import CredentialProof
from app.services.hole_posts import HolePostService, HolePostServiceError


class ThreadSafeMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0
        self._lock = threading.Lock()

    def sm3_digest(self, message: bytes) -> bytes:
        with self._lock:
            if message not in self._digests:
                self._counter += 1
                seed = f"hash-{self._counter:08d}-".encode("ascii")
                self._digests[message] = (seed + message)[:32].ljust(32, b"x")
            return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


class MockVerificationKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x04" + b"\x33" * (SM2_PUBLIC_KEY_SIZE - 1))

    def get_signer_public_key(self, service: str) -> bytes | None:
        return self.key


def test_concurrent_publish_same_sn_at_most_one_succeeds():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_file = Path(tmp_dir) / "concurrency_test.db"
        db_url = f"sqlite:///{db_file}"

        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False, "timeout": 30.0},
        )
        with engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            conn.exec_driver_sql("PRAGMA busy_timeout=30000")

        Base.metadata.create_all(engine)
        session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

        crypto_engine = ThreadSafeMockCryptoEngine()
        crypto_engine.set_result("blind_verify", True)
        key_provider = MockVerificationKeyProvider()

        sn_hex = "00112233445566778899aabbccddeeff"
        sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
        now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)

        num_threads = 10
        successes = []
        failures = []

        def attempt_publish(thread_idx: int):
            session = session_factory()
            try:
                service = HolePostService(
                    session=session,
                    crypto_engine=crypto_engine,
                    signer_verification_key_provider=key_provider,
                )
                proof = CredentialProof(
                    sn=sn_hex,
                    service="hole_post",
                    period="2026-09-09",
                    signature=sig_b64,
                )
                post = service.publish(
                    content=f"Concurrent post from thread {thread_idx}",
                    credential=proof,
                    idempotency_key=f"concurrent-idemp-key-{thread_idx:04d}",
                    now=now,
                )
                return ("success", post.id)
            except Exception as err:
                return ("failure", type(err).__name__, str(err))
            finally:
                session.close()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(attempt_publish, i) for i in range(num_threads)]
            for future in as_completed(futures):
                res = future.result()
                if res[0] == "success":
                    successes.append(res)
                else:
                    failures.append(res)

        # Exactly 1 request succeeds, all other 9 requests fail
        assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}: {successes}"
        assert len(failures) == num_threads - 1

        # Verify final database state
        verify_session = session_factory()
        try:
            assert verify_session.query(ConsumedSN).count() == 1
            assert verify_session.query(HolePost).count() == 1
            assert verify_session.query(HolePostIdempotency).count() == 1

            single_post = verify_session.query(HolePost).first()
            assert single_post is not None
            assert single_post.credential_prefix == "00112233"
            assert single_post.status == "published"
        finally:
            verify_session.close()
            engine.dispose()
