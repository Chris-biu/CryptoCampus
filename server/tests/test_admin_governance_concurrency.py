from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import time
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.models.user import User
from app.services.admin_audit import AdminAuditChainService


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


@pytest.fixture
def thread_safe_db(tmp_path):
    db_file = tmp_path / "test_concurrency.db"
    engine = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"check_same_thread": False, "timeout": 30},
        poolclass=NullPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    crypto_engine = DeterministicMockCryptoEngine()

    session = session_factory()
    admin = User(id=str(uuid.uuid4()), email="admin@campus.edu", role="admin", status="active")
    session.add(admin)
    session.commit()
    session.close()

    return {
        "engine": engine,
        "session_factory": session_factory,
        "crypto_engine": crypto_engine,
        "admin_id": admin.id,
    }


def test_concurrent_audit_chain_append_prevents_forks_and_verifies(thread_safe_db):
    session_factory = thread_safe_db["session_factory"]
    crypto_engine = thread_safe_db["crypto_engine"]
    admin_id = thread_safe_db["admin_id"]
    service = AdminAuditChainService(crypto_engine)

    # Function executed by worker threads with bounded retries on conflict
    def worker_append(worker_id: int):
        max_retries = 20
        for attempt in range(max_retries):
            session: Session = session_factory()
            try:
                now = datetime.now(timezone.utc)
                service.append(
                    session=session,
                    actor_id=admin_id,
                    action=f"action.worker.{worker_id}",
                    target=f"target:{worker_id}",
                    detail_hash=crypto_engine.sm3_digest(f"detail:{worker_id}".encode("utf-8")),
                    timestamp=now,
                )
                session.commit()
                session.close()
                return True
            except (IntegrityError, OperationalError):
                session.rollback()
                session.close()
                time.sleep(0.02 * (attempt + 1))
            except Exception:
                session.rollback()
                session.close()
                raise
        return False

    num_workers = 4
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        results = list(executor.map(worker_append, range(num_workers)))

    assert all(results)

    # Verify that the entire chain has exactly num_workers entries with complete linear integrity
    verify_session = session_factory()
    ordered_entries = service.verify_chain(verify_session)
    assert len(ordered_entries) == num_workers

    # Check that no two entries have the same hash_prev or hash_curr
    prev_hashes = [e.hash_prev for e in ordered_entries]
    curr_hashes = [e.hash_curr for e in ordered_entries]
    assert len(set(prev_hashes)) == num_workers
    assert len(set(curr_hashes)) == num_workers
    verify_session.close()
