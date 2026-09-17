from __future__ import annotations

import json
from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.benchmarks.executor import BenchmarkExecutor, QueueFullError
from app.benchmarks.runner import BenchmarkMetricResult
from app.models.benchmark import BenchmarkJob, BenchmarkMetricEntity
from app.models.user import User


class FakeBenchmarkRunner:
    def __init__(self, should_fail: bool = False, error_msg: str = "engine_fail"):
        self.should_fail = should_fail
        self.error_msg = error_msg
        self.executed_jobs: list[str] = []

    def run(self, *, iterations: int, include_pqc: bool, clock_ns=None):
        if self.should_fail:
            from app.benchmarks.statistics import BenchmarkError
            raise BenchmarkError(self.error_msg)
        return [
            BenchmarkMetricResult(
                operation="signature.sm2.sign",
                sample_count=iterations,
                mean_ns=1000000.0,
                p99_ns=1500000,
                mean_ms=1.0,
                p99_ms=1.5,
                pqc_overhead_percent=None,
            )
        ]


class DummyEngine:
    def sm3_digest(self, message: bytes) -> bytes:
        return b"\xaa" * 32

    def provider_status(self):
        from app.crypto.types import ProviderStatus
        return ProviderStatus(state="online", version="1.0", provider="test", capabilities={})


def _create_user(session: Session) -> User:
    user = User(
        id=str(uuid.uuid4()),
        email=f"tester_{uuid.uuid4().hex[:8]}@campus.edu",
        role="admin",
        status="active",
        failed_login_count=0,
        created_at=datetime.now(timezone.utc),
    )
    session.add(user)
    session.commit()
    return user


def test_executor_processes_job_successfully(db_engine, db_session: Session) -> None:
    user = _create_user(db_session)
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    job = BenchmarkJob(
        id=job_id,
        actor_id=user.id,
        iterations=10,
        include_pqc=False,
        status="queued",
        engine_version="test-1.0",
        provider_snapshot_json="{}",
        created_at=now,
    )
    db_session.add(job)
    db_session.commit()

    runner = FakeBenchmarkRunner(should_fail=False)
    session_factory = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    executor = BenchmarkExecutor(
        session_factory=session_factory,
        runner_factory=lambda: runner,
        crypto_engine=DummyEngine(),
        max_queue_size=2,
    )

    # Process job synchronously
    executor.process_job_sync(job_id)

    db_session.expire_all()
    updated = db_session.scalar(select(BenchmarkJob).where(BenchmarkJob.id == job_id))
    assert updated is not None
    assert updated.status == "completed"
    assert updated.started_at is not None
    assert updated.finished_at is not None
    assert updated.error_code is None

    metrics = db_session.scalars(select(BenchmarkMetricEntity).where(BenchmarkMetricEntity.job_id == job_id)).all()
    assert len(metrics) == 1
    assert metrics[0].operation == "signature.sm2.sign"
    assert metrics[0].sample_count == 10
    assert metrics[0].mean_ns == 1000000


def test_executor_handles_runner_failure(db_engine, db_session: Session) -> None:
    user = _create_user(db_session)
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    job = BenchmarkJob(
        id=job_id,
        actor_id=user.id,
        iterations=10,
        include_pqc=False,
        status="queued",
        created_at=now,
    )
    db_session.add(job)
    db_session.commit()

    runner = FakeBenchmarkRunner(should_fail=True, error_msg="engine_unavailable")
    session_factory = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    executor = BenchmarkExecutor(session_factory=session_factory, runner_factory=lambda: runner, max_queue_size=2)

    executor.process_job_sync(job_id)

    db_session.expire_all()
    updated = db_session.scalar(select(BenchmarkJob).where(BenchmarkJob.id == job_id))
    assert updated is not None
    assert updated.status == "failed"
    assert updated.error_code == "ENGINE_UNAVAILABLE"

    metrics = db_session.scalars(select(BenchmarkMetricEntity).where(BenchmarkMetricEntity.job_id == job_id)).all()
    assert len(metrics) == 0


def test_executor_bounded_queue_limit(db_engine, db_session: Session) -> None:
    session_factory = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    executor = BenchmarkExecutor(session_factory=session_factory, runner_factory=lambda: FakeBenchmarkRunner(), max_queue_size=2)

    assert executor.enqueue("job-1") is True
    assert executor.enqueue("job-2") is True
    # 3rd enqueue exceeds capacity 2
    with pytest.raises(QueueFullError):
        executor.enqueue("job-3")


def test_executor_recover_interrupted_jobs(db_session: Session) -> None:
    user = _create_user(db_session)
    now = datetime.now(timezone.utc)

    # A job stuck in 'running' before crash
    stuck_job = BenchmarkJob(
        id=str(uuid.uuid4()),
        actor_id=user.id,
        iterations=100,
        include_pqc=False,
        status="running",
        created_at=now,
        started_at=now,
    )
    db_session.add(stuck_job)
    db_session.commit()

    from app.benchmarks.executor import recover_interrupted_jobs
    recovered_count = recover_interrupted_jobs(db_session)

    assert recovered_count == 1
    db_session.expire_all()
    stuck = db_session.scalar(select(BenchmarkJob).where(BenchmarkJob.id == stuck_job.id))
    assert stuck.status == "failed"
    assert stuck.error_code == "INTERRUPTED"
    assert stuck.finished_at is not None
