from __future__ import annotations

from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.benchmark import (
    BenchmarkIdempotency,
    BenchmarkJob,
    BenchmarkMetricEntity,
    compute_benchmark_request_hash,
)
from app.models.user import User


class FakeSm3Engine:
    def sm3_digest(self, message: bytes) -> bytes:
        import hashlib
        # Fake SM3 for model helper test
        return hashlib.sha256(b"fake_sm3:" + message).digest()


def _create_test_user(session: Session) -> User:
    user = User(
        id=str(uuid.uuid4()),
        email=f"admin_{uuid.uuid4().hex[:8]}@campus.edu",
        role="admin",
        status="active",
        failed_login_count=0,
        created_at=datetime.now(timezone.utc),
    )
    session.add(user)
    session.commit()
    return user


def test_benchmark_job_crud(db_session: Session) -> None:
    user = _create_test_user(db_session)
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    job = BenchmarkJob(
        id=job_id,
        actor_id=user.id,
        iterations=100,
        include_pqc=True,
        status="queued",
        engine_version="openHiTLS-1.0",
        provider_snapshot_json="{}",
        error_code=None,
        created_at=now,
    )
    db_session.add(job)
    db_session.commit()

    saved = db_session.scalar(select(BenchmarkJob).where(BenchmarkJob.id == job_id))
    assert saved is not None
    assert saved.actor_id == user.id
    assert saved.iterations == 100
    assert saved.include_pqc is True
    assert saved.status == "queued"


def test_benchmark_job_iterations_constraint(db_session: Session) -> None:
    user = _create_test_user(db_session)
    now = datetime.now(timezone.utc)

    # < 10 must fail
    with pytest.raises(IntegrityError):
        job_too_few = BenchmarkJob(
            id=str(uuid.uuid4()),
            actor_id=user.id,
            iterations=9,
            include_pqc=True,
            status="queued",
            created_at=now,
        )
        db_session.add(job_too_few)
        db_session.commit()
    db_session.rollback()

    # > 10000 must fail
    with pytest.raises(IntegrityError):
        job_too_many = BenchmarkJob(
            id=str(uuid.uuid4()),
            actor_id=user.id,
            iterations=10001,
            include_pqc=True,
            status="queued",
            created_at=now,
        )
        db_session.add(job_too_many)
        db_session.commit()
    db_session.rollback()


def test_benchmark_job_status_constraint(db_session: Session) -> None:
    user = _create_test_user(db_session)
    now = datetime.now(timezone.utc)

    with pytest.raises(IntegrityError):
        invalid_status_job = BenchmarkJob(
            id=str(uuid.uuid4()),
            actor_id=user.id,
            iterations=10,
            include_pqc=False,
            status="unknown_status",
            created_at=now,
        )
        db_session.add(invalid_status_job)
        db_session.commit()
    db_session.rollback()


def test_benchmark_metric_entity_unique_constraint(db_session: Session) -> None:
    user = _create_test_user(db_session)
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    job = BenchmarkJob(
        id=job_id,
        actor_id=user.id,
        iterations=50,
        include_pqc=True,
        status="completed",
        created_at=now,
    )
    db_session.add(job)
    db_session.commit()

    m1 = BenchmarkMetricEntity(
        job_id=job_id,
        operation="signature.sm2.sign",
        sample_count=50,
        mean_ns=1500000,
        p99_ns=2000000,
        pqc_overhead_basis_points=None,
    )
    db_session.add(m1)
    db_session.commit()

    # Duplicate (job_id, operation) must fail
    m2 = BenchmarkMetricEntity(
        job_id=job_id,
        operation="signature.sm2.sign",
        sample_count=50,
        mean_ns=1600000,
        p99_ns=2100000,
        pqc_overhead_basis_points=None,
    )
    db_session.add(m2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_benchmark_idempotency_unique_constraint(db_session: Session) -> None:
    user = _create_test_user(db_session)
    job_id1 = str(uuid.uuid4())
    job_id2 = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    j1 = BenchmarkJob(id=job_id1, actor_id=user.id, iterations=10, include_pqc=False, status="queued", created_at=now)
    j2 = BenchmarkJob(id=job_id2, actor_id=user.id, iterations=10, include_pqc=False, status="queued", created_at=now)
    db_session.add_all([j1, j2])
    db_session.commit()

    key_hash = b"\x01" * 32
    req_hash = b"\x02" * 32

    idemp1 = BenchmarkIdempotency(
        id=str(uuid.uuid4()),
        actor_id=user.id,
        key_hash=key_hash,
        request_hash=req_hash,
        job_id=job_id1,
        created_at=now,
    )
    db_session.add(idemp1)
    db_session.commit()

    # Same (actor_id, key_hash) must fail
    idemp2 = BenchmarkIdempotency(
        id=str(uuid.uuid4()),
        actor_id=user.id,
        key_hash=key_hash,
        request_hash=req_hash,
        job_id=job_id2,
        created_at=now,
    )
    db_session.add(idemp2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_compute_benchmark_request_hash() -> None:
    engine = FakeSm3Engine()
    actor_id = "test-actor-uuid"
    h1 = compute_benchmark_request_hash(engine, actor_id, 100, True)
    h2 = compute_benchmark_request_hash(engine, actor_id, 100, True)
    h3 = compute_benchmark_request_hash(engine, actor_id, 100, False)
    h4 = compute_benchmark_request_hash(engine, actor_id, 200, True)

    assert len(h1) == 32
    assert h1 == h2
    assert h1 != h3
    assert h1 != h4
