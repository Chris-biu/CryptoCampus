from __future__ import annotations

from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.benchmarks.executor import BenchmarkExecutor
from app.crypto.types import ProviderStatus
from app.models.benchmark import BenchmarkJob
from app.models.user import User
from app.services.benchmarks import BenchmarkService, BenchmarkServiceError


class ServiceMockCrypto:
    def __init__(self, online: bool = True, pqc: bool = True):
        self.online = online
        self.pqc = pqc

    def sm3_digest(self, data: bytes) -> bytes:
        import hashlib
        return hashlib.sha256(b"mock_sm3:" + data).digest()

    def provider_status(self) -> ProviderStatus:
        return ProviderStatus(
            state="online" if self.online else "offline",
            version="mock-1.0",
            provider="mock-provider",
            capabilities={"sm2": True, "sm4_gcm": True, "hybrid_envelope": self.pqc},
        )


def _make_user(session: Session, role: str = "admin") -> User:
    user = User(
        id=str(uuid.uuid4()),
        email=f"user_{uuid.uuid4().hex[:8]}@campus.edu",
        role=role,
        status="active",
        failed_login_count=0,
        created_at=datetime.now(timezone.utc),
    )
    session.add(user)
    session.commit()
    return user


def test_service_create_job_offline_engine(db_session: Session, db_engine) -> None:
    user = _make_user(db_session)
    session_factory = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    crypto = ServiceMockCrypto(online=False)
    executor = BenchmarkExecutor(session_factory=session_factory, crypto_engine=crypto)
    service = BenchmarkService(db_session, crypto_engine=crypto, executor=executor)

    with pytest.raises(BenchmarkServiceError) as exc_info:
        service.create_job(
            actor_id=user.id,
            iterations=10,
            include_pqc=False,
            idempotency_key="key-1",
            now=datetime.now(timezone.utc),
        )
    assert exc_info.value.status_code == 503
    assert exc_info.value.code == "ENGINE_UNAVAILABLE"


def test_service_create_job_missing_pqc_capability(db_session: Session, db_engine) -> None:
    user = _make_user(db_session)
    session_factory = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    crypto = ServiceMockCrypto(online=True, pqc=False)
    executor = BenchmarkExecutor(session_factory=session_factory, crypto_engine=crypto)
    service = BenchmarkService(db_session, crypto_engine=crypto, executor=executor)

    with pytest.raises(BenchmarkServiceError) as exc_info:
        service.create_job(
            actor_id=user.id,
            iterations=10,
            include_pqc=True,  # requires PQC
            idempotency_key="key-pqc",
            now=datetime.now(timezone.utc),
        )
    assert exc_info.value.status_code == 503
    assert exc_info.value.code == "PQC_UNAVAILABLE"


def test_service_create_job_idempotency_and_conflict(db_session: Session, db_engine) -> None:
    user = _make_user(db_session)
    session_factory = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    crypto = ServiceMockCrypto(online=True, pqc=True)
    executor = BenchmarkExecutor(session_factory=session_factory, crypto_engine=crypto)
    service = BenchmarkService(db_session, crypto_engine=crypto, executor=executor)
    now = datetime.now(timezone.utc)

    # 1. Create job
    job1 = service.create_job(
        actor_id=user.id,
        iterations=50,
        include_pqc=True,
        idempotency_key="idemp-key-123",
        now=now,
    )
    assert job1.status == "queued"

    # 2. Replay with identical parameters -> returns original job (same ID)
    job2 = service.create_job(
        actor_id=user.id,
        iterations=50,
        include_pqc=True,
        idempotency_key="idemp-key-123",
        now=now,
    )
    assert job2.id == job1.id

    # 3. Same key with different parameters -> 409 Conflict
    with pytest.raises(BenchmarkServiceError) as exc_info:
        service.create_job(
            actor_id=user.id,
            iterations=100,  # changed iterations!
            include_pqc=True,
            idempotency_key="idemp-key-123",
            now=now,
        )
    assert exc_info.value.status_code == 409
    assert exc_info.value.code == "CONFLICT"


def test_service_get_job_and_export_status(db_session: Session, db_engine) -> None:
    user = _make_user(db_session)
    session_factory = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    crypto = ServiceMockCrypto(online=True, pqc=True)
    executor = BenchmarkExecutor(session_factory=session_factory, crypto_engine=crypto)
    service = BenchmarkService(db_session, crypto_engine=crypto, executor=executor)
    now = datetime.now(timezone.utc)

    job = service.create_job(
        actor_id=user.id,
        iterations=10,
        include_pqc=False,
        idempotency_key="export-key-1",
        now=now,
    )

    # 1. Get job when still queued -> metrics is empty
    result = service.get_job(job.id)
    assert result.id == job.id
    assert result.status == "queued"
    assert result.metrics == []

    # 2. Export when not completed -> 409 Conflict
    with pytest.raises(BenchmarkServiceError) as exc_info:
        service.export_job(job.id, "json")
    assert exc_info.value.status_code == 409
    assert exc_info.value.code == "CONFLICT"

    # 3. Non-existent job -> 404 NotFound
    with pytest.raises(BenchmarkServiceError) as exc_info404:
        service.get_job(str(uuid.uuid4()))
    assert exc_info404.value.status_code == 404
