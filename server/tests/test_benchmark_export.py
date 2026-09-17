from __future__ import annotations

from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.models.benchmark import BenchmarkJob, BenchmarkMetricEntity
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user
from app.api.routes.system import get_crypto_engine
from app.db.session import get_db


class ExportMockCrypto:
    def sm3_digest(self, data: bytes) -> bytes:
        import hashlib
        return hashlib.sha256(b"export_sm3:" + data).digest()


def _seed_completed_benchmark(session) -> tuple[User, str]:
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

    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    job = BenchmarkJob(
        id=job_id,
        actor_id=user.id,
        iterations=10,
        include_pqc=True,
        status="completed",
        engine_version="openHiTLS-1.0",
        provider_snapshot_json="{}",
        created_at=now,
        started_at=now,
        finished_at=now,
    )
    m1 = BenchmarkMetricEntity(
        job_id=job_id,
        operation="envelope.sm2.seal",
        sample_count=10,
        mean_ns=1234567,
        p99_ns=2345678,
        pqc_overhead_basis_points=None,
    )
    m2 = BenchmarkMetricEntity(
        job_id=job_id,
        operation="envelope.hybrid.seal",
        sample_count=10,
        mean_ns=3456789,
        p99_ns=4567890,
        pqc_overhead_basis_points=18012,  # 180.12%
    )
    session.add_all([job, m1, m2])
    session.commit()
    return user, job_id


def test_export_json_success(db_session) -> None:
    user, job_id = _seed_completed_benchmark(db_session)
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(user.id, "admin", "active")
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: ExportMockCrypto()

    client = TestClient(app)
    resp = client.get(f"/api/v1/admin/benchmarks/{job_id}/export?format=json")

    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    body = resp.json()
    assert body["id"] == job_id
    assert body["status"] == "completed"
    assert len(body["metrics"]) == 2
    assert body["metrics"][0]["operation"] == "envelope.sm2.seal"
    assert body["metrics"][0]["mean_ms"] == 1.234567
    assert body["metrics"][0]["p99_ms"] == 2.345678
    assert body["metrics"][0]["pqc_overhead_percent"] is None
    assert body["metrics"][1]["operation"] == "envelope.hybrid.seal"
    assert body["metrics"][1]["pqc_overhead_percent"] == 180.12


def test_export_csv_success(db_session) -> None:
    user, job_id = _seed_completed_benchmark(db_session)
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(user.id, "admin", "active")
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: ExportMockCrypto()

    client = TestClient(app)
    resp = client.get(f"/api/v1/admin/benchmarks/{job_id}/export?format=csv")

    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert f"benchmark-{job_id}.csv" in resp.headers["content-disposition"]

    csv_text = resp.text
    lines = csv_text.splitlines()
    assert lines[0] == "operation,mean_ms,p99_ms,pqc_overhead_percent"
    assert lines[1] == "envelope.sm2.seal,1.234567,2.345678,"
    assert lines[2] == "envelope.hybrid.seal,3.456789,4.567890,180.120000"


def test_export_uncompleted_job_returns_conflict(db_session) -> None:
    user = User(
        id=str(uuid.uuid4()),
        email="admin2@campus.edu",
        role="admin",
        status="active",
        failed_login_count=0,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    db_session.commit()

    job_id = str(uuid.uuid4())
    job = BenchmarkJob(
        id=job_id,
        actor_id=user.id,
        iterations=10,
        include_pqc=False,
        status="running",  # still running
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(job)
    db_session.commit()

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(user.id, "admin", "active")
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    resp = client.get(f"/api/v1/admin/benchmarks/{job_id}/export?format=json")
    assert resp.status_code == 409


def test_export_invalid_format(db_session) -> None:
    user, job_id = _seed_completed_benchmark(db_session)
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(user.id, "admin", "active")
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: ExportMockCrypto()

    client = TestClient(app)
    resp = client.get(f"/api/v1/admin/benchmarks/{job_id}/export?format=pdf")
    assert resp.status_code == 422
