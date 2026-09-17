from __future__ import annotations

from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.models.benchmark import BenchmarkJob, BenchmarkMetricEntity
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user
from app.crypto.types import ProviderStatus


class RouteMockCrypto:
    def __init__(self, online: bool = True, pqc: bool = True):
        self.online = online
        self.pqc = pqc

    def sm3_digest(self, data: bytes) -> bytes:
        import hashlib
        return hashlib.sha256(b"route_sm3:" + data).digest()

    def provider_status(self) -> ProviderStatus:
        return ProviderStatus(
            state="online" if self.online else "offline",
            version="mock-1.0",
            provider="mock-provider",
            capabilities={"sm2": True, "sm4_gcm": True, "hybrid_envelope": self.pqc},
        )


def _seed_admin_user(session) -> User:
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


from app.db.session import get_db
from app.api.routes.system import get_crypto_engine


def test_benchmark_routes_auth_and_permissions(db_session) -> None:
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)

    # 1. No auth -> 401
    resp = client.post("/api/v1/admin/benchmarks", json={"iterations": 10}, headers={"Idempotency-Key": "k1"})
    assert resp.status_code == 401

    # 2. Student role -> 403
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(str(uuid.uuid4()), "student", "active")
    resp_student = client.post("/api/v1/admin/benchmarks", json={"iterations": 10}, headers={"Idempotency-Key": "k1"})
    assert resp_student.status_code == 403

    # 3. Student role on GET -> 403
    resp_get_student = client.get(f"/api/v1/admin/benchmarks/{uuid.uuid4()}")
    assert resp_get_student.status_code == 403


def test_post_benchmark_validation_and_creation(db_session) -> None:
    admin = _seed_admin_user(db_session)
    crypto = RouteMockCrypto(online=True, pqc=True)
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(admin.id, "admin", "active")
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto

    client = TestClient(app)

    # Missing Idempotency-Key header -> 422
    resp_missing_key = client.post("/api/v1/admin/benchmarks", json={"iterations": 10})
    assert resp_missing_key.status_code == 422

    # Iterations < 10 -> 422
    resp_low = client.post("/api/v1/admin/benchmarks", json={"iterations": 5}, headers={"Idempotency-Key": "k-low"})
    assert resp_low.status_code == 422

    # Iterations > 10000 -> 422
    resp_high = client.post("/api/v1/admin/benchmarks", json={"iterations": 10001}, headers={"Idempotency-Key": "k-high"})
    assert resp_high.status_code == 422

    # Successful creation -> 202
    resp_ok = client.post("/api/v1/admin/benchmarks", json={"iterations": 50, "include_pqc": True}, headers={"Idempotency-Key": "key-valid-1"})
    assert resp_ok.status_code == 202
    data = resp_ok.json()
    assert data["status"] == "queued"
    assert "id" in data
    job_id = data["id"]

    # Idempotent replay -> same job
    resp_replay = client.post("/api/v1/admin/benchmarks", json={"iterations": 50, "include_pqc": True}, headers={"Idempotency-Key": "key-valid-1"})
    assert resp_replay.status_code == 202
    assert resp_replay.json()["id"] == job_id

    # Conflict with same key, different params -> 409
    resp_conflict = client.post("/api/v1/admin/benchmarks", json={"iterations": 100, "include_pqc": True}, headers={"Idempotency-Key": "key-valid-1"})
    assert resp_conflict.status_code == 409

    # Query status -> 200
    resp_get = client.get(f"/api/v1/admin/benchmarks/{job_id}")
    assert resp_get.status_code == 200
    assert resp_get.json()["id"] == job_id


def test_post_benchmark_offline_engine(db_session) -> None:
    admin = _seed_admin_user(db_session)
    crypto = RouteMockCrypto(online=False, pqc=False)
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(admin.id, "admin", "active")
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto

    client = TestClient(app)
    resp = client.post("/api/v1/admin/benchmarks", json={"iterations": 10}, headers={"Idempotency-Key": "k-offline"})
    assert resp.status_code == 503


def test_get_benchmark_not_found(db_session) -> None:
    admin = _seed_admin_user(db_session)
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(admin.id, "admin", "active")
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    resp = client.get(f"/api/v1/admin/benchmarks/{uuid.uuid4()}")
    assert resp.status_code == 404
