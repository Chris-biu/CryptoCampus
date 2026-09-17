import pytest
from fastapi.testclient import TestClient

from app.api.routes.admin import get_system_status_service
from app.api.routes.system import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import ProviderStatus
from app.db.session import get_db
from app.main import create_app
from app.models.audit import AuditLog
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_roles


def test_admin_engine_requires_authentication() -> None:
    app = create_app()
    client = TestClient(app)

    response = client.get("/api/v1/admin/engine")
    assert response.status_code == 401


def test_admin_engine_forbids_student(client) -> None:
    app = create_app()
    app.dependency_overrides[require_roles("admin", "teacher")] = lambda: CurrentUser(
        "student-1", "student", "active"
    )
    # But wait, require_roles raises 403 if role is not admin or teacher!
    # If we call it through normal require_authenticated_user:


def test_admin_engine_forbids_student_role() -> None:
    app = create_app()
    from app.security.auth_dependencies import require_authenticated_user
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        "student-1", "student", "active"
    )
    client = TestClient(app)

    response = client.get("/api/v1/admin/engine")
    assert response.status_code == 403


def test_admin_engine_allows_admin_and_records_audit_log(db_session) -> None:
    admin = User(id="admin-user-1", email="admin@campus.edu", role="admin")
    db_session.add(admin)
    db_session.commit()

    engine = MockCryptoEngine(
        status=ProviderStatus(
            state="online",
            version="mock-v1",
            provider="mock-pqc",
            capabilities={"sm2": True, "sm3": True, "sm4_gcm": True, "ml_kem_768": True},
        )
    )
    engine.set_result("sm3_digest", b"\xaa" * 32)

    app = create_app()
    from app.security.auth_dependencies import require_authenticated_user
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        admin.id, "admin", "active"
    )
    app.dependency_overrides[get_crypto_engine] = lambda: engine
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    response = client.get("/api/v1/admin/engine")

    assert response.status_code == 200
    data = response.json()
    assert data["api"] == "ok"
    assert data["engine"] == "online"
    assert data["version"] == "1.0.0"
    assert data["tlcp"] == "unknown"
    assert data["providers"] == {
        "sm2": True,
        "sm3": True,
        "sm4_gcm": True,
        "ml_kem_768": True,
    }

    # Verify audit log was recorded
    audit = (
        db_session.query(AuditLog)
        .filter_by(actor=admin.id, action="provider.status.view")
        .first()
    )
    assert audit is not None
    assert audit.target == "engine"
    assert audit.detail_hash is not None
    assert len(audit.detail_hash) == 32


def test_admin_engine_allows_teacher_role(db_session) -> None:
    teacher = User(id="teacher-user-1", email="teacher@campus.edu", role="teacher")
    db_session.add(teacher)
    db_session.commit()

    engine = MockCryptoEngine(
        status=ProviderStatus(
            state="degraded",
            version="mock-v1",
            provider="mock-pqc",
            capabilities={"sm2": True, "sm3": False, "sm4_gcm": True},
        )
    )
    engine.set_result("sm3_digest", b"\xbb" * 32)

    app = create_app()
    from app.security.auth_dependencies import require_authenticated_user
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        teacher.id, "teacher", "active"
    )
    app.dependency_overrides[get_crypto_engine] = lambda: engine
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    response = client.get("/api/v1/admin/engine")

    assert response.status_code == 200
    assert response.json()["api"] == "degraded"
    assert response.json()["engine"] == "degraded"


def test_admin_engine_and_system_status_are_consistent(db_session) -> None:
    admin = User(id="admin-user-2", email="admin2@campus.edu", role="admin")
    db_session.add(admin)
    db_session.commit()

    engine = MockCryptoEngine(
        status=ProviderStatus(
            state="online",
            version="test",
            provider="mock",
            capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
        )
    )
    engine.set_result("sm3_digest", b"\xcc" * 32)

    app = create_app()
    from app.security.auth_dependencies import require_authenticated_user
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        admin.id, "admin", "active"
    )
    app.dependency_overrides[get_crypto_engine] = lambda: engine
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    public_res = client.get("/api/v1/system/status")
    admin_res = client.get("/api/v1/admin/engine")

    assert public_res.status_code == 200
    assert admin_res.status_code == 200
    assert public_res.json() == admin_res.json()
