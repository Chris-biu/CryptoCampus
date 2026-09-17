from datetime import datetime, timezone
import hashlib
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.system import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.drop import Drop
from app.models.inspect import InspectRecord
from app.models.user import User
from app.models.vote import VoteRecord
from app.security.auth_dependencies import CurrentUser, get_current_user


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


@pytest.fixture
def db_env():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    crypto_engine = DeterministicMockCryptoEngine()

    session = session_factory()
    admin = User(id=str(uuid.uuid4()), email="admin@campus.edu", role="admin", status="active")
    teacher = User(id=str(uuid.uuid4()), email="teacher@campus.edu", role="teacher", status="active")
    student = User(id=str(uuid.uuid4()), email="student@campus.edu", role="student", status="active")
    target_student = User(id=str(uuid.uuid4()), email="target@campus.edu", role="student", status="active")
    session.add_all([admin, teacher, student, target_student])
    session.commit()

    app = create_app()

    def override_get_db():
        s = session_factory()
        try:
            yield s
        finally:
            s.close()

    def override_crypto_engine():
        return crypto_engine

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_crypto_engine] = override_crypto_engine

    return {
        "app": app,
        "session_factory": session_factory,
        "crypto_engine": crypto_engine,
        "admin": admin,
        "teacher": teacher,
        "student": student,
        "target_student": target_student,
    }


def _client_as(app, user: User | None) -> TestClient:
    client = TestClient(app)
    if user is not None:
        current = CurrentUser(
            user_id=user.id,
            role=user.role,
            status=user.status,
            session_id=str(uuid.uuid4()),
        )
        app.dependency_overrides[get_current_user] = lambda: current
    else:
        if get_current_user in app.dependency_overrides:
            del app.dependency_overrides[get_current_user]
    return client


def test_list_users_route(db_env):
    app = db_env["app"]
    # 401 unauth
    unauth_client = _client_as(app, None)
    res = unauth_client.get("/api/v1/admin/users")
    assert res.status_code == 401

    # 403 student
    student_client = _client_as(app, db_env["student"])
    res = student_client.get("/api/v1/admin/users")
    assert res.status_code == 403

    # 200 admin
    admin_client = _client_as(app, db_env["admin"])
    res = admin_client.get("/api/v1/admin/users")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 4


def test_update_user_role_route(db_env):
    app = db_env["app"]
    target_id = db_env["target_student"].id

    # 403 student
    student_client = _client_as(app, db_env["student"])
    res = student_client.patch(
        f"/api/v1/admin/users/{target_id}/role",
        json={"role": "teacher", "reason": "Promoted to teacher assistant"},
    )
    assert res.status_code == 403

    # 200 admin
    admin_client = _client_as(app, db_env["admin"])
    res = admin_client.patch(
        f"/api/v1/admin/users/{target_id}/role",
        json={"role": "teacher", "reason": "Promoted to teacher assistant"},
    )
    assert res.status_code == 200
    assert res.json()["role"] == "teacher"


def test_destroy_drop_route(db_env):
    app = db_env["app"]
    session = db_env["session_factory"]()
    code = "link123456789012"
    code_hash = db_env["crypto_engine"].sm3_digest(code.encode("utf-8"))
    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=db_env["admin"].id,
        recipient_user_id=db_env["student"].id,
        link_code_hash=code_hash,
        kind="text",
        ciphertext=b"encrypted",
        nonce=b"1" * 12,
        tag=b"2" * 16,
        enc_key_sm2=b"sm2",
        sender_cert_serial="serial",
        recipient_sm2_fingerprint=b"fp" * 16,
        access_code_hash=b"0" * 32,
        ttl_policy="hours_24",
        content_size=10,
        status="available",
    )
    session.add(drop)
    session.commit()
    session.close()

    # 403 student
    student_client = _client_as(app, db_env["student"])
    res = student_client.post(f"/api/v1/admin/drops/{code}/destroy")
    assert res.status_code == 403

    # 204 admin
    admin_client = _client_as(app, db_env["admin"])
    res = admin_client.post(f"/api/v1/admin/drops/{code}/destroy")
    assert res.status_code == 204


def test_flag_vote_for_audit_route(db_env):
    app = db_env["app"]
    session = db_env["session_factory"]()
    vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=db_env["admin"].id,
        title="Student Council Election",
        description="Vote",
        scope="public",
        closes_at=datetime.now(timezone.utc),
        status="open",
    )
    session.add(vote)
    session.commit()
    session.close()

    # 403 student
    student_client = _client_as(app, db_env["student"])
    res = student_client.post(
        f"/api/v1/admin/votes/{vote.id}/audit-flags",
        json={"reason": "Suspicious ballot concentration"},
    )
    assert res.status_code == 403

    # 201 admin
    admin_client = _client_as(app, db_env["admin"])
    res = admin_client.post(
        f"/api/v1/admin/votes/{vote.id}/audit-flags",
        json={"reason": "Suspicious ballot concentration"},
    )
    assert res.status_code == 201
    assert res.json()["accepted"] is True


def test_list_inspect_records_route(db_env):
    app = db_env["app"]
    session = db_env["session_factory"]()
    rec = InspectRecord(
        id=str(uuid.uuid4()),
        operation="sm4_encrypt",
        owner_user_id=db_env["student"].id,
        steps_json="[]",
        redacted_values_json="{}",
        created_at=datetime.now(timezone.utc),
    )
    session.add(rec)
    session.commit()
    session.close()

    # 403 student
    student_client = _client_as(app, db_env["student"])
    res = student_client.get("/api/v1/admin/inspect-records")
    assert res.status_code == 403

    # 200 admin
    admin_client = _client_as(app, db_env["admin"])
    res = admin_client.get("/api/v1/admin/inspect-records")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert len(data["items"]) >= 1
    assert "steps" not in data["items"][0]
    assert "redacted_values" not in data["items"][0]


def test_export_admin_audit_route(db_env):
    app = db_env["app"]

    # 403 student
    student_client = _client_as(app, db_env["student"])
    res = student_client.get("/api/v1/admin/audit/export?format=json")
    assert res.status_code == 403

    # 200 admin json
    admin_client = _client_as(app, db_env["admin"])
    res_json = admin_client.get("/api/v1/admin/audit/export?format=json")
    assert res_json.status_code == 200
    assert isinstance(res_json.json(), list)

    # 200 admin csv
    res_csv = admin_client.get("/api/v1/admin/audit/export?format=csv")
    assert res_csv.status_code == 200
    assert "actor_id,action,target,detail_hash,hash_prev,hash_curr,timestamp" in res_csv.text
