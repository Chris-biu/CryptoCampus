from datetime import datetime, timezone
import hashlib
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.admin import get_hole_content_governance_service
from app.crypto.dependencies import get_crypto_engine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit import AuditLog, RevocationLog
from app.models.hole import HolePost
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user
from app.services.hole_governance import HoleContentGovernanceService


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def __init__(self) -> None:
        super().__init__()
        self._error: CryptoBridgeError | None = None

    def set_error(self, error: CryptoBridgeError | None) -> None:
        self._error = error

    def sm3_digest(self, message: bytes) -> bytes:
        if self._error is not None:
            raise self._error
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


def _setup_test_env():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    admin_user = User(
        id=str(uuid.uuid4()),
        email="admin@campus.edu",
        role="admin",
        status="active",
    )
    teacher_user = User(
        id=str(uuid.uuid4()),
        email="teacher@campus.edu",
        role="teacher",
        status="active",
    )
    student_user = User(
        id=str(uuid.uuid4()),
        email="student@campus.edu",
        role="student",
        status="active",
    )

    with session_factory() as s:
        s.add_all([admin_user, teacher_user, student_user])
        s.commit()

    crypto_engine = DeterministicMockCryptoEngine()
    app = create_app()

    service = HoleContentGovernanceService(
        session_factory=session_factory,
        crypto_engine=crypto_engine,
    )

    app.dependency_overrides[get_crypto_engine] = lambda: crypto_engine
    app.dependency_overrides[get_hole_content_governance_service] = lambda: service

    def create_post(
        post_id: str | None = None,
        status: str = "published",
        sn: bytes = b"\x11" * 16,
        credential_service: str = "hole_post",
    ) -> HolePost:
        pid = post_id or str(uuid.uuid4())
        prefix = sn[:4].hex().lower() if len(sn) >= 4 else "00000000"
        post = HolePost(
            id=pid,
            content="Sensitive content to be withdrawn",
            credential_service=credential_service,
            credential_period="2026-09-10",
            credential_sn=sn,
            credential_signature=b"\x99" * 64,
            credential_prefix=prefix,
            credential_valid=True,
            status=status,
        )
        with session_factory() as s:
            s.add(post)
            s.commit()
        return post


    return {
        "app": app,
        "session_factory": session_factory,
        "crypto_engine": crypto_engine,
        "admin_user": admin_user,
        "teacher_user": teacher_user,
        "student_user": student_user,
        "create_post": create_post,
    }


def test_withdraw_hole_post_success_admin() -> None:
    env = _setup_test_env()
    app = env["app"]
    admin = env["admin_user"]
    post = env["create_post"](sn=b"\x12" * 16)

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=admin.id,
        role="admin",
        status="active",
    )
    client = TestClient(app)

    response = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": "违规不良言论"},
    )
    assert response.status_code == 200, response.text
    data = response.json()

    # Verify exactly the 5 allowed fields
    expected_keys = {"sn", "reason", "hash_prev", "hash_curr", "timestamp"}
    assert set(data.keys()) == expected_keys
    assert data["sn"] == (b"\x12" * 16).hex().lower()
    assert data["reason"] == "违规不良言论"
    assert isinstance(data["hash_prev"], str)
    assert isinstance(data["hash_curr"], str)
    assert isinstance(data["timestamp"], str)

    # Post-state check in DB
    with env["session_factory"]() as s:
        updated_post = s.get(HolePost, post.id)
        assert updated_post.status == "withdrawn"
        assert updated_post.credential_valid is False
        # Sensitive post content remains untouched
        assert updated_post.content == "Sensitive content to be withdrawn"

        # Check RevocationLog
        records = list(s.query(RevocationLog).all())
        assert len(records) == 1
        assert bytes(records[0].sn) == b"\x12" * 16
        assert records[0].reason == "违规不良言论"
        assert records[0].operator == admin.id

        # Check AuditLog
        audits = list(s.query(AuditLog).all())
        assert len(audits) == 1
        assert audits[0].actor == admin.id
        assert audits[0].action == "hole.post.withdraw"
        assert audits[0].target == f"hole_post:{post.id}"



def test_withdraw_hole_post_success_teacher() -> None:
    env = _setup_test_env()
    app = env["app"]
    teacher = env["teacher_user"]
    post = env["create_post"](sn=b"\x34" * 16)

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=teacher.id,
        role="teacher",
        status="active",
    )
    client = TestClient(app)

    response = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": "教师权限撤帖"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["reason"] == "教师权限撤帖"


def test_withdraw_hole_post_unauthorized_401() -> None:
    env = _setup_test_env()
    app = env["app"]
    post = env["create_post"]()
    # No auth override
    client = TestClient(app)

    response = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": "未登录撤帖"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


def test_withdraw_hole_post_forbidden_student_403() -> None:
    env = _setup_test_env()
    app = env["app"]
    student = env["student_user"]
    post = env["create_post"]()

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=student.id,
        role="student",
        status="active",
    )
    client = TestClient(app)

    response = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": "学生越权撤帖"},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "FORBIDDEN"


def test_withdraw_hole_post_not_found_404() -> None:
    env = _setup_test_env()
    app = env["app"]
    admin = env["admin_user"]
    missing_id = str(uuid.uuid4())

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=admin.id,
        role="admin",
        status="active",
    )
    client = TestClient(app)

    response = client.post(
        f"/api/v1/admin/hole/posts/{missing_id}/withdraw",
        json={"reason": "帖子不存在测试"},
    )
    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"


def test_withdraw_hole_post_validation_errors_422() -> None:
    env = _setup_test_env()
    app = env["app"]
    admin = env["admin_user"]
    post = env["create_post"]()

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=admin.id,
        role="admin",
        status="active",
    )
    client = TestClient(app)

    # 1. Invalid post_id (not a UUID)
    res_invalid_uuid = client.post(
        "/api/v1/admin/hole/posts/invalid-uuid-format/withdraw",
        json={"reason": "合法理由"},
    )
    assert res_invalid_uuid.status_code == 422
    assert res_invalid_uuid.json()["code"] == "VALIDATION_ERROR"

    # 2. Empty reason
    res_empty_reason = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": ""},
    )
    assert res_empty_reason.status_code == 422
    assert res_empty_reason.json()["code"] == "VALIDATION_ERROR"

    # 3. Whitespace-only reason
    res_ws_reason = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": "    "},
    )
    assert res_ws_reason.status_code == 422
    assert res_ws_reason.json()["code"] == "VALIDATION_ERROR"

    # 4. Reason too long (> 500 chars)
    res_long_reason = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": "r" * 501},
    )
    assert res_long_reason.status_code == 422
    assert res_long_reason.json()["code"] == "VALIDATION_ERROR"

    # 5. Extra fields in request body
    res_extra_fields = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={
            "reason": "正常理由",
            "operator_id": admin.id,
            "sn": "1234567890",
            "hash_curr": "bad",
        },
    )
    assert res_extra_fields.status_code == 422
    assert res_extra_fields.json()["code"] == "VALIDATION_ERROR"


def test_withdraw_hole_post_engine_unavailable_503() -> None:
    env = _setup_test_env()
    app = env["app"]
    admin = env["admin_user"]
    post = env["create_post"]()
    env["crypto_engine"].set_error(CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=admin.id,
        role="admin",
        status="active",
    )
    client = TestClient(app)

    response = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": "引擎故障测试"},
    )
    assert response.status_code == 503
    assert response.json()["code"] == "PROVIDER_UNAVAILABLE"


def test_withdraw_hole_post_integrity_error_500() -> None:
    env = _setup_test_env()
    app = env["app"]
    admin = env["admin_user"]
    # Corrupt credential_sn in post (e.g. too short)
    post = env["create_post"](sn=b"\x00" * 4)

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=admin.id,
        role="admin",
        status="active",
    )
    client = TestClient(app)

    response = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": "凭据SN不合法测试"},
    )
    assert response.status_code == 500
    assert response.json()["code"] == "INTERNAL_ERROR"


def test_withdraw_hole_post_idempotency_200() -> None:
    env = _setup_test_env()
    app = env["app"]
    admin = env["admin_user"]
    post = env["create_post"](sn=b"\x55" * 16)

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=admin.id,
        role="admin",
        status="active",
    )
    client = TestClient(app)

    # First withdrawal
    resp1 = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": "首次撤帖"},
    )
    assert resp1.status_code == 200
    data1 = resp1.json()

    # Second withdrawal (idempotent replay)
    resp2 = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": "再次撤帖"},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()

    # Must return same revocation entry
    assert data1["sn"] == data2["sn"]
    assert data1["hash_curr"] == data2["hash_curr"]
    assert data1["hash_prev"] == data2["hash_prev"]


def test_withdraw_hole_post_response_security_no_sensitive_leak() -> None:
    env = _setup_test_env()
    app = env["app"]
    admin = env["admin_user"]
    post = env["create_post"](sn=b"\x66" * 16)

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=admin.id,
        role="admin",
        status="active",
    )
    client = TestClient(app)

    response = client.post(
        f"/api/v1/admin/hole/posts/{post.id}/withdraw",
        json={"reason": "保密检查测试"},
    )
    assert response.status_code == 200
    raw_text = response.text
    data = response.json()

    # Strict check: keys must only be sn, reason, hash_prev, hash_curr, timestamp
    assert set(data.keys()) == {"sn", "reason", "hash_prev", "hash_curr", "timestamp"}

    # Must not contain operator, post_id, author_id, or content
    assert admin.id not in raw_text
    assert post.id not in raw_text
    assert "author" not in data
    assert "operator" not in data
    assert "post_id" not in data
    assert "content" not in data
