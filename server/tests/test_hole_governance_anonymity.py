import base64
from datetime import datetime, timezone
import hashlib
import logging
import re
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.admin import get_hole_content_governance_service
from app.crypto.dependencies import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE, SM2_SIGNATURE_SIZE
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit import AuditLog, RevocationLog
from app.models.credential import ConsumedSN, CredentialIssueIdempotency, CredentialLedger
from app.models.hole import HolePost, HolePostIdempotency
from app.models.user import User
from app.schemas.credential import CredentialProof
from app.schemas.hole import WITHDRAWN_CONTENT_PLACEHOLDER, HolePost as HolePostSchema
from app.security.auth_dependencies import CurrentUser, require_authenticated_user
from app.services.credential_verification import CredentialVerificationService
from app.services.hole_governance import HoleContentGovernanceService
from app.services.hole_posts import HolePostService
from app.services.signer_provider import (
    ServerSignerVerificationKeyProvider,
    get_signer_verification_key_provider,
)


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def __init__(self) -> None:
        super().__init__()
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(b"mock-sm3:" + message).digest()

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


class MockVerificationKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x04" + b"\x33" * (SM2_PUBLIC_KEY_SIZE - 1))

    def get_signer_public_key(self, service: str) -> bytes | None:
        return self.key


@pytest.fixture
def env():
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
    student_user = User(
        id=str(uuid.uuid4()),
        email="student@campus.edu",
        role="student",
        status="active",
    )

    with session_factory() as s:
        s.add_all([admin_user, student_user])
        s.commit()

    crypto_engine = DeterministicMockCryptoEngine()
    crypto_engine.set_result("blind_verify", True)
    key_provider = MockVerificationKeyProvider()

    governance_service = HoleContentGovernanceService(
        session_factory=session_factory,
        crypto_engine=crypto_engine,
    )

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session_factory()
    app.dependency_overrides[get_crypto_engine] = lambda: crypto_engine
    app.dependency_overrides[get_signer_verification_key_provider] = lambda: key_provider
    app.dependency_overrides[get_hole_content_governance_service] = lambda: governance_service
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=admin_user.id,
        role="admin",
        status="active",
    )

    client = TestClient(app)

    return {
        "engine": engine,
        "session_factory": session_factory,
        "crypto_engine": crypto_engine,
        "key_provider": key_provider,
        "admin_user": admin_user,
        "student_user": student_user,
        "governance_service": governance_service,
        "app": app,
        "client": client,
    }


def _create_and_publish_post(env, content="Original sensitive hole content"):
    client = env["client"]
    today_utc = datetime.now(timezone.utc).date().isoformat()
    sn_bytes = uuid.uuid4().bytes
    sn_hex = sn_bytes.hex().lower()
    sig_b64 = base64.b64encode(b"\x88" * SM2_SIGNATURE_SIZE).decode("ascii")

    proof = {
        "sn": sn_hex,
        "service": "hole_post",
        "period": today_utc,
        "signature": sig_b64,
    }
    idemp_key = f"idemp-key-{uuid.uuid4().hex}"
    resp = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": idemp_key},
        json={"content": content, "credential": proof},
    )
    assert resp.status_code == 201, resp.text
    return resp.json(), proof, idemp_key


def test_1_list_posts_placeholder_and_physical_content_retained(env):
    """测试 1（列表占位与物理正文保留）:
    - 创建 published 帖子并撤下，验证 GET /hole/posts 返回固定占位且 credential_valid=False。
    - 用独立的数据库 Session 直查数据库表 hole_posts，断言 post.content == original_content（证明未被物理擦除）。
    """
    client = env["client"]
    session_factory = env["session_factory"]

    original_content = "This is a confidential post that will be withdrawn"
    post_data, proof, idemp_key = _create_and_publish_post(env, content=original_content)
    post_id = post_data["id"]

    # Withdraw the post via admin route
    withdraw_resp = client.post(
        f"/api/v1/admin/hole/posts/{post_id}/withdraw",
        json={"reason": "含有违规敏感言论"},
    )
    assert withdraw_resp.status_code == 200, withdraw_resp.text

    # Verify GET /api/v1/hole/posts
    list_resp = client.get("/api/v1/hole/posts")
    assert list_resp.status_code == 200
    posts = list_resp.json()["items"]
    withdrawn_post = next((p for p in posts if p["id"] == post_id), None)
    assert withdrawn_post is not None
    assert withdrawn_post["content"] == WITHDRAWN_CONTENT_PLACEHOLDER
    assert withdrawn_post["content"] == "【内容已由管理员撤下（违规）】"
    assert withdrawn_post["credential_valid"] is False
    assert withdrawn_post["status"] == "withdrawn"
    assert withdrawn_post["credential_prefix"] == proof["sn"][:8]

    # Verify physical retention in database with independent Session
    independent_session: Session = session_factory()
    try:
        db_post = independent_session.get(HolePost, post_id)
        assert db_post is not None
        assert db_post.status == "withdrawn"
        assert db_post.credential_valid is False
        assert db_post.content == original_content, "Original content must be physically retained in the database!"
    finally:
        independent_session.close()

    # Verify idempotent publish replay returns placeholder
    replay_resp = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": idemp_key},
        json={"content": original_content, "credential": proof},
    )
    assert replay_resp.status_code == 201
    replay_data = replay_resp.json()
    assert replay_data["id"] == post_id
    assert replay_data["content"] == WITHDRAWN_CONTENT_PLACEHOLDER
    assert replay_data["credential_valid"] is False
    assert replay_data["status"] == "withdrawn"


def test_2_credential_verification_three_states_independence(env):
    """测试 2（凭据验证三状态独立性）:
    - 验证撤帖前后凭据验证接口对 valid, consumed, revoked 的正确返回值。
    """
    client = env["client"]
    today_utc = datetime.now(timezone.utc).date().isoformat()
    sn_hex = uuid.uuid4().bytes.hex().lower()
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")

    proof = {
        "sn": sn_hex,
        "service": "hole_post",
        "period": today_utc,
        "signature": sig_b64,
    }

    # State 1: Before publishing (valid, unconsumed, unrevoked)
    verify_resp1 = client.post("/api/v1/hole/credentials/verify", json=proof)
    assert verify_resp1.status_code == 200
    data1 = verify_resp1.json()
    assert data1["valid"] is True
    assert data1["consumed"] is False
    assert data1["revoked"] is False

    # State 2: After publishing (valid, consumed, unrevoked)
    pub_resp = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": f"idemp-key-{uuid.uuid4().hex}"},
        json={"content": "Post for verification state test", "credential": proof},
    )
    assert pub_resp.status_code == 201
    post_id = pub_resp.json()["id"]

    verify_resp2 = client.post("/api/v1/hole/credentials/verify", json=proof)
    assert verify_resp2.status_code == 200
    data2 = verify_resp2.json()
    assert data2["valid"] is True
    assert data2["consumed"] is True
    assert data2["revoked"] is False

    # State 3: After withdrawal (valid, consumed, revoked)
    withdraw_resp = client.post(
        f"/api/v1/admin/hole/posts/{post_id}/withdraw",
        json={"reason": "凭据联动测试撤帖"},
    )
    assert withdraw_resp.status_code == 200

    verify_resp3 = client.post("/api/v1/hole/credentials/verify", json=proof)
    assert verify_resp3.status_code == 200
    data3 = verify_resp3.json()
    assert data3["valid"] is True, "Blind signature cryptographic validity remains True"
    assert data3["consumed"] is True, "Consumed status remains True"
    assert data3["revoked"] is True, "Revoked status becomes True because SN is in RevocationLog"

    # State 4: Tampered signature with consumed & revoked SN
    tampered_proof = dict(proof)
    tampered_proof["signature"] = base64.b64encode(b"\x00" * SM2_SIGNATURE_SIZE).decode("ascii")
    env["crypto_engine"].set_result("blind_verify", False)
    verify_resp4 = client.post("/api/v1/hole/credentials/verify", json=tampered_proof)
    assert verify_resp4.status_code == 200
    data4 = verify_resp4.json()
    assert data4["valid"] is False
    assert data4["consumed"] is True
    assert data4["revoked"] is True


def test_3_credential_issuance_ledger_isolation(env):
    """测试 3（签发账本隔离）:
    - 撤帖前后，核验数据库中 ConsumedSN、CredentialLedger、CredentialIssueIdempotency 的记录数及内容完全一致，
      未被撤帖操作触碰或更改。
    """
    client = env["client"]
    session_factory = env["session_factory"]
    student = env["student_user"]

    # Pre-populate CredentialLedger and CredentialIssueIdempotency
    with session_factory() as s:
        ledger = CredentialLedger(
            user_id=student.id,
            service="hole_post",
            period="2026-09-10",
            issued_count=3,
        )
        issue_idemp = CredentialIssueIdempotency(
            user_id=student.id,
            service="hole_post",
            period="2026-09-10",
            key_hash=b"\x11" * 32,
            request_hash=b"\x22" * 32,
            blind_signature=b"\x33" * 64,
        )
        s.add_all([ledger, issue_idemp])
        s.commit()

    # Publish a post
    post_data, proof, _ = _create_and_publish_post(env, content="Post before ledger isolation test")
    post_id = post_data["id"]

    # Take snapshot before withdrawal
    def take_db_snapshot():
        with session_factory() as s:
            consumed = [(r.sn, r.service, r.consumed_at) for r in s.query(ConsumedSN).order_by(ConsumedSN.sn).all()]
            ledgers = [(r.id, r.user_id, r.service, r.period, r.issued_count) for r in s.query(CredentialLedger).order_by(CredentialLedger.id).all()]
            issue_idemps = [(r.id, r.user_id, r.service, r.period, r.key_hash, r.request_hash, r.blind_signature) for r in s.query(CredentialIssueIdempotency).order_by(CredentialIssueIdempotency.id).all()]
            return consumed, ledgers, issue_idemps

    consumed_before, ledgers_before, idemps_before = take_db_snapshot()
    assert len(consumed_before) == 1
    assert len(ledgers_before) == 1
    assert len(idemps_before) == 1

    # Perform withdrawal
    withdraw_resp = client.post(
        f"/api/v1/admin/hole/posts/{post_id}/withdraw",
        json={"reason": "隔离验证撤帖"},
    )
    assert withdraw_resp.status_code == 200

    # Take snapshot after withdrawal
    consumed_after, ledgers_after, idemps_after = take_db_snapshot()

    # Assert exact equality: no modifications, insertions, or deletions to these tables
    assert consumed_before == consumed_after, "ConsumedSN must not be altered by withdrawal"
    assert ledgers_before == ledgers_after, "CredentialLedger must not be altered by withdrawal"
    assert idemps_before == idemps_after, "CredentialIssueIdempotency must not be altered by withdrawal"


def test_4_governance_sql_level_anonymity_isolation(env):
    """测试 4（SQL 级别匿名隔离检测）:
    - 使用 SQLAlchemy event.listens_for(engine, "before_cursor_execute") 监听治理服务执行期间的所有 SQL。
    - 严禁出现涉及 credential_ledger、credential_issue_idempotency、sessions、user_sessions 或网络 IP 的查询语句。
    """
    engine = env["engine"]
    client = env["client"]

    post_data, _, _ = _create_and_publish_post(env, content="Post for SQL audit test")
    post_id = post_data["id"]

    captured_sqls: list[str] = []

    def before_cursor_execute_listener(conn, cursor, statement, parameters, context, executemany):
        captured_sqls.append(statement)

    event.listen(engine, "before_cursor_execute", before_cursor_execute_listener)
    try:
        withdraw_resp = client.post(
            f"/api/v1/admin/hole/posts/{post_id}/withdraw",
            json={"reason": "SQL审计匿名检测撤帖"},
        )
        assert withdraw_resp.status_code == 200
    finally:
        event.remove(engine, "before_cursor_execute", before_cursor_execute_listener)

    # Must have executed SQLs during withdrawal
    assert len(captured_sqls) > 0, "Expected SQL statements during withdrawal"

    forbidden_tables = [
        "credential_ledger",
        "credential_issue_idempotency",
        "user_sessions",
        "sessions",
    ]

    for sql in captured_sqls:
        sql_lower = sql.lower()
        for forbidden in forbidden_tables:
            assert forbidden not in sql_lower, f"Forbidden table '{forbidden}' accessed during withdrawal SQL: {sql}"

        # Network IP or client IP detection
        assert "client_ip" not in sql_lower
        assert "user_ip" not in sql_lower
        assert "network_ip" not in sql_lower
        # Check standalone word 'ip'
        assert re.search(r"\bip\b", sql_lower) is None, f"Forbidden network IP column accessed in SQL: {sql}"


def test_5_sensitive_log_isolation_zero_leak(env, caplog):
    """测试 5（敏感日志隔离检测）:
    - 设置 Python logging 捕获 handler，在日志中搜索是否含有帖子原始正文、完整 SN（hex）、凭据签名、
      撤销 reason 明文、JWT Token 等敏感信息，断言全部未出现在日志中（只允许出现脱敏信息或契约公开响应）。
    """
    client = env["client"]

    sensitive_content = "SuperSecretPlainTextConfidentialPost-998877"
    raw_sn = uuid.uuid4().bytes
    full_sn_hex = raw_sn.hex().lower()
    raw_sig = b"\x7a" * SM2_SIGNATURE_SIZE
    b64_sig = base64.b64encode(raw_sig).decode("ascii")
    confidential_reason = "ConfidentialInternalReason-12345678"
    fake_jwt_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload.signature999"

    today_utc = datetime.now(timezone.utc).date().isoformat()
    proof = {
        "sn": full_sn_hex,
        "service": "hole_post",
        "period": today_utc,
        "signature": b64_sig,
    }

    # Custom log handler as well to test explicitly
    class MemoryLogHandler(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(self.format(record))

    memory_handler = MemoryLogHandler()
    root_logger = logging.getLogger()
    root_logger.addHandler(memory_handler)

    try:
        with caplog.at_level(logging.DEBUG):
            # 1. Publish post
            pub_resp = client.post(
                "/api/v1/hole/posts",
                headers={"Idempotency-Key": f"idemp-key-{uuid.uuid4().hex}"},
                json={"content": sensitive_content, "credential": proof},
            )
            assert pub_resp.status_code == 201
            post_id = pub_resp.json()["id"]

            # 2. Withdraw post with authorization header and confidential reason
            withdraw_resp = client.post(
                f"/api/v1/admin/hole/posts/{post_id}/withdraw",
                headers={"Authorization": fake_jwt_token},
                json={"reason": confidential_reason},
            )
            assert withdraw_resp.status_code == 200

            # 3. List posts
            list_resp = client.get("/api/v1/hole/posts")
            assert list_resp.status_code == 200
    finally:
        root_logger.removeHandler(memory_handler)

    all_logs = caplog.text + "\n" + "\n".join(memory_handler.records)

    # Assert ZERO sensitive data leaked into logging:
    assert sensitive_content not in all_logs, "Original post content must not leak into logs"
    assert full_sn_hex not in all_logs, "Full SN hex must not leak into logs"
    assert b64_sig not in all_logs, "Signature must not leak into logs"
    assert raw_sig.hex() not in all_logs, "Raw signature must not leak into logs"
    assert confidential_reason not in all_logs, "Confidential reason text must not leak into logs"
    assert fake_jwt_token not in all_logs, "JWT auth token must not leak into logs"
