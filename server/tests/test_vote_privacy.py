import base64
from datetime import datetime, timedelta, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.dependencies import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit import AuditLog
from app.models.user import User
from app.models.vote import VoteCredentialIssue, VoteOption, VoteRecord
from app.security.auth_dependencies import CurrentUser, require_authenticated_user
from app.services.vote_signer import VoteSignerMaterialProvider, get_vote_signer_provider


class MockVoteSignerMaterialProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x66" * SM2_PRIVATE_KEY_SIZE)

    def get_signer_private_key(self, *, vote_id: str) -> bytes | None:
        return self.key

    def get_signer_public_key(self, *, vote_id: str) -> bytes | None:
        return b"\x88" * 64


class DynamicMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            seed = f"hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


def _create_sqlite_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


@pytest.fixture
def privacy_env():
    session = _create_sqlite_session()
    creator = User(
        id=str(uuid.uuid4()),
        email="privacy_creator@campus.edu.cn",
        role="teacher",
        status="active",
    )
    student = User(
        id=str(uuid.uuid4()),
        email="privacy_student@campus.edu.cn",
        role="student",
        status="active",
    )
    session.add_all([creator, student])

    now = datetime.now(timezone.utc)
    vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator.id,
        title="隐私边界测试投票",
        scope="public",
        closes_at=now + timedelta(days=5),
        status="open",
        created_at=now,
    )
    opt1 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="选项A", position=0)
    opt2 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="选项B", position=1)
    session.add_all([vote, opt1, opt2])
    session.commit()

    crypto = DynamicMockCryptoEngine()
    crypto.set_result("blind_sign", b"\x33" * 64)
    signer_provider = MockVoteSignerMaterialProvider()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_vote_signer_provider] = lambda: signer_provider
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=student.id,
        role=student.role,
        status=student.status,
    )

    client = TestClient(app)
    return {
        "client": client,
        "session": session,
        "vote": vote,
        "student": student,
        "creator": creator,
    }


def test_issue_credential_rejects_forbidden_fields_with_422(privacy_env):
    client = privacy_env["client"]
    vote = privacy_env["vote"]
    blinded_b64 = base64.b64encode(b"blinded-msg").decode("ascii")

    forbidden_payloads = [
        {"service": "vote_ballot", "period": vote.id, "blinded_message": blinded_b64, "user_id": "malicious_user"},
        {"service": "vote_ballot", "period": vote.id, "blinded_message": blinded_b64, "sn": "11223344556677889900aabbccddeeff"},
        {"service": "vote_ballot", "period": vote.id, "blinded_message": blinded_b64, "option_id": str(uuid.uuid4())},
        {"service": "vote_ballot", "period": vote.id, "blinded_message": blinded_b64, "blinding_factor": "secret_factor"},
        {"service": "vote_ballot", "period": vote.id, "blinded_message": blinded_b64, "unblinded_credential": "fake_cred"},
    ]

    for payload in forbidden_payloads:
        res = client.post(
            f"/api/v1/votes/{vote.id}/credentials",
            headers={"Idempotency-Key": "idemp-privacy-forbid-0001"},
            json=payload,
        )
        assert res.status_code == 422, f"Failed on payload keys: {payload.keys()}"


def test_issue_credential_response_leaks_no_metadata_or_identity(privacy_env):
    client = privacy_env["client"]
    vote = privacy_env["vote"]
    blinded_b64 = base64.b64encode(b"blinded-msg-strict").decode("ascii")

    res = client.post(
        f"/api/v1/votes/{vote.id}/credentials",
        headers={"Idempotency-Key": "idemp-privacy-strict-res-01"},
        json={"service": "vote_ballot", "period": vote.id, "blinded_message": blinded_b64},
    )
    assert res.status_code == 201
    data = res.json()
    assert set(data.keys()) == {"blind_signature", "algorithm"}
    assert data["algorithm"] == "SM2-BLIND-PROTOCOL-V1"
    assert "user_id" not in data
    assert "vote_id" not in data
    assert "sn" not in data
    assert "has_voted" not in data
    assert "quota" not in data


def test_public_endpoints_leak_no_creator_or_voter_identities(privacy_env):
    client = privacy_env["client"]
    vote = privacy_env["vote"]

    # 1. GET /votes
    res_list = client.get("/api/v1/votes")
    assert res_list.status_code == 200
    list_items = res_list.json()["items"]
    assert len(list_items) >= 1
    for item in list_items:
        assert set(item.keys()) == {"id", "title", "options", "scope", "status", "closes_at"}
        assert "creator_id" not in item
        assert "key_hash" not in item
        assert "request_hash" not in item

    # 2. GET /votes/{id}
    res_detail = client.get(f"/api/v1/votes/{vote.id}")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert set(detail.keys()) == {"id", "title", "options", "scope", "status", "closes_at"}
    assert "creator_id" not in detail
    assert "key_hash" not in detail
    assert "request_hash" not in detail


def test_audit_logs_record_no_plaintext_secrets_or_blinded_messages(privacy_env):
    client = privacy_env["client"]
    session = privacy_env["session"]
    vote = privacy_env["vote"]
    student = privacy_env["student"]

    raw_blinded = b"very-sensitive-blinded-secret-message"
    blinded_b64 = base64.b64encode(raw_blinded).decode("ascii")

    res = client.post(
        f"/api/v1/votes/{vote.id}/credentials",
        headers={"Idempotency-Key": "idemp-privacy-audit-check-1"},
        json={"service": "vote_ballot", "period": vote.id, "blinded_message": blinded_b64},
    )
    assert res.status_code == 201

    # Check AuditLog
    audits = session.query(AuditLog).filter_by(action="vote.credential.issue").all()
    assert len(audits) == 1
    audit = audits[0]
    assert audit.actor == student.id
    assert audit.target == f"vote:{vote.id}"
    assert len(audit.detail_hash) == 32  # SM3 digest only
    # Raw blinded message string or bytes must NOT appear in audit log
    assert raw_blinded not in audit.detail_hash
    assert blinded_b64.encode("ascii") not in audit.detail_hash

    # Check VoteCredentialIssue table
    issues = session.query(VoteCredentialIssue).filter_by(user_id=student.id, vote_id=vote.id).all()
    assert len(issues) == 1
    issue = issues[0]
    # Verify request_hash and key_hash are 32-byte digests
    assert len(issue.request_hash) == 32
    assert len(issue.key_hash) == 32
    # Verify no unblinded credential or SN fields exist in schema/columns
    assert not hasattr(issue, "sn")
    assert not hasattr(issue, "option_id")
    assert not hasattr(issue, "blinding_factor")
