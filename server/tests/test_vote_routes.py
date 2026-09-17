import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.dependencies import get_crypto_engine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE, SM2_PUBLIC_KEY_SIZE
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.models.vote import VoteOption, VoteRecord, VoteScopeMember, VoteScopeUnit
from app.security.auth_dependencies import CurrentUser, require_authenticated_user
from app.services.vote_signer import VoteSignerMaterialProvider, get_vote_signer_provider
from app.services.vote_tally_provider import (
    VoteTallyMaterial,
    VoteTallyMaterialProvider,
    get_vote_tally_provider,
)


class MockVoteSignerMaterialProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x66" * SM2_PRIVATE_KEY_SIZE)

    def get_signer_private_key(self, *, vote_id: str) -> bytes | None:
        return self.key

    def get_signer_public_key(self, *, vote_id: str) -> bytes | None:
        return b"\x04" + b"\x88" * (SM2_PUBLIC_KEY_SIZE - 1)


class MockTallyMaterialProvider:
    def __init__(self, material: VoteTallyMaterial) -> None:
        self.material = material

    @contextmanager
    def unlocked(self):
        yield self.material


class DynamicMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0
        self.valid_signatures: set[tuple[bytes, bytes, bytes]] = set()

    def add_valid_signature(self, message: bytes, signature: bytes, public_key: bytes) -> None:
        self.valid_signatures.add((message, signature, public_key))

    def blind_verify(self, *, message: bytes, signature: bytes, signer_public_key: bytes) -> bool:
        return (message, signature, signer_public_key) in self.valid_signatures

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            seed = f"hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right

    def sm2_sign(self, private_key: bytes, digest: bytes) -> bytes:
        return b"\x88" * 64

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        return len(signature) == 64 and signature == (b"\x88" * 64)


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
def route_env():
    session = _create_sqlite_session()
    now = datetime.now(timezone.utc)
    creator = User(
        id=str(uuid.uuid4()),
        email="creator@campus.edu.cn",
        role="teacher",
        status="active",
    )
    student = User(
        id=str(uuid.uuid4()),
        email="student@campus.edu.cn",
        role="student",
        status="active",
    )
    sys_user = User(
        id=str(uuid.uuid4()),
        email="sys_tally_route@campus.edu.cn",
        role="system",
        status="active",
    )
    session.add_all([creator, student, sys_user])
    session.commit()

    tally_pubkey = b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1)
    cert = CertificateRecord(
        serial="tally-route-01",
        subject_user_id=sys_user.id,
        kind="platform_ca",
        status="active",
        certificate_der=b"DER-TALLY-CERT-ROUTE",
        key_usage="digitalSignature",
        issuer_serial="root-ca",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        created_at=now,
    )
    session.add(cert)
    session.commit()

    tally_mat = VoteTallyMaterial(
        system_user_id=sys_user.id,
        certificate_serial="tally-route-01",
        certificate_der=b"DER-TALLY-CERT-ROUTE",
        public_key=tally_pubkey,
        private_key=b"\x12" * SM2_PRIVATE_KEY_SIZE,
    )
    tally_provider = MockTallyMaterialProvider(tally_mat)

    crypto = DynamicMockCryptoEngine()
    crypto.set_result("blind_sign", b"\x77" * 64)
    signer_provider = MockVoteSignerMaterialProvider()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_vote_signer_provider] = lambda: signer_provider
    app.dependency_overrides[get_vote_tally_provider] = lambda: tally_provider

    client = TestClient(app)
    return {
        "client": client,
        "app": app,
        "session": session,
        "creator": creator,
        "student": student,
        "crypto": crypto,
        "signer_provider": signer_provider,
        "tally_provider": tally_provider,
        "tally_mat": tally_mat,
    }


def _auth_as(env, user: User):
    env["app"].dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=user.id,
        role=user.role,
        status=user.status,
    )


def _auth_as_role(env, role: str):
    env["app"].dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=str(uuid.uuid4()),
        role=role,
        status="active",
    )


# --- 1. POST /api/v1/votes tests ---


def test_create_vote_success_201(route_env):
    client = route_env["client"]
    _auth_as(route_env, route_env["creator"])

    future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    response = client.post(
        "/api/v1/votes",
        headers={"Idempotency-Key": "key-create-vote-success-001"},
        json={
            "title": "2026 校园十佳歌手初赛",
            "description": "请全体师生投票",
            "options": [{"label": "选手甲"}, {"label": "选手乙"}, {"label": "选手丙"}],
            "scope": "public",
            "closes_at": future,
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["title"] == "2026 校园十佳歌手初赛"
    assert data["scope"] == "public"
    assert data["status"] == "open"
    assert len(data["options"]) == 3
    assert [opt["label"] for opt in data["options"]] == ["选手甲", "选手乙", "选手丙"]


def test_create_vote_unauthenticated_401(route_env):
    client = route_env["client"]
    future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    response = client.post(
        "/api/v1/votes",
        headers={"Idempotency-Key": "key-create-unauth-0001"},
        json={
            "title": "未认证投票",
            "options": [{"label": "A"}, {"label": "B"}],
            "scope": "public",
            "closes_at": future,
        },
    )
    assert response.status_code == 401


def test_create_vote_unauthorized_role_403(route_env):
    client = route_env["client"]
    _auth_as_role(route_env, "guest")
    future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    response = client.post(
        "/api/v1/votes",
        headers={"Idempotency-Key": "key-create-guest-0001"},
        json={
            "title": "访客创建投票",
            "options": [{"label": "A"}, {"label": "B"}],
            "scope": "public",
            "closes_at": future,
        },
    )
    assert response.status_code == 403


def test_create_vote_class_scope_requires_membership(route_env):
    client = route_env["client"]
    session = route_env["session"]
    creator = route_env["creator"]
    _auth_as(route_env, creator)
    future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    class_unit = VoteScopeUnit(kind="class", name="路由测试班级", active=True)
    session.add(class_unit)
    session.commit()

    payload = {
        "title": "班级专属投票",
        "options": [{"label": "A"}, {"label": "B"}],
        "scope": "class",
        "scope_id": class_unit.id,
        "closes_at": future,
    }

    denied = client.post(
        "/api/v1/votes",
        headers={"Idempotency-Key": "key-create-class-scope-01"},
        json=payload,
    )
    assert denied.status_code == 403
    assert denied.json()["code"] == "FORBIDDEN"

    session.add(VoteScopeMember(scope_id=class_unit.id, user_id=creator.id))
    session.commit()
    created = client.post(
        "/api/v1/votes",
        headers={"Idempotency-Key": "key-create-class-scope-02"},
        json=payload,
    )
    assert created.status_code == 201
    stored = session.get(VoteRecord, created.json()["id"])
    assert stored.scope_id == class_unit.id


def test_create_vote_idempotency_conflict_409(route_env):
    client = route_env["client"]
    _auth_as(route_env, route_env["creator"])
    future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    idemp_key = "key-idemp-conflict-test-01"

    res1 = client.post(
        "/api/v1/votes",
        headers={"Idempotency-Key": idemp_key},
        json={
            "title": "原版投票标题",
            "options": [{"label": "A"}, {"label": "B"}],
            "scope": "public",
            "closes_at": future,
        },
    )
    assert res1.status_code == 201

    res2 = client.post(
        "/api/v1/votes",
        headers={"Idempotency-Key": idemp_key},
        json={
            "title": "篡改后的投票标题",
            "options": [{"label": "A"}, {"label": "B"}],
            "scope": "public",
            "closes_at": future,
        },
    )
    assert res2.status_code == 409
    assert res2.json()["code"] == "CONFLICT"


def test_create_vote_idempotent_replay_201(route_env):
    client = route_env["client"]
    _auth_as(route_env, route_env["creator"])
    future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    idemp_key = "key-idemp-replay-test-0001"
    payload = {
        "title": "重放投票测试",
        "options": [{"label": "A"}, {"label": "B"}],
        "scope": "public",
        "closes_at": future,
    }

    res1 = client.post("/api/v1/votes", headers={"Idempotency-Key": idemp_key}, json=payload)
    assert res1.status_code == 201

    res2 = client.post("/api/v1/votes", headers={"Idempotency-Key": idemp_key}, json=payload)
    assert res2.status_code == 201
    assert res1.json()["id"] == res2.json()["id"]


def test_create_vote_validation_errors_422(route_env):
    client = route_env["client"]
    _auth_as(route_env, route_env["creator"])
    future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

    # 1. options < 2
    res = client.post(
        "/api/v1/votes",
        headers={"Idempotency-Key": "key-val-fail-0000000001"},
        json={"title": "T", "options": [{"label": "A"}], "scope": "public", "closes_at": future},
    )
    assert res.status_code == 422

    # 2. closes_at in past
    res = client.post(
        "/api/v1/votes",
        headers={"Idempotency-Key": "key-val-fail-0000000002"},
        json={"title": "T", "options": [{"label": "A"}, {"label": "B"}], "scope": "public", "closes_at": past},
    )
    assert res.status_code == 422

    # 3. missing idempotency key
    res = client.post(
        "/api/v1/votes",
        json={"title": "T", "options": [{"label": "A"}, {"label": "B"}], "scope": "public", "closes_at": future},
    )
    assert res.status_code == 422

    # 4. idempotency key < 16 chars
    res = client.post(
        "/api/v1/votes",
        headers={"Idempotency-Key": "short"},
        json={"title": "T", "options": [{"label": "A"}, {"label": "B"}], "scope": "public", "closes_at": future},
    )
    assert res.status_code == 422


# --- 2. GET /api/v1/votes tests ---


def test_list_votes_public_200(route_env):
    client = route_env["client"]
    session = route_env["session"]
    creator = route_env["creator"]

    now = datetime.now(timezone.utc)
    class_unit = VoteScopeUnit(kind="class", name="列表隐藏班级", active=True)
    session.add(class_unit)
    session.commit()
    v1 = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator.id,
        title="开放投票",
        scope="public",
        closes_at=now + timedelta(days=3),
        status="open",
        created_at=now - timedelta(hours=1),
    )
    v2 = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator.id,
        title="已截止投票",
        scope="public",
        closes_at=now - timedelta(hours=1),  # Past deadline
        status="open",
        created_at=now - timedelta(hours=2),
    )
    v3 = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator.id,
        title="班级投票不应公开",
        scope="class",
        scope_id=class_unit.id,
        closes_at=now + timedelta(days=3),
        status="open",
        created_at=now - timedelta(hours=3),
    )
    session.add_all([v1, v2, v3])
    session.commit()

    # Public GET without token
    response = client.get("/api/v1/votes?page=1&page_size=10")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2

    # Verify dynamic status mapping
    item_titles = {it["title"]: it["status"] for it in data["items"]}
    assert item_titles["开放投票"] == "open"
    assert item_titles["已截止投票"] == "closed"


def test_list_votes_ignores_invalid_auth_header(route_env):
    client = route_env["client"]
    response = client.get("/api/v1/votes", headers={"Authorization": "Bearer invalid_garbage_token"})
    assert response.status_code == 200


# --- 3. GET /api/v1/votes/{vote_id} tests ---


def test_get_vote_detail_public_200_and_not_found_404(route_env):
    client = route_env["client"]
    session = route_env["session"]
    creator = route_env["creator"]

    now = datetime.now(timezone.utc)
    class_unit = VoteScopeUnit(kind="class", name="详情隐藏班级", active=True)
    session.add(class_unit)
    session.commit()
    vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator.id,
        title="详情测试投票",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now,
    )
    opt1 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="选项1", position=0)
    opt2 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="选项2", position=1)
    session.add_all([vote, opt1, opt2])

    class_vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator.id,
        title="私有班级投票",
        scope="class",
        scope_id=class_unit.id,
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now,
    )
    session.add(class_vote)
    session.commit()

    # 1. 200 for public vote
    res = client.get(f"/api/v1/votes/{vote.id}")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == vote.id
    assert data["title"] == "详情测试投票"
    assert len(data["options"]) == 2

    # 2. 404 for non-existent vote
    res_not_found = client.get(f"/api/v1/votes/{uuid.uuid4()}")
    assert res_not_found.status_code == 404

    # 3. 404 for non-public vote (does not leak existence)
    res_hidden = client.get(f"/api/v1/votes/{class_vote.id}")
    assert res_hidden.status_code == 404


# --- 4. POST /api/v1/votes/{vote_id}/credentials tests ---


def test_issue_credential_success_201_and_idempotent_replay(route_env):
    client = route_env["client"]
    session = route_env["session"]
    creator = route_env["creator"]
    student = route_env["student"]
    _auth_as(route_env, student)

    now = datetime.now(timezone.utc)
    vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator.id,
        title="选票签发测试投票",
        scope="public",
        closes_at=now + timedelta(days=3),
        status="open",
        created_at=now,
    )
    opt1 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="1", position=0)
    opt2 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="2", position=1)
    session.add_all([vote, opt1, opt2])
    session.commit()

    blinded_b64 = base64.b64encode(b"blinded-vote-message-001").decode("ascii")
    idemp_key = "idemp-key-vote-issue-0001"

    # First issuance -> 201
    res1 = client.post(
        f"/api/v1/votes/{vote.id}/credentials",
        headers={"Idempotency-Key": idemp_key},
        json={
            "service": "vote_ballot",
            "period": vote.id,
            "blinded_message": blinded_b64,
        },
    )
    assert res1.status_code == 201
    data1 = res1.json()
    assert "blind_signature" in data1
    assert data1["algorithm"] == "SM2-BLIND-PROTOCOL-V1"
    assert set(data1.keys()) == {"blind_signature", "algorithm"}

    # Idempotent replay -> 201 with identical blind_signature
    res2 = client.post(
        f"/api/v1/votes/{vote.id}/credentials",
        headers={"Idempotency-Key": idemp_key},
        json={
            "service": "vote_ballot",
            "period": vote.id,
            "blinded_message": blinded_b64,
        },
    )
    assert res2.status_code == 201
    assert res2.json()["blind_signature"] == data1["blind_signature"]


def test_issue_credential_class_scope_allows_member_and_rejects_outsider(route_env):
    client = route_env["client"]
    session = route_env["session"]
    creator = route_env["creator"]
    student = route_env["student"]
    now = datetime.now(timezone.utc)

    class_unit = VoteScopeUnit(kind="class", name="凭证签发测试班级", active=True)
    session.add(class_unit)
    session.commit()
    session.add(VoteScopeMember(scope_id=class_unit.id, user_id=student.id))
    session.commit()
    vote = VoteRecord(
        creator_id=creator.id,
        title="班级选票签发测试",
        scope="class",
        scope_id=class_unit.id,
        closes_at=now + timedelta(days=1),
        status="open",
        created_at=now,
    )
    session.add(vote)
    session.commit()
    payload = {
        "service": "vote_ballot",
        "period": vote.id,
        "blinded_message": base64.b64encode(b"class-scope-ballot").decode("ascii"),
    }

    _auth_as(route_env, creator)
    denied = client.post(
        f"/api/v1/votes/{vote.id}/credentials",
        headers={"Idempotency-Key": "class-outsider-credential-01"},
        json=payload,
    )
    assert denied.status_code == 403
    assert denied.json()["code"] == "FORBIDDEN"

    _auth_as(route_env, student)
    issued = client.post(
        f"/api/v1/votes/{vote.id}/credentials",
        headers={"Idempotency-Key": "class-member-credential-0001"},
        json=payload,
    )
    assert issued.status_code == 201
    assert issued.json()["algorithm"] == "SM2-BLIND-PROTOCOL-V1"


def test_issue_credential_conflict_409(route_env):
    client = route_env["client"]
    session = route_env["session"]
    creator = route_env["creator"]
    student = route_env["student"]
    _auth_as(route_env, student)

    now = datetime.now(timezone.utc)
    vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator.id,
        title="冲突测试投票",
        scope="public",
        closes_at=now + timedelta(days=3),
        status="open",
        created_at=now,
    )
    session.add(vote)
    session.commit()

    blinded_b64 = base64.b64encode(b"msg1").decode("ascii")
    res1 = client.post(
        f"/api/v1/votes/{vote.id}/credentials",
        headers={"Idempotency-Key": "idemp-vote-issue-first-001"},
        json={"service": "vote_ballot", "period": vote.id, "blinded_message": blinded_b64},
    )
    assert res1.status_code == 201

    # Same student, same vote, different key -> 409
    res2 = client.post(
        f"/api/v1/votes/{vote.id}/credentials",
        headers={"Idempotency-Key": "idemp-vote-issue-second-002"},
        json={"service": "vote_ballot", "period": vote.id, "blinded_message": blinded_b64},
    )
    assert res2.status_code == 409
    assert res2.json()["code"] == "CONFLICT"


def test_issue_credential_vote_closed_409(route_env):
    client = route_env["client"]
    session = route_env["session"]
    creator = route_env["creator"]
    student = route_env["student"]
    _auth_as(route_env, student)

    now = datetime.now(timezone.utc)
    vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator.id,
        title="已截止选票签发",
        scope="public",
        closes_at=now - timedelta(seconds=1),
        status="open",
        created_at=now - timedelta(days=1),
    )
    session.add(vote)
    session.commit()

    res = client.post(
        f"/api/v1/votes/{vote.id}/credentials",
        headers={"Idempotency-Key": "idemp-closed-vote-00000001"},
        json={
            "service": "vote_ballot",
            "period": vote.id,
            "blinded_message": base64.b64encode(b"msg").decode("ascii"),
        },
    )
    assert res.status_code == 409
    assert res.json()["code"] == "CONFLICT"


def test_issue_credential_vote_not_found_404(route_env):
    client = route_env["client"]
    student = route_env["student"]
    _auth_as(route_env, student)
    fake_id = str(uuid.uuid4())

    res = client.post(
        f"/api/v1/votes/{fake_id}/credentials",
        headers={"Idempotency-Key": "idemp-not-found-0000000001"},
        json={
            "service": "vote_ballot",
            "period": fake_id,
            "blinded_message": base64.b64encode(b"msg").decode("ascii"),
        },
    )
    assert res.status_code == 404


def test_issue_credential_unauthenticated_401(route_env):
    client = route_env["client"]
    fake_id = str(uuid.uuid4())

    res = client.post(
        f"/api/v1/votes/{fake_id}/credentials",
        headers={"Idempotency-Key": "idemp-unauth-000000000001"},
        json={
            "service": "vote_ballot",
            "period": fake_id,
            "blinded_message": base64.b64encode(b"msg").decode("ascii"),
        },
    )
    assert res.status_code == 401


def test_issue_credential_unauthorized_role_403(route_env):
    client = route_env["client"]
    _auth_as_role(route_env, "guest")
    fake_id = str(uuid.uuid4())

    res = client.post(
        f"/api/v1/votes/{fake_id}/credentials",
        headers={"Idempotency-Key": "idemp-guest-0000000000001"},
        json={
            "service": "vote_ballot",
            "period": fake_id,
            "blinded_message": base64.b64encode(b"msg").decode("ascii"),
        },
    )
    assert res.status_code == 403


def test_issue_credential_engine_unavailable_503(route_env):
    client = route_env["client"]
    session = route_env["session"]
    creator = route_env["creator"]
    student = route_env["student"]
    _auth_as(route_env, student)

    # Provider returning None
    class EmptySignerProvider:
        def get_signer_private_key(self, *, vote_id: str) -> bytes | None:
            return None
        def get_signer_public_key(self, *, vote_id: str) -> bytes | None:
            return None

    route_env["app"].dependency_overrides[get_vote_signer_provider] = EmptySignerProvider

    now = datetime.now(timezone.utc)
    vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator.id,
        title="私钥缺失测试",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now,
    )
    session.add(vote)
    session.commit()

    res = client.post(
        f"/api/v1/votes/{vote.id}/credentials",
        headers={"Idempotency-Key": "idemp-key-provider-fail-01"},
        json={
            "service": "vote_ballot",
            "period": vote.id,
            "blinded_message": base64.b64encode(b"msg").decode("ascii"),
        },
    )
    assert res.status_code == 503
    assert res.json()["code"] == "SERVICE_UNAVAILABLE"


def test_issue_credential_invalid_service_or_period_422(route_env):
    client = route_env["client"]
    student = route_env["student"]
    _auth_as(route_env, student)
    vote_id = str(uuid.uuid4())

    # 1. Invalid service (not vote_ballot)
    res = client.post(
        f"/api/v1/votes/{vote_id}/credentials",
        headers={"Idempotency-Key": "idemp-val-service-00000001"},
        json={"service": "hole_post", "period": vote_id, "blinded_message": base64.b64encode(b"m").decode("ascii")},
    )
    assert res.status_code == 422

    # 2. Invalid period (mismatched vote_id)
    res = client.post(
        f"/api/v1/votes/{vote_id}/credentials",
        headers={"Idempotency-Key": "idemp-val-period-0000000001"},
        json={"service": "vote_ballot", "period": "mismatched-period", "blinded_message": base64.b64encode(b"m").decode("ascii")},
    )
    assert res.status_code == 422


def _create_test_vote(session, creator_id, *, status="open", offset_hours=24):
    now = datetime.now(timezone.utc)
    vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator_id,
        title="匿名投票测试",
        scope="public",
        closes_at=now + timedelta(hours=offset_hours),
        status=status,
        created_at=now - timedelta(hours=1),
    )
    opt1 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="选项A", position=0)
    opt2 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="选项B", position=1)
    session.add_all([vote, opt1, opt2])
    session.commit()
    return vote, opt1, opt2


def _prepare_valid_credential(crypto, signer_pubkey, vote_id, option_id, sn_hex="11223344556677889900aabbccddeeff"):
    from app.services.vote_ballot_verification import encode_vote_ballot_message

    sig_bytes = b"\x77" * 64
    msg = encode_vote_ballot_message(
        sn_hex=sn_hex,
        service="vote_ballot",
        vote_id=vote_id,
        option_id=option_id,
    )
    crypto.add_valid_signature(msg, sig_bytes, signer_pubkey)
    return {
        "sn": sn_hex,
        "service": "vote_ballot",
        "period": vote_id,
        "signature": base64.b64encode(sig_bytes).decode("ascii"),
    }


def test_submit_ballot_success_201_and_idempotent_replay(route_env):
    client = route_env["client"]
    session = route_env["session"]
    crypto = route_env["crypto"]
    creator = route_env["creator"]

    vote, opt1, opt2 = _create_test_vote(session, creator.id)
    signer_pubkey = route_env["signer_provider"].get_signer_public_key(vote_id=vote.id)
    cred = _prepare_valid_credential(crypto, signer_pubkey, vote.id, opt1.id)

    idemp_key = "idemp-ballot-submit-00000001"
    res = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": idemp_key},
        json={
            "option_id": opt1.id,
            "credential": cred,
        },
    )
    assert res.status_code == 201
    assert res.json() == {"accepted": True}

    # Verify DB state
    from app.models.credential import ConsumedSN
    from app.models.vote import AnonymousBallot, BallotIdempotency, VoteResultSnapshot

    assert session.query(AnonymousBallot).filter_by(vote_id=vote.id).count() == 1
    assert session.query(BallotIdempotency).count() == 1
    assert session.query(ConsumedSN).filter_by(service="vote_ballot").count() == 1
    snapshot = session.query(VoteResultSnapshot).filter_by(vote_id=vote.id).one()
    assert snapshot.version == 1
    assert snapshot.total == 1
    assert snapshot.get_counts() == {opt1.id: 1, opt2.id: 0}

    # Idempotent replay with same key and same body
    res_replay = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": idemp_key},
        json={
            "option_id": opt1.id,
            "credential": cred,
        },
    )
    assert res_replay.status_code == 201
    assert res_replay.json() == {"accepted": True}
    assert session.query(AnonymousBallot).filter_by(vote_id=vote.id).count() == 1
    assert session.query(VoteResultSnapshot).filter_by(vote_id=vote.id).count() == 1


def test_submit_ballot_idempotency_conflict_409(route_env):
    client = route_env["client"]
    session = route_env["session"]
    crypto = route_env["crypto"]
    creator = route_env["creator"]

    vote, opt1, opt2 = _create_test_vote(session, creator.id)
    signer_pubkey = route_env["signer_provider"].get_signer_public_key(vote_id=vote.id)
    cred1 = _prepare_valid_credential(crypto, signer_pubkey, vote.id, opt1.id, sn_hex="11111111111111111111111111111111")
    cred2 = _prepare_valid_credential(crypto, signer_pubkey, vote.id, opt2.id, sn_hex="22222222222222222222222222222222")

    idemp_key = "idemp-ballot-conflict-000001"
    res1 = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": idemp_key},
        json={"option_id": opt1.id, "credential": cred1},
    )
    assert res1.status_code == 201

    # Same idempotency key with different payload
    res2 = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": idemp_key},
        json={"option_id": opt2.id, "credential": cred2},
    )
    assert res2.status_code == 409
    assert res2.json()["code"] == "CONFLICT"


def test_submit_ballot_credential_reuse_409(route_env):
    client = route_env["client"]
    session = route_env["session"]
    crypto = route_env["crypto"]
    creator = route_env["creator"]

    vote, opt1, opt2 = _create_test_vote(session, creator.id)
    signer_pubkey = route_env["signer_provider"].get_signer_public_key(vote_id=vote.id)
    sn_hex = "33333333333333333333333333333333"
    cred = _prepare_valid_credential(crypto, signer_pubkey, vote.id, opt1.id, sn_hex=sn_hex)

    res1 = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": "idemp-reuse-first-key-0001"},
        json={"option_id": opt1.id, "credential": cred},
    )
    assert res1.status_code == 201

    # Different idempotency key, but same SN reused
    res2 = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": "idemp-reuse-second-key-002"},
        json={"option_id": opt1.id, "credential": cred},
    )
    assert res2.status_code == 409
    assert res2.json()["code"] == "CONFLICT"


def test_submit_ballot_closed_vote_409(route_env):
    client = route_env["client"]
    session = route_env["session"]
    crypto = route_env["crypto"]
    creator = route_env["creator"]

    vote, opt1, opt2 = _create_test_vote(session, creator.id, offset_hours=-2)
    signer_pubkey = route_env["signer_provider"].get_signer_public_key(vote_id=vote.id)
    cred = _prepare_valid_credential(crypto, signer_pubkey, vote.id, opt1.id)

    res = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": "idemp-closed-vote-0000001"},
        json={"option_id": opt1.id, "credential": cred},
    )
    assert res.status_code == 409
    assert res.json()["code"] == "CONFLICT"


def test_submit_ballot_vote_not_found_404(route_env):
    client = route_env["client"]
    fake_vote_id = str(uuid.uuid4())
    fake_option_id = str(uuid.uuid4())
    cred = {
        "sn": "44444444444444444444444444444444",
        "service": "vote_ballot",
        "period": fake_vote_id,
        "signature": base64.b64encode(b"sig" * 21 + b"x").decode("ascii"),
    }
    res = client.post(
        f"/api/v1/votes/{fake_vote_id}/ballots",
        headers={"Idempotency-Key": "idemp-not-found-000000001"},
        json={"option_id": fake_option_id, "credential": cred},
    )
    assert res.status_code == 404
    assert res.json()["code"] == "NOT_FOUND"


def test_submit_ballot_invalid_option_422(route_env):
    client = route_env["client"]
    session = route_env["session"]
    creator = route_env["creator"]

    vote, opt1, opt2 = _create_test_vote(session, creator.id)
    random_opt_id = str(uuid.uuid4())
    cred = {
        "sn": "55555555555555555555555555555555",
        "service": "vote_ballot",
        "period": vote.id,
        "signature": base64.b64encode(b"sig" * 21 + b"x").decode("ascii"),
    }
    res = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": "idemp-invalid-opt-0000001"},
        json={"option_id": random_opt_id, "credential": cred},
    )
    assert res.status_code == 422


def test_submit_ballot_invalid_signature_422(route_env):
    client = route_env["client"]
    session = route_env["session"]
    creator = route_env["creator"]

    vote, opt1, opt2 = _create_test_vote(session, creator.id)
    # Signature not added to crypto engine
    cred = {
        "sn": "66666666666666666666666666666666",
        "service": "vote_ballot",
        "period": vote.id,
        "signature": base64.b64encode(b"\x99" * 64).decode("ascii"),
    }
    res = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": "idemp-bad-sig-00000000001"},
        json={"option_id": opt1.id, "credential": cred},
    )
    assert res.status_code == 422


def test_submit_ballot_public_no_jwt_and_ignores_invalid_auth(route_env):
    client = route_env["client"]
    session = route_env["session"]
    crypto = route_env["crypto"]
    creator = route_env["creator"]

    vote, opt1, opt2 = _create_test_vote(session, creator.id)
    signer_pubkey = route_env["signer_provider"].get_signer_public_key(vote_id=vote.id)

    # 1. Without any Authorization header
    cred1 = _prepare_valid_credential(crypto, signer_pubkey, vote.id, opt1.id, sn_hex="77777777777777777777777777777777")
    res1 = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": "idemp-no-auth-00000000001"},
        json={"option_id": opt1.id, "credential": cred1},
    )
    assert res1.status_code == 201
    assert res1.json() == {"accepted": True}

    # 2. With invalid / malformed Authorization header
    cred2 = _prepare_valid_credential(crypto, signer_pubkey, vote.id, opt2.id, sn_hex="88888888888888888888888888888888")
    res2 = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={
            "Idempotency-Key": "idemp-bad-auth-00000000001",
            "Authorization": "Bearer this-is-not-a-valid-jwt-token",
        },
        json={"option_id": opt2.id, "credential": cred2},
    )
    assert res2.status_code == 201
    assert res2.json() == {"accepted": True}


def test_submit_ballot_tally_engine_unavailable_503(route_env):
    client = route_env["client"]
    session = route_env["session"]
    crypto = route_env["crypto"]
    creator = route_env["creator"]

    class FailingTallyProvider:
        @contextmanager
        def unlocked(self):
            from app.services.vote_tally_provider import VoteTallyMaterialUnavailableError
            raise VoteTallyMaterialUnavailableError("engine_unavailable", "计票台不可用")
            yield

    route_env["app"].dependency_overrides[get_vote_tally_provider] = FailingTallyProvider

    vote, opt1, opt2 = _create_test_vote(session, creator.id)
    signer_pubkey = route_env["signer_provider"].get_signer_public_key(vote_id=vote.id)
    cred = _prepare_valid_credential(crypto, signer_pubkey, vote.id, opt1.id, sn_hex="99999999999999999999999999999999")

    res = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": "idemp-tally-fail-00000001"},
        json={"option_id": opt1.id, "credential": cred},
    )
    assert res.status_code == 503
    assert res.json()["code"] == "SERVICE_UNAVAILABLE"


def test_get_vote_results_and_verify(route_env):
    client = route_env["client"]
    session = route_env["session"]
    crypto = route_env["crypto"]
    creator = route_env["creator"]

    fake_id = str(uuid.uuid4())
    # 404 for non-existent vote
    assert client.get(f"/api/v1/votes/{fake_id}/results").status_code == 404
    assert client.get(f"/api/v1/votes/{fake_id}/results/verify").status_code == 404

    vote, opt1, opt2 = _create_test_vote(session, creator.id)

    # 404 before any snapshot
    assert client.get(f"/api/v1/votes/{vote.id}/results").status_code == 404
    assert client.get(f"/api/v1/votes/{vote.id}/results/verify").status_code == 404

    # Submit ballot to generate snapshot
    signer_pubkey = route_env["signer_provider"].get_signer_public_key(vote_id=vote.id)
    cred = _prepare_valid_credential(crypto, signer_pubkey, vote.id, opt1.id, sn_hex="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    res_sub = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": "idemp-get-result-00000001"},
        json={"option_id": opt1.id, "credential": cred},
    )
    assert res_sub.status_code == 201

    # GET /results with invalid Authorization header - still works (public endpoint)
    res_res = client.get(
        f"/api/v1/votes/{vote.id}/results",
        headers={"Authorization": "Bearer invalid-token"},
    )
    assert res_res.status_code == 200
    res_data = res_res.json()
    assert res_data["vote_id"] == vote.id
    assert res_data["counts"] == {opt1.id: 1, opt2.id: 0}
    assert res_data["total"] == 1
    assert "signature" in res_data
    assert "signer_certificate" in res_data
    assert "published_at" in res_data

    # GET /results/verify without Authorization header
    res_ver = client.get(f"/api/v1/votes/{vote.id}/results/verify")
    assert res_ver.status_code == 200
    ver_data = res_ver.json()
    assert ver_data["valid"] is True
    assert ver_data["algorithm"] == "SM3-with-SM2"
    assert ver_data["certificate_valid"] is True

    # Tamper with snapshot in database
    from app.models.vote import VoteResultSnapshot
    snapshot = session.query(VoteResultSnapshot).filter_by(vote_id=vote.id).one()
    snapshot.total = 999
    session.commit()

    res_ver_tampered = client.get(f"/api/v1/votes/{vote.id}/results/verify")
    assert res_ver_tampered.status_code == 200
    assert res_ver_tampered.json()["valid"] is False

