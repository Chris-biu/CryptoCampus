from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy.orm import sessionmaker

from app.crypto.mock import MockCryptoEngine
from app.db.session import create_db_engine, init_database
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.vote import CreateVoteOption, CreateVoteRequest
from app.services.votes import VoteService, VoteServiceError


class DeterministicDigestMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._counter = 0
        self._digests: dict[bytes, bytes] = {}

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            seed = f"hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


def _setup_service():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    sm = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = sm()
    crypto_engine = DeterministicDigestMockCryptoEngine()
    service = VoteService(session=session, crypto_engine=crypto_engine)
    return session, crypto_engine, service


def test_create_vote_success_and_preserves_option_order():
    session, crypto, service = _setup_service()
    creator = User(email="student1@example.com", role="student", status="active")
    session.add(creator)
    session.commit()

    now = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    closes_at = now + timedelta(days=3)

    req = CreateVoteRequest(
        title="十佳歌手初赛投票",
        description="请投出您宝贵的一票",
        options=[
            CreateVoteOption(label="选手甲"),
            CreateVoteOption(label="选手乙"),
            CreateVoteOption(label="选手丙"),
        ],
        scope="public",
        closes_at=closes_at,
    )

    vote = service.create(
        creator_id=creator.id,
        request=req,
        idempotency_key="vote-create-key-000000000001",
        now=now,
    )

    assert vote.id is not None
    assert vote.title == "十佳歌手初赛投票"
    assert vote.scope == "public"
    assert vote.status == "open"
    assert vote.closes_at == closes_at
    assert len(vote.options) == 3
    assert [opt.label for opt in vote.options] == ["选手甲", "选手乙", "选手丙"]
    assert vote.options[0].id != vote.options[1].id != vote.options[2].id

    # Verify audit log
    audit = session.query(AuditLog).filter_by(action="vote.create").one_or_none()
    assert audit is not None
    assert audit.actor == creator.id
    assert audit.target == f"vote:{vote.id}"
    assert audit.detail_hash is not None


def test_create_vote_idempotent_replay_and_conflict():
    session, crypto, service = _setup_service()
    creator = User(email="student2@example.com", role="student", status="active")
    session.add(creator)
    session.commit()

    now = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    closes_at = now + timedelta(days=2)

    req1 = CreateVoteRequest(
        title="学生会换届选举",
        options=[CreateVoteOption(label="A候选人"), CreateVoteOption(label="B候选人")],
        scope="public",
        closes_at=closes_at,
    )

    idem_key = "idemp-vote-test-key-0000000001"
    first = service.create(
        creator_id=creator.id,
        request=req1,
        idempotency_key=idem_key,
        now=now,
    )

    # Replay with same key and exact same request
    second = service.create(
        creator_id=creator.id,
        request=req1,
        idempotency_key=idem_key,
        now=now + timedelta(minutes=5),
    )

    assert first.id == second.id
    assert [opt.id for opt in first.options] == [opt.id for opt in second.options]

    # Exactly 1 audit record created
    audit_count = session.query(AuditLog).filter_by(action="vote.create").count()
    assert audit_count == 1

    # Same key with different request content must return 409 conflict
    req2 = CreateVoteRequest(
        title="完全不同的选举",
        options=[CreateVoteOption(label="C候选人"), CreateVoteOption(label="D候选人")],
        scope="public",
        closes_at=closes_at,
    )
    with pytest.raises(VoteServiceError) as exc_info:
        service.create(
            creator_id=creator.id,
            request=req2,
            idempotency_key=idem_key,
            now=now,
        )
    assert exc_info.value.code == "idempotency_conflict"


def test_create_vote_different_creators_same_key():
    session, crypto, service = _setup_service()
    user1 = User(email="user1@example.com", role="student", status="active")
    user2 = User(email="user2@example.com", role="teacher", status="active")
    session.add_all([user1, user2])
    session.commit()

    now = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    closes_at = now + timedelta(days=2)

    req = CreateVoteRequest(
        title="通识课评价",
        options=[CreateVoteOption(label="好"), CreateVoteOption(label="极好")],
        scope="public",
        closes_at=closes_at,
    )

    idem_key = "shared-idemp-key-00000000001"
    vote1 = service.create(
        creator_id=user1.id,
        request=req,
        idempotency_key=idem_key,
        now=now,
    )
    vote2 = service.create(
        creator_id=user2.id,
        request=req,
        idempotency_key=idem_key,
        now=now,
    )

    assert vote1.id != vote2.id


def test_create_vote_validates_creator_and_deadline():
    session, crypto, service = _setup_service()
    creator = User(email="frozen@example.com", role="student", status="frozen")
    session.add(creator)
    session.commit()

    now = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    future = now + timedelta(days=1)
    req = CreateVoteRequest(
        title="无效用户测试",
        options=[CreateVoteOption(label="甲"), CreateVoteOption(label="乙")],
        scope="public",
        closes_at=future,
    )

    # Inactive creator rejected
    with pytest.raises(VoteServiceError) as exc:
        service.create(
            creator_id=creator.id,
            request=req,
            idempotency_key="key-creator-inactive-0001",
            now=now,
        )
    assert exc.value.code == "user_inactive"

    # closes_at in the past rejected
    active_creator = User(email="active@example.com", role="student", status="active")
    session.add(active_creator)
    session.commit()

    past_req = CreateVoteRequest(
        title="过去投票测试",
        options=[CreateVoteOption(label="甲"), CreateVoteOption(label="乙")],
        scope="public",
        closes_at=now,  # equal or past
    )
    with pytest.raises(VoteServiceError) as exc_past:
        service.create(
            creator_id=active_creator.id,
            request=past_req,
            idempotency_key="key-closes-at-past-00001",
            now=now,
        )
    assert exc_past.value.code == "closes_at_in_past"
