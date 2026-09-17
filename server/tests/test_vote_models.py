from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db.session import create_db_engine, init_database
from app.models.user import User
from app.models.vote import (
    VoteCreateIdempotency,
    VoteOption,
    VoteRecord,
    VoteScopeMember,
    VoteScopeUnit,
)
from app.schemas.vote import CreateVoteOption, CreateVoteRequest, Vote, VotePage


def _make_session():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    sm = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return sm()


def test_vote_record_and_option_database_constraints():
    session = _make_session()
    user = User(
        email="creator@example.com",
        role="student",
        status="active",
    )
    session.add(user)
    session.commit()

    now = datetime.now(timezone.utc)
    closes_at = now + timedelta(days=7)

    vote = VoteRecord(
        creator_id=user.id,
        title="班委选举",
        description="测试议题描述",
        scope="public",
        closes_at=closes_at,
        status="open",
        created_at=now,
    )
    session.add(vote)
    session.commit()

    assert vote.id is not None
    assert vote.title == "班委选举"
    assert vote.status == "open"

    opt0 = VoteOption(vote_id=vote.id, label="候选人甲", position=0)
    opt1 = VoteOption(vote_id=vote.id, label="候选人乙", position=1)
    session.add_all([opt0, opt1])
    session.commit()

    assert opt0.id != opt1.id
    assert len(vote.options) == 2

    # Duplicate position under same vote must violate unique(vote_id, position)
    duplicate_pos = VoteOption(vote_id=vote.id, label="候选人丙", position=0)
    session.add(duplicate_pos)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_vote_create_idempotency_database_constraints():
    session = _make_session()
    user = User(email="creator2@example.com", role="student", status="active")
    session.add(user)
    session.commit()

    now = datetime.now(timezone.utc)
    vote = VoteRecord(
        creator_id=user.id,
        title="投票测试",
        scope="public",
        closes_at=now + timedelta(days=1),
        status="open",
        created_at=now,
    )
    session.add(vote)
    session.commit()

    key_hash = b"\x11" * 32
    request_hash = b"\x22" * 32

    idemp1 = VoteCreateIdempotency(
        creator_id=user.id,
        key_hash=key_hash,
        request_hash=request_hash,
        vote_id=vote.id,
        created_at=now,
    )
    session.add(idemp1)
    session.commit()

    # Same creator and key_hash violates unique(creator_id, key_hash)
    idemp_dup = VoteCreateIdempotency(
        creator_id=user.id,
        key_hash=key_hash,
        request_hash=b"\x33" * 32,
        vote_id=vote.id,
        created_at=now,
    )
    session.add(idemp_dup)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

    # Different creator with same key_hash must be allowed
    user2 = User(email="creator3@example.com", role="teacher", status="active")
    session.add(user2)
    session.commit()

    idemp_other = VoteCreateIdempotency(
        creator_id=user2.id,
        key_hash=key_hash,
        request_hash=request_hash,
        vote_id=vote.id,
        created_at=now,
    )
    session.add(idemp_other)
    session.commit()
    assert idemp_other.id is not None


def test_create_vote_request_options_boundary():
    future_time = datetime.now(timezone.utc) + timedelta(days=1)

    # 1 option rejected
    with pytest.raises(ValidationError):
        CreateVoteRequest(
            title="标题",
            options=[CreateVoteOption(label="唯一选项")],
            scope="public",
            closes_at=future_time,
        )

    # 2 options valid
    req2 = CreateVoteRequest(
        title="标题",
        options=[CreateVoteOption(label="甲"), CreateVoteOption(label="乙")],
        scope="public",
        closes_at=future_time,
    )
    assert len(req2.options) == 2

    # 20 options valid
    opts20 = [CreateVoteOption(label=f"选项{i}") for i in range(20)]
    req20 = CreateVoteRequest(
        title="标题",
        options=opts20,
        scope="public",
        closes_at=future_time,
    )
    assert len(req20.options) == 20

    # 21 options rejected
    opts21 = [CreateVoteOption(label=f"选项{i}") for i in range(21)]
    with pytest.raises(ValidationError):
        CreateVoteRequest(
            title="标题",
            options=opts21,
            scope="public",
            closes_at=future_time,
        )


def test_create_vote_request_scope_id_rules():
    future_time = datetime.now(timezone.utc) + timedelta(days=1)
    options = [CreateVoteOption(label="甲"), CreateVoteOption(label="乙")]
    scope_id = "11111111-1111-4111-8111-111111111111"

    public_request = CreateVoteRequest(
        title="公开投票", options=options, scope="public", closes_at=future_time
    )
    assert public_request.scope_id is None

    class_request = CreateVoteRequest(
        title="班级投票",
        options=options,
        scope="class",
        scope_id=scope_id,
        closes_at=future_time,
    )
    assert class_request.scope_id == scope_id

    with pytest.raises(ValidationError):
        CreateVoteRequest(
            title="缺少范围标识", options=options, scope="group", closes_at=future_time
        )

    with pytest.raises(ValidationError):
        CreateVoteRequest(
            title="公开投票不能指定范围",
            options=options,
            scope="public",
            scope_id=scope_id,
            closes_at=future_time,
        )


def test_vote_scope_database_constraints():
    session = _make_session()
    user = User(email="scope-member@example.com", role="student", status="active")
    class_unit = VoteScopeUnit(kind="class", name="软件工程 2301", active=True)
    session.add_all([user, class_unit])
    session.commit()

    session.add(VoteScopeMember(scope_id=class_unit.id, user_id=user.id))
    session.commit()

    session.add(VoteScopeMember(scope_id=class_unit.id, user_id=user.id))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

    session.add(
        VoteRecord(
            creator_id=user.id,
            title="无效公开投票",
            scope="public",
            scope_id=class_unit.id,
            closes_at=datetime.now(timezone.utc) + timedelta(days=1),
            status="open",
        )
    )
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_init_database_upgrades_legacy_votes_with_scope_id_and_fail_closed_trigger():
    engine = create_db_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TABLE votes (
                id VARCHAR(36) PRIMARY KEY,
                creator_id VARCHAR(36) NOT NULL,
                title VARCHAR(200) NOT NULL,
                description VARCHAR(2000),
                scope VARCHAR(16) NOT NULL,
                closes_at DATETIME NOT NULL,
                status VARCHAR(16) NOT NULL,
                created_at DATETIME NOT NULL
            )
            """
        )

    init_database(engine)
    with engine.connect() as connection:
        columns = {
            row["name"]
            for row in connection.exec_driver_sql("PRAGMA table_info(votes)").mappings()
        }
        triggers = {
            row["name"]
            for row in connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'votes'"
            ).mappings()
        }

    assert "scope_id" in columns
    assert {"trg_votes_scope_insert", "trg_votes_scope_update"} <= triggers

    session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    user = User(email="legacy-scope@example.com", role="student", status="active")
    session.add(user)
    session.commit()
    session.add(
        VoteRecord(
            creator_id=user.id,
            title="旧库中缺少范围绑定的班级投票",
            scope="class",
            scope_id=None,
            closes_at=datetime.now(timezone.utc) + timedelta(days=1),
            status="open",
        )
    )
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_create_vote_request_string_boundaries_and_forbid_extra():
    future_time = datetime.now(timezone.utc) + timedelta(days=1)
    valid_opts = [CreateVoteOption(label="甲"), CreateVoteOption(label="乙")]

    # Empty title rejected
    with pytest.raises(ValidationError):
        CreateVoteRequest(
            title="",
            options=valid_opts,
            scope="public",
            closes_at=future_time,
        )

    # Title 201 chars rejected
    with pytest.raises(ValidationError):
        CreateVoteRequest(
            title="A" * 201,
            options=valid_opts,
            scope="public",
            closes_at=future_time,
        )

    # Description 2001 chars rejected
    with pytest.raises(ValidationError):
        CreateVoteRequest(
            title="合法标题",
            description="D" * 2001,
            options=valid_opts,
            scope="public",
            closes_at=future_time,
        )

    # Option label 101 chars rejected
    with pytest.raises(ValidationError):
        CreateVoteRequest(
            title="合法标题",
            options=[CreateVoteOption(label="O" * 101), CreateVoteOption(label="乙")],
            scope="public",
            closes_at=future_time,
        )

    # Scope invalid value rejected
    with pytest.raises(ValidationError):
        CreateVoteRequest(
            title="合法标题",
            options=valid_opts,
            scope="invalid_scope",
            closes_at=future_time,
        )

    # Extra fields forbidden
    with pytest.raises(ValidationError):
        CreateVoteRequest.model_validate({
            "title": "合法标题",
            "options": [{"label": "甲"}, {"label": "乙"}],
            "scope": "public",
            "closes_at": future_time.isoformat(),
            "unexpected_field": "disallowed",
        })


def test_create_vote_request_closes_at_validation():
    valid_opts = [CreateVoteOption(label="甲"), CreateVoteOption(label="乙")]

    # Naive datetime (no timezone) rejected
    naive_dt = datetime.now() + timedelta(days=1)
    with pytest.raises(ValidationError):
        CreateVoteRequest(
            title="标题",
            options=valid_opts,
            scope="public",
            closes_at=naive_dt,
        )


def test_vote_response_schema():
    future_time = datetime.now(timezone.utc) + timedelta(days=1)
    vote_data = {
        "id": "11111111-1111-4111-8111-111111111111",
        "title": "测试投票",
        "options": [
            {"id": "22222222-2222-4222-8222-222222222222", "label": "甲"},
            {"id": "33333333-3333-4333-8333-333333333333", "label": "乙"},
        ],
        "scope": "public",
        "status": "open",
        "closes_at": future_time.isoformat(),
    }
    vote = Vote.model_validate(vote_data)
    assert vote.id == "11111111-1111-4111-8111-111111111111"
    assert len(vote.options) == 2
    assert vote.status == "open"

    page_data = {
        "items": [vote_data],
        "page": 1,
        "page_size": 20,
        "total": 1,
    }
    page = VotePage.model_validate(page_data)
    assert page.total == 1
    assert page.items[0].title == "测试投票"
