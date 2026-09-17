from datetime import datetime, timedelta, timezone
import json
import pytest
from sqlalchemy.orm import sessionmaker

from app.crypto.mock import MockCryptoEngine
from app.db.session import create_db_engine, init_database
from app.models.user import User
from app.models.vote import VoteOption, VoteRecord, VoteResultSnapshot, VoteScopeUnit
from app.services.votes import VoteService, VoteServiceError


def _setup_env():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    sm = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = sm()
    crypto = MockCryptoEngine()
    service = VoteService(session=session, crypto_engine=crypto)
    return session, service


def test_list_public_empty():
    session, service = _setup_env()
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    page = service.list_public(page=1, page_size=20, now=now)
    assert page.total == 0
    assert page.items == []
    assert page.page == 1
    assert page.page_size == 20


def test_list_public_pagination_ordering_and_scope_filtering():
    session, service = _setup_env()
    creator = User(email="user@example.com", role="student", status="active")
    session.add(creator)
    session.commit()

    base_time = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    future = base_time + timedelta(days=5)
    class_unit = VoteScopeUnit(kind="class", name="查询测试班级", active=True)
    group_unit = VoteScopeUnit(kind="group", name="查询测试群组", active=True)
    session.add_all([class_unit, group_unit])
    session.commit()

    # Insert 5 public votes with distinct created_at
    public_votes = []
    for i in range(5):
        vote = VoteRecord(
            id=f"00000000-0000-4000-8000-00000000000{i}",
            creator_id=creator.id,
            title=f"公开投票{i}",
            scope="public",
            closes_at=future,
            status="open",
            created_at=base_time + timedelta(minutes=i * 10),
        )
        opt1 = VoteOption(vote_id=vote.id, label="选项1", position=0)
        opt2 = VoteOption(vote_id=vote.id, label="选项2", position=1)
        session.add_all([vote, opt1, opt2])
        public_votes.append(vote)

    # Insert 2 non-public votes (class, group)
    class_vote = VoteRecord(
        creator_id=creator.id,
        title="班级内部投票",
        scope="class",
        scope_id=class_unit.id,
        closes_at=future,
        status="open",
        created_at=base_time + timedelta(minutes=25),
    )
    group_vote = VoteRecord(
        creator_id=creator.id,
        title="群组内部投票",
        scope="group",
        scope_id=group_unit.id,
        closes_at=future,
        status="open",
        created_at=base_time + timedelta(minutes=35),
    )
    session.add_all([class_vote, group_vote])
    session.commit()

    now = base_time + timedelta(hours=1)

    # Total must only count public votes (5)
    page1 = service.list_public(page=1, page_size=2, now=now)
    assert page1.total == 5
    assert len(page1.items) == 2
    # Ordered by created_at DESC -> vote4, vote3
    assert page1.items[0].title == "公开投票4"
    assert page1.items[1].title == "公开投票3"

    # Page 2 -> vote2, vote1
    page2 = service.list_public(page=2, page_size=2, now=now)
    assert len(page2.items) == 2
    assert page2.items[0].title == "公开投票2"
    assert page2.items[1].title == "公开投票1"

    # Page 3 -> vote0
    page3 = service.list_public(page=3, page_size=2, now=now)
    assert len(page3.items) == 1
    assert page3.items[0].title == "公开投票0"

    # Page 4 (beyond end) -> empty items, total unchanged
    page4 = service.list_public(page=4, page_size=2, now=now)
    assert page4.items == []
    assert page4.total == 5

    # Invalid pagination rejected
    with pytest.raises(VoteServiceError) as exc_page:
        service.list_public(page=0, page_size=20, now=now)
    assert exc_page.value.code == "invalid_pagination"

    with pytest.raises(VoteServiceError) as exc_size:
        service.list_public(page=1, page_size=101, now=now)
    assert exc_size.value.code == "invalid_pagination"


def test_dynamic_status_mapping_on_queries():
    session, service = _setup_env()
    creator = User(email="creator@example.com", role="student", status="active")
    session.add(creator)
    session.commit()

    t0 = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    closes_at = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    vote_active = VoteRecord(
        creator_id=creator.id,
        title="活跃投票",
        scope="public",
        closes_at=closes_at,
        status="open",
        created_at=t0,
    )
    opt_a1 = VoteOption(vote_id=vote_active.id, label="A", position=0)
    opt_a2 = VoteOption(vote_id=vote_active.id, label="B", position=1)

    vote_published = VoteRecord(
        creator_id=creator.id,
        title="已公示投票",
        scope="public",
        closes_at=closes_at,
        status="published",
        created_at=t0,
    )
    opt_p1 = VoteOption(vote_id=vote_published.id, label="A", position=0)
    opt_p2 = VoteOption(vote_id=vote_published.id, label="B", position=1)

    snap_published = VoteResultSnapshot(
        vote_id=vote_published.id,
        version=1,
        counts_json=json.dumps({opt_p1.id: 0, opt_p2.id: 0}),
        total=0,
        result_digest=b"\x00" * 32,
        signature=b"\x00" * 64,
        signer_certificate=b"CERT",
        signer_public_key=b"\x04" + b"\x00" * 64,
        published_at=t0,
        is_final=True,
    )
    vote_published.final_snapshot_id = snap_published.id

    session.add_all([vote_active, opt_a1, opt_a2, vote_published, opt_p1, opt_p2, snap_published])
    session.commit()

    # Query before closes_at: status is "open"
    res_before = service.get_public(vote_id=vote_active.id, now=datetime(2026, 9, 10, 11, 59, 59, tzinfo=timezone.utc))
    assert res_before.status == "open"

    # Query exactly at closes_at: dynamically mapped to "closed"
    res_exact = service.get_public(vote_id=vote_active.id, now=closes_at)
    assert res_exact.status == "closed"

    # Query after closes_at: dynamically mapped to "closed"
    res_after = service.get_public(vote_id=vote_active.id, now=datetime(2026, 9, 10, 13, 0, 0, tzinfo=timezone.utc))
    assert res_after.status == "closed"

    # Verify database was NOT mutated by GET
    db_vote = session.get(VoteRecord, vote_active.id)
    assert db_vote.status == "open"

    # Published vote retains "published" even after closes_at
    res_pub = service.get_public(vote_id=vote_published.id, now=datetime(2026, 9, 10, 13, 0, 0, tzinfo=timezone.utc))
    assert res_pub.status == "published"


def test_get_public_not_found_and_hidden_scopes():
    session, service = _setup_env()
    creator = User(email="creator2@example.com", role="student", status="active")
    session.add(creator)
    session.commit()

    now = datetime.now(timezone.utc)
    class_unit = VoteScopeUnit(kind="class", name="隐藏范围班级", active=True)
    session.add(class_unit)
    session.commit()
    class_vote = VoteRecord(
        creator_id=creator.id,
        title="班级秘密投票",
        scope="class",
        scope_id=class_unit.id,
        closes_at=now + timedelta(days=1),
        status="open",
        created_at=now,
    )
    session.add(class_vote)
    session.commit()

    # Non-existent vote returns vote_not_found (404)
    with pytest.raises(VoteServiceError) as exc1:
        service.get_public(vote_id="non-existent-id", now=now)
    assert exc1.value.code == "vote_not_found"

    # Non-public vote returns vote_not_found (404)
    with pytest.raises(VoteServiceError) as exc2:
        service.get_public(vote_id=class_vote.id, now=now)
    assert exc2.value.code == "vote_not_found"
