from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import sessionmaker

from app.db.session import create_db_engine, init_database
from app.models.user import User
from app.models.vote import VoteRecord, VoteScopeMember, VoteScopeUnit
from app.services.vote_scope import (
    DatabaseScopeMembershipProvider,
    DefaultVoteScopePolicy,
    VoteScopeError,
)


def _setup_scope_env():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    sm = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = sm()
    provider = DatabaseScopeMembershipProvider(session)
    policy = DefaultVoteScopePolicy(session, membership_provider=provider)
    return session, policy, provider


def _add_scope(session, *, kind: str, name: str, active: bool = True) -> VoteScopeUnit:
    unit = VoteScopeUnit(kind=kind, name=name, active=active)
    session.add(unit)
    session.commit()
    return unit


def _add_member(session, *, scope_id: str, user_id: str) -> None:
    session.add(VoteScopeMember(scope_id=scope_id, user_id=user_id))
    session.commit()


def test_database_membership_provider_reads_scope_and_membership():
    session, _, provider = _setup_scope_env()
    student = User(email="member@example.com", role="student", status="active")
    session.add(student)
    session.commit()
    class_unit = _add_scope(session, kind="class", name="软件工程 1 班")
    _add_member(session, scope_id=class_unit.id, user_id=student.id)

    assert provider.get_scope(scope_id=class_unit.id).kind == "class"
    assert provider.is_member(user_id=student.id, scope_id=class_unit.id) is True
    assert provider.is_member(user_id="missing-user", scope_id=class_unit.id) is False


def test_scope_policy_create_permissions():
    session, policy, _ = _setup_scope_env()
    student = User(email="student@example.com", role="student", status="active")
    outsider = User(email="outsider@example.com", role="student", status="active")
    frozen = User(email="frozen@example.com", role="student", status="frozen")
    session.add_all([student, outsider, frozen])
    session.commit()
    class_unit = _add_scope(session, kind="class", name="计算机 2301")
    group_unit = _add_scope(session, kind="group", name="密码学社")
    inactive_unit = _add_scope(session, kind="group", name="已停用社团", active=False)
    _add_member(session, scope_id=class_unit.id, user_id=student.id)
    _add_member(session, scope_id=group_unit.id, user_id=student.id)
    _add_member(session, scope_id=inactive_unit.id, user_id=student.id)

    policy.require_can_create(user_id=student.id, scope="public", scope_id=None)
    policy.require_can_create(user_id=student.id, scope="class", scope_id=class_unit.id)
    policy.require_can_create(user_id=student.id, scope="group", scope_id=group_unit.id)

    with pytest.raises(VoteScopeError, match="不应携带") as exc_public_id:
        policy.require_can_create(user_id=student.id, scope="public", scope_id=class_unit.id)
    assert exc_public_id.value.code == "scope_id_forbidden"

    with pytest.raises(VoteScopeError) as exc_required:
        policy.require_can_create(user_id=student.id, scope="class", scope_id=None)
    assert exc_required.value.code == "scope_id_required"

    with pytest.raises(VoteScopeError) as exc_outsider:
        policy.require_can_create(user_id=outsider.id, scope="class", scope_id=class_unit.id)
    assert exc_outsider.value.code == "not_scope_member"

    with pytest.raises(VoteScopeError) as exc_mismatch:
        policy.require_can_create(user_id=student.id, scope="class", scope_id=group_unit.id)
    assert exc_mismatch.value.code == "scope_kind_mismatch"

    with pytest.raises(VoteScopeError) as exc_inactive_scope:
        policy.require_can_create(user_id=student.id, scope="group", scope_id=inactive_unit.id)
    assert exc_inactive_scope.value.code == "scope_inactive"

    with pytest.raises(VoteScopeError) as exc_user_inactive:
        policy.require_can_create(user_id=frozen.id, scope="public", scope_id=None)
    assert exc_user_inactive.value.code == "user_inactive"

    with pytest.raises(VoteScopeError) as exc_invalid:
        policy.require_can_create(user_id=student.id, scope="unknown", scope_id=None)
    assert exc_invalid.value.code == "invalid_scope"


def test_scope_policy_issue_permissions_use_persisted_vote_scope():
    session, policy, _ = _setup_scope_env()
    member = User(email="member2@example.com", role="student", status="active")
    outsider = User(email="outsider2@example.com", role="student", status="active")
    session.add_all([member, outsider])
    session.commit()
    class_unit = _add_scope(session, kind="class", name="网络工程 2301")
    _add_member(session, scope_id=class_unit.id, user_id=member.id)

    now = datetime.now(timezone.utc)
    public_vote = VoteRecord(
        creator_id=member.id,
        title="公开投票",
        scope="public",
        scope_id=None,
        closes_at=now + timedelta(days=1),
        status="open",
        created_at=now,
    )
    class_vote = VoteRecord(
        creator_id=member.id,
        title="班级投票",
        scope="class",
        scope_id=class_unit.id,
        closes_at=now + timedelta(days=1),
        status="open",
        created_at=now,
    )
    session.add_all([public_vote, class_vote])
    session.commit()

    policy.require_can_issue(user_id=member.id, vote_id=public_vote.id)
    policy.require_can_issue(user_id=member.id, vote_id=class_vote.id)

    with pytest.raises(VoteScopeError) as exc_outsider:
        policy.require_can_issue(user_id=outsider.id, vote_id=class_vote.id)
    assert exc_outsider.value.code == "not_scope_member"

    with pytest.raises(VoteScopeError) as exc_novote:
        policy.require_can_issue(user_id=member.id, vote_id="non-existent-vote-id")
    assert exc_novote.value.code == "vote_not_found"
