import pytest
from sqlalchemy.orm import sessionmaker

from app.db.seed_demo import (
    DEMO_CLASS_ID,
    DEMO_GROUP_ID,
    seed_demo_scope_data,
)
from app.db.session import create_db_engine, init_database
from app.models.user import User
from app.models.vote import VoteScopeMember, VoteScopeUnit


def _make_session():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()


def test_demo_seed_requires_explicit_opt_in(monkeypatch):
    session = _make_session()
    monkeypatch.delenv("CRYPTOCAMPUS_ALLOW_DEMO_SEED", raising=False)
    monkeypatch.setenv("CRYPTOCAMPUS_ENV", "development")
    with pytest.raises(RuntimeError, match="显式设置"):
        seed_demo_scope_data(session)


def test_demo_seed_is_forbidden_in_production(monkeypatch):
    session = _make_session()
    monkeypatch.setenv("CRYPTOCAMPUS_ALLOW_DEMO_SEED", "1")
    monkeypatch.setenv("CRYPTOCAMPUS_ENV", "production")
    with pytest.raises(RuntimeError, match="生产环境禁止"):
        seed_demo_scope_data(session)


def test_demo_seed_creates_idempotent_scope_memberships(monkeypatch):
    session = _make_session()
    monkeypatch.setenv("CRYPTOCAMPUS_ALLOW_DEMO_SEED", "1")
    monkeypatch.setenv("CRYPTOCAMPUS_ENV", "development")

    first = seed_demo_scope_data(session)
    second = seed_demo_scope_data(session)

    assert first == {"users": 3, "scopes": 2, "memberships": 6}
    assert second == {"users": 0, "scopes": 0, "memberships": 0}
    assert session.query(User).filter(User.email.like("%@example.edu")).count() == 3
    assert session.get(VoteScopeUnit, DEMO_CLASS_ID).kind == "class"
    assert session.get(VoteScopeUnit, DEMO_GROUP_ID).kind == "group"
    assert session.query(VoteScopeMember).count() == 6
