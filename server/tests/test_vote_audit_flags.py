from datetime import datetime, timezone
import hashlib
import uuid
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.models.admin_audit import AdminAuditEntry
from app.models.user import User
from app.models.vote import VoteRecord
from app.models.vote_audit import VoteAuditFlag
from app.services.admin_audit import AdminAuditChainService
from app.services.vote_audit_flags import VoteAuditFlagError, VoteAuditFlagService


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def crypto_engine():
    return DeterministicMockCryptoEngine()


@pytest.fixture
def audit_chain_service(crypto_engine):
    return AdminAuditChainService(crypto_engine)


@pytest.fixture
def admin_user(db_session):
    admin = User(
        id=str(uuid.uuid4()),
        email="admin@campus.edu",
        role="admin",
        status="active",
    )
    db_session.add(admin)
    db_session.commit()
    return admin


def _create_vote(db_session, creator_id) -> VoteRecord:
    vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator_id,
        title="Class Representative Election",
        description="Vote for representative",
        scope="public",
        closes_at=datetime.now(timezone.utc),
        status="open",
    )
    db_session.add(vote)
    db_session.commit()
    return vote


def test_flag_vote_success_creates_flag_and_audit(db_session, crypto_engine, audit_chain_service, admin_user):
    vote = _create_vote(db_session, admin_user.id)
    service = VoteAuditFlagService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    now = datetime.now(timezone.utc)
    reason = "Abnormal ballot concentration detected"

    result = service.flag(
        vote_id=vote.id,
        actor_id=admin_user.id,
        reason=reason,
        now=now,
    )
    db_session.commit()

    assert result == {"accepted": True}

    # Verify VoteRecord was untouched
    fresh_vote = db_session.get(VoteRecord, vote.id)
    assert fresh_vote.status == "open"
    assert fresh_vote.title == "Class Representative Election"

    # Verify VoteAuditFlag created
    flags = list(db_session.execute(select(VoteAuditFlag)).scalars().all())
    assert len(flags) == 1
    flag = flags[0]
    assert flag.vote_id == vote.id
    assert flag.actor_id == admin_user.id
    expected_reason_hash = crypto_engine.sm3_digest(reason.strip().encode("utf-8"))
    assert flag.reason_hash == expected_reason_hash

    # Verify AdminAuditEntry created
    entries = list(db_session.execute(select(AdminAuditEntry)).scalars().all())
    assert len(entries) == 1
    entry = entries[0]
    assert entry.action == "vote.audit.flag"
    assert entry.target == f"vote:{vote.id}"
    assert entry.actor_id == admin_user.id


def test_flag_vote_idempotent_no_duplicate_flag_or_audit(db_session, crypto_engine, audit_chain_service, admin_user):
    vote = _create_vote(db_session, admin_user.id)
    service = VoteAuditFlagService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    now = datetime.now(timezone.utc)
    reason = "Abnormal ballot pattern"

    # First flag
    res1 = service.flag(vote_id=vote.id, actor_id=admin_user.id, reason=reason, now=now)
    db_session.commit()
    assert res1 == {"accepted": True}

    # Second flag with same actor and reason
    res2 = service.flag(vote_id=vote.id, actor_id=admin_user.id, reason=reason, now=now)
    db_session.commit()
    assert res2 == {"accepted": True}

    # Only 1 flag and 1 audit entry
    flags = list(db_session.execute(select(VoteAuditFlag)).scalars().all())
    assert len(flags) == 1
    entries = list(db_session.execute(select(AdminAuditEntry)).scalars().all())
    assert len(entries) == 1


def test_flag_vote_not_found(db_session, crypto_engine, audit_chain_service, admin_user):
    service = VoteAuditFlagService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    now = datetime.now(timezone.utc)
    with pytest.raises(VoteAuditFlagError) as exc_info:
        service.flag(
            vote_id=str(uuid.uuid4()),
            actor_id=admin_user.id,
            reason="Test reason",
            now=now,
        )
    assert exc_info.value.code == "not_found"


def test_flag_vote_invalid_reason(db_session, crypto_engine, audit_chain_service, admin_user):
    vote = _create_vote(db_session, admin_user.id)
    service = VoteAuditFlagService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    now = datetime.now(timezone.utc)

    # Empty reason
    with pytest.raises(VoteAuditFlagError) as exc_info:
        service.flag(vote_id=vote.id, actor_id=admin_user.id, reason="   ", now=now)
    assert exc_info.value.code == "validation_error"

    # Too long reason (> 500)
    with pytest.raises(VoteAuditFlagError) as exc_info:
        service.flag(vote_id=vote.id, actor_id=admin_user.id, reason="x" * 501, now=now)
    assert exc_info.value.code == "validation_error"
