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
from app.models.audit import AuditLog, RevocationLog
from app.models.hole import HolePost
from app.models.user import User
from app.services.admin_audit import AdminAuditChainService
from app.services.hole_governance import HoleContentGovernanceService


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


@pytest.fixture
def test_env():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    crypto_engine = DeterministicMockCryptoEngine()
    audit_chain_service = AdminAuditChainService(crypto_engine)

    # Seed admin and author
    session = session_factory()
    admin = User(
        id=str(uuid.uuid4()),
        email="admin@campus.edu",
        role="admin",
        status="active",
    )
    author = User(
        id=str(uuid.uuid4()),
        email="author@campus.edu",
        role="student",
        status="active",
    )
    session.add_all([admin, author])
    session.commit()

    service = HoleContentGovernanceService(
        session_factory=session_factory,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )

    return {
        "engine": engine,
        "session_factory": session_factory,
        "crypto_engine": crypto_engine,
        "audit_chain_service": audit_chain_service,
        "admin": admin,
        "author": author,
        "service": service,
    }


def _create_published_post(session_factory, author_id) -> HolePost:
    session = session_factory()
    post = HolePost(
        id=str(uuid.uuid4()),
        content="This is anonymous hole post content",
        credential_sn=b"credential_sn_12345678",
        credential_service="hole_post",
        credential_period="2026-09",
        credential_signature=b"sig" * 16,
        credential_prefix="ABCD",
        credential_valid=True,
        status="published",
        created_at=datetime.now(timezone.utc),
    )
    session.add(post)
    session.commit()
    session.close()
    return post


def test_hole_withdraw_writes_admin_audit_chain_entry(test_env):
    session_factory = test_env["session_factory"]
    service = test_env["service"]
    admin = test_env["admin"]

    post = _create_published_post(session_factory, test_env["author"].id)
    now = datetime.now(timezone.utc)

    entry_dto = service.withdraw_post(
        post_id=post.id,
        reason="Violation of campus policies",
        operator_id=admin.id,
        now=now,
    )
    assert entry_dto is not None

    session = session_factory()
    # Check post status
    updated_post = session.get(HolePost, post.id)
    assert updated_post.status == "withdrawn"
    assert updated_post.credential_valid is False

    # Check RevocationLog
    rev_logs = list(session.execute(select(RevocationLog)).scalars().all())
    assert len(rev_logs) == 1

    # Check AuditLog
    audits = list(session.execute(select(AuditLog)).scalars().all())
    assert len(audits) == 1

    # Check AdminAuditEntry
    admin_audits = list(session.execute(select(AdminAuditEntry)).scalars().all())
    assert len(admin_audits) == 1
    admin_entry = admin_audits[0]
    assert admin_entry.action == "hole.post.withdraw"
    assert admin_entry.target == f"hole_post:{post.id}"
    assert admin_entry.actor_id == admin.id
    assert admin_entry.detail_hash == audits[0].detail_hash
    session.close()


def test_hole_withdraw_idempotent_no_duplicate_admin_audit(test_env):
    session_factory = test_env["session_factory"]
    service = test_env["service"]
    admin = test_env["admin"]

    post = _create_published_post(session_factory, test_env["author"].id)
    now = datetime.now(timezone.utc)

    # First withdraw
    service.withdraw_post(
        post_id=post.id,
        reason="Violation 1",
        operator_id=admin.id,
        now=now,
    )

    # Second withdraw (idempotent replay)
    service.withdraw_post(
        post_id=post.id,
        reason="Violation 1",
        operator_id=admin.id,
        now=now,
    )

    session = session_factory()
    admin_audits = list(session.execute(select(AdminAuditEntry)).scalars().all())
    assert len(admin_audits) == 1  # Exactly 1, no duplicate audit
    session.close()
