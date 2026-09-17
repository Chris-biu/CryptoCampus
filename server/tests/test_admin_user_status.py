from datetime import datetime, timezone
import hashlib
import uuid
import pytest

from app.crypto.mock import MockCryptoEngine
from app.models.admin_audit import AdminAuditEntry
from app.models.session import UserSession
from app.models.user import User
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.account_lifecycle import AccountGovernanceError, AccountGovernanceService
from app.services.admin_audit import AdminAuditChainService


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


def _user(db_session, email: str, role: str = "student", status: str = "active") -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        role=role,
        status=status,
    )
    db_session.add(u)
    db_session.commit()
    return u


def test_freeze_revokes_sessions_and_writes_chain_audit(db_session) -> None:
    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)
    key_cache = PrivateKeyUnlockCache()
    service = AccountGovernanceService(
        session=db_session,
        crypto_engine=engine,
        key_cache=key_cache,
        audit_chain_service=chain_service,
    )

    admin = _user(db_session, "admin_status@campus.edu", role="admin")
    target = _user(db_session, "target_status@campus.edu", role="student", status="active")

    # Add active session and key cache
    s1 = UserSession(
        user_id=target.id,
        device="dev1",
        ip="127.0.0.1",
        refresh_token_hash=b"h1" * 16,
        expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        last_active_at=datetime(2026, 9, 10, tzinfo=timezone.utc),
        revoked=False,
    )
    db_session.add(s1)
    db_session.commit()
    key_cache.put(target.id, b"secret_key", datetime(2030, 1, 1, tzinfo=timezone.utc))

    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    res = service.update_status(admin.id, target.id, "frozen", "Terms of service violation", now)

    assert res.status == "frozen"
    db_session.refresh(s1)
    assert s1.revoked is True
    assert key_cache.get(target.id, now) is None

    # Check AdminAuditEntry
    chain_entry = db_session.query(AdminAuditEntry).filter_by(
        actor_id=admin.id, action="user.status.update"
    ).first()
    assert chain_entry is not None
    assert chain_entry.target == f"user:{target.id}"


def test_unfreeze_does_not_resurrect_revoked_sessions(db_session) -> None:
    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)
    key_cache = PrivateKeyUnlockCache()
    service = AccountGovernanceService(
        session=db_session,
        crypto_engine=engine,
        key_cache=key_cache,
        audit_chain_service=chain_service,
    )

    admin = _user(db_session, "admin_unf@campus.edu", role="admin")
    target = _user(db_session, "target_unf@campus.edu", role="student", status="frozen")

    s1 = UserSession(
        user_id=target.id,
        device="dev1",
        ip="127.0.0.1",
        refresh_token_hash=b"h1" * 16,
        expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        last_active_at=datetime(2026, 9, 10, tzinfo=timezone.utc),
        revoked=True,
    )
    db_session.add(s1)
    db_session.commit()

    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    res = service.update_status(admin.id, target.id, "active", "Appeal accepted", now)

    assert res.status == "active"
    db_session.refresh(s1)
    # Session must remain revoked
    assert s1.revoked is True


def test_status_update_idempotent_no_duplicate_audit(db_session) -> None:
    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)
    key_cache = PrivateKeyUnlockCache()
    service = AccountGovernanceService(
        session=db_session,
        crypto_engine=engine,
        key_cache=key_cache,
        audit_chain_service=chain_service,
    )

    admin = _user(db_session, "admin_idem@campus.edu", role="admin")
    target = _user(db_session, "target_idem@campus.edu", role="student", status="frozen")
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    count_before = db_session.query(AdminAuditEntry).count()
    res = service.update_status(admin.id, target.id, "frozen", "Already frozen", now)
    assert res.status == "frozen"
    assert db_session.query(AdminAuditEntry).count() == count_before
