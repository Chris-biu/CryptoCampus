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


def test_update_role_success_revokes_sessions_and_audits(db_session) -> None:
    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)
    key_cache = PrivateKeyUnlockCache()
    service = AccountGovernanceService(
        session=db_session,
        crypto_engine=engine,
        key_cache=key_cache,
        audit_chain_service=chain_service,
    )

    admin = _user(db_session, "admin_role@campus.edu", role="admin")
    target = _user(db_session, "student_to_promote@campus.edu", role="student")

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
    res = service.update_role(
        actor_id=admin.id,
        target_id=target.id,
        new_role="teacher",
        reason="Promoted to faculty member",
        now=now,
    )

    assert res.role == "teacher"
    db_session.refresh(s1)
    assert s1.revoked is True
    assert key_cache.get(target.id, now) is None

    audit_entry = db_session.query(AdminAuditEntry).filter_by(
        actor_id=admin.id, action="user.role.update"
    ).first()
    assert audit_entry is not None
    assert audit_entry.target == f"user:{target.id}"


def test_update_role_protects_last_active_teacher(db_session) -> None:
    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)
    key_cache = PrivateKeyUnlockCache()
    service = AccountGovernanceService(
        session=db_session,
        crypto_engine=engine,
        key_cache=key_cache,
        audit_chain_service=chain_service,
    )

    admin = _user(db_session, "admin_role_prot@campus.edu", role="admin")
    # Only one active teacher in system
    teacher = _user(db_session, "sole_teacher@campus.edu", role="teacher", status="active")

    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    # Demoting the sole active teacher must be rejected with 409 (last_teacher_protected)
    with pytest.raises(AccountGovernanceError) as exc_info:
        service.update_role(
            actor_id=admin.id,
            target_id=teacher.id,
            new_role="student",
            reason="Demotion attempt",
            now=now,
        )
    assert exc_info.value.code == "last_teacher_protected"

    # If another active teacher exists, demotion is allowed
    second_teacher = _user(db_session, "second_teacher@campus.edu", role="teacher", status="active")
    res = service.update_role(
        actor_id=admin.id,
        target_id=teacher.id,
        new_role="student",
        reason="Demotion allowed now",
        now=now,
    )
    assert res.role == "student"


def test_update_role_idempotent_no_duplicate_audit(db_session) -> None:
    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)
    key_cache = PrivateKeyUnlockCache()
    service = AccountGovernanceService(
        session=db_session,
        crypto_engine=engine,
        key_cache=key_cache,
        audit_chain_service=chain_service,
    )

    admin = _user(db_session, "admin_role_idem@campus.edu", role="admin")
    student = _user(db_session, "student_idem@campus.edu", role="student")
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    count_before = db_session.query(AdminAuditEntry).count()
    res = service.update_role(
        actor_id=admin.id,
        target_id=student.id,
        new_role="student",
        reason="No change",
        now=now,
    )
    assert res.role == "student"
    assert db_session.query(AdminAuditEntry).count() == count_before
