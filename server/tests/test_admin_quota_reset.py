from datetime import datetime, timezone
import hashlib
import uuid
import pytest

from app.crypto.mock import MockCryptoEngine
from app.models.admin_audit import AdminAuditEntry
from app.models.admin_governance import AdminQuotaResetIdempotency
from app.models.credential import CredentialLedger
from app.models.user import User
from app.services.admin_audit import AdminAuditChainService
from app.services.quota import QuotaError, QuotaService


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


def _create_user(session, email: str, role: str = "student", status: str = "active") -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        role=role,
        status=status,
    )
    session.add(u)
    session.commit()
    return u


def test_admin_quota_reset_success_and_chain_audit(db_session) -> None:
    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)
    quota_service = QuotaService(
        session=db_session,
        digest=engine.sm3_digest,
        audit_chain_service=chain_service,
    )

    admin = _create_user(db_session, "admin_q@campus.edu", role="admin")
    target = _create_user(db_session, "target_q@campus.edu", role="student")

    now = datetime(2026, 9, 10, 14, 0, 0, tzinfo=timezone.utc)
    period = now.date().isoformat()

    # Seed some used quotas
    ledger_entry = CredentialLedger(
        user_id=target.id,
        service="drop",
        period=period,
        issued_count=5,
    )
    db_session.add(ledger_entry)
    db_session.commit()

    idemp_key = "test-quota-reset-key-12345"
    quotas = quota_service.reset(target.id, admin.id, idemp_key, now)

    # Check quotas reset to 0
    drop_quota = next(q for q in quotas if q.resource == "drop")
    assert drop_quota.used == 0

    # Check DB idempotency record
    key_hash = engine.sm3_digest(idemp_key.encode("utf-8"))
    idemp_rec = db_session.query(AdminQuotaResetIdempotency).filter_by(
        actor_id=admin.id, key_hash=key_hash
    ).first()
    assert idemp_rec is not None
    assert idemp_rec.target_user_id == target.id

    # Check AdminAuditEntry
    audit_entry = db_session.query(AdminAuditEntry).filter_by(
        actor_id=admin.id, action="user.quota.reset"
    ).first()
    assert audit_entry is not None
    assert audit_entry.target == f"user:{target.id}"


def test_admin_quota_reset_idempotent_replay(db_session) -> None:
    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)
    quota_service = QuotaService(
        session=db_session,
        digest=engine.sm3_digest,
        audit_chain_service=chain_service,
    )

    admin = _create_user(db_session, "admin_replay@campus.edu", role="admin")
    target = _create_user(db_session, "target_replay@campus.edu", role="student")
    now = datetime(2026, 9, 10, 14, 0, 0, tzinfo=timezone.utc)
    idemp_key = "replay-key-must-be-long-enough"

    # First call
    first_res = quota_service.reset(target.id, admin.id, idemp_key, now)
    audit_count_before = db_session.query(AdminAuditEntry).count()

    # Replay with identical key & target
    second_res = quota_service.reset(target.id, admin.id, idemp_key, now)

    assert [q.model_dump() for q in first_res] == [q.model_dump() for q in second_res]
    # No second audit log entry created!
    assert db_session.query(AdminAuditEntry).count() == audit_count_before


def test_admin_quota_reset_conflict_different_target(db_session) -> None:
    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)
    quota_service = QuotaService(
        session=db_session,
        digest=engine.sm3_digest,
        audit_chain_service=chain_service,
    )

    admin = _create_user(db_session, "admin_conflict@campus.edu", role="admin")
    target1 = _create_user(db_session, "target1@campus.edu", role="student")
    target2 = _create_user(db_session, "target2@campus.edu", role="student")
    now = datetime(2026, 9, 10, 14, 0, 0, tzinfo=timezone.utc)
    idemp_key = "conflict-key-same-for-both-targets"

    # First target
    quota_service.reset(target1.id, admin.id, idemp_key, now)

    # Reusing same key for different target raises conflict
    with pytest.raises(QuotaError) as exc_info:
        quota_service.reset(target2.id, admin.id, idemp_key, now)
    assert exc_info.value.code == "conflict"


def test_admin_quota_reset_key_length_validation(db_session) -> None:
    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)
    quota_service = QuotaService(
        session=db_session,
        digest=engine.sm3_digest,
        audit_chain_service=chain_service,
    )

    admin = _create_user(db_session, "admin_short@campus.edu", role="admin")
    target = _create_user(db_session, "target_short@campus.edu", role="student")
    now = datetime(2026, 9, 10, 14, 0, 0, tzinfo=timezone.utc)

    with pytest.raises(QuotaError) as exc_info:
        quota_service.reset(target.id, admin.id, "short", now)
    assert exc_info.value.code == "idempotency_invalid"
