import base64
from datetime import datetime, timezone
import hashlib
import uuid
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.db.session import create_session_factory, init_database
from app.models.audit import AuditLog, RevocationLog
from app.models.hole import HolePost
from app.models.user import User
from app.services.hole_governance import (
    HoleContentGovernanceService,
    HoleGovernanceError,
    RevocationEntryDTO,
)
from app.services.revocation_log import (
    GENESIS_HASH,
    calculate_revocation_hash,
    canonical_utc,
    order_and_verify_chain,
)


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def __init__(self) -> None:
        super().__init__()
        self._error_to_raise: CryptoBridgeError | None = None

    def set_error_to_raise(self, error: CryptoBridgeError | None) -> None:
        self._error_to_raise = error

    def sm3_digest(self, message: bytes) -> bytes:
        if self._error_to_raise is not None:
            raise self._error_to_raise
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


def create_user(
    session: Session,
    *,
    role: str = "admin",
    status: str = "active",
    email: str | None = None,
) -> User:
    uid = str(uuid4())
    user = User(
        id=uid,
        email=email or f"user-{uid[:8]}@campus.edu",
        role=role,
        status=status,
        salt_a=b"salt_a",
        auth_hash=b"auth_hash",
        salt_k=b"salt_k",
        enc_sk=b"enc_sk",
        pubkey=b"pubkey",
        cert_serial=f"cert-{uid[:8]}",
    )
    session.add(user)
    session.commit()
    return user


def create_post(
    session: Session,
    *,
    content: str = "Initial hole post content",
    credential_sn: bytes = b"sn_1234567890123456",
    credential_service: str = "hole_post",
    credential_period: str = "2026-09",
    status: str = "published",
    credential_valid: bool = True,
) -> HolePost:
    pid = str(uuid4())
    post = HolePost(
        id=pid,
        content=content,
        credential_sn=credential_sn,
        credential_service=credential_service,
        credential_period=credential_period,
        credential_signature=b"\x11" * 64,
        credential_prefix="cc",
        credential_valid=credential_valid,
        status=status,
    )
    session.add(post)
    session.commit()
    return post


@pytest.fixture
def governance_setup(db_engine):
    init_database(db_engine)
    session_factory = create_session_factory(db_engine)
    crypto = DeterministicMockCryptoEngine()
    service = HoleContentGovernanceService(session_factory, crypto)
    return session_factory, crypto, service


def test_admin_withdraw_post_success(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, content="Top Secret Content")

    now = datetime(2026, 9, 9, 14, 30, 0, tzinfo=timezone.utc)
    reason = "  Violates community rule #3  "
    expected_norm_reason = "Violates community rule #3"

    dto = service.withdraw_post(
        post_id=post.id,
        reason=reason,
        operator_id=admin.id,
        now=now,
    )

    expected_hash_prev_b64 = base64.b64encode(GENESIS_HASH).decode("ascii")
    expected_hash_curr = calculate_revocation_hash(
        crypto,
        hash_prev=GENESIS_HASH,
        sn=b"sn_1234567890123456",
        reason=expected_norm_reason,
        timestamp=now,
    )
    expected_hash_curr_b64 = base64.b64encode(expected_hash_curr).decode("ascii")

    # Verify DTO
    assert isinstance(dto, RevocationEntryDTO)
    assert dto.sn == post.credential_sn.hex().lower()
    assert dto.reason == expected_norm_reason
    assert dto.hash_prev == expected_hash_prev_b64
    assert dto.hash_curr == expected_hash_curr_b64
    assert dto.timestamp == now

    # Verify database state using a fresh session
    with session_factory() as verify_session:
        db_post = verify_session.get(HolePost, post.id)
        assert db_post is not None
        assert db_post.status == "withdrawn"
        assert db_post.credential_valid is False
        assert db_post.content == "Top Secret Content"
        assert db_post.credential_sn == b"sn_1234567890123456"

        rev_logs = list(verify_session.execute(select(RevocationLog)).scalars().all())
        assert len(rev_logs) == 1
        rev_entry = rev_logs[0]
        assert bytes(rev_entry.sn) == b"sn_1234567890123456"
        assert rev_entry.reason == expected_norm_reason
        assert rev_entry.operator == admin.id
        assert bytes(rev_entry.hash_prev) == GENESIS_HASH
        assert bytes(rev_entry.hash_curr) == expected_hash_curr
        assert canonical_utc(rev_entry.ts) == canonical_utc(now)

        audit_logs = list(verify_session.execute(select(AuditLog)).scalars().all())
        assert len(audit_logs) == 1
        audit_entry = audit_logs[0]
        assert audit_entry.actor == admin.id
        assert audit_entry.action == "hole.post.withdraw"
        assert audit_entry.target == f"hole_post:{post.id}"
        assert canonical_utc(audit_entry.ts) == canonical_utc(now)

        expected_audit_hash = crypto.sm3_digest(
            b"CryptoCampus-Hole-Withdraw-Audit-v1\x00"
            + uuid.UUID(post.id).bytes
            + uuid.UUID(admin.id).bytes
            + expected_hash_curr
        )
        assert bytes(audit_entry.detail_hash) == expected_audit_hash


def test_teacher_withdraw_post_success(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        teacher = create_user(session, role="teacher", status="active")
        post = create_post(session, content="Post withdrawn by teacher")

    now = datetime(2026, 9, 9, 15, 0, 0, tzinfo=timezone.utc)
    reason = "Inappropriate teacher post"

    dto = service.withdraw_post(
        post_id=post.id,
        reason=reason,
        operator_id=teacher.id,
        now=now,
    )

    assert isinstance(dto, RevocationEntryDTO)
    assert dto.reason == reason

    with session_factory() as verify_session:
        db_post = verify_session.get(HolePost, post.id)
        assert db_post.status == "withdrawn"
        assert db_post.credential_valid is False

        audit_logs = list(verify_session.execute(select(AuditLog)).scalars().all())
        assert len(audit_logs) == 1
        assert audit_logs[0].actor == teacher.id


def test_student_cannot_withdraw(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        student = create_user(session, role="student", status="active")
        post = create_post(session)

    now = datetime(2026, 9, 9, 15, 30, 0, tzinfo=timezone.utc)

    with pytest.raises(HoleGovernanceError) as exc_info:
        service.withdraw_post(
            post_id=post.id,
            reason="Student attempt",
            operator_id=student.id,
            now=now,
        )

    assert exc_info.value.code == "forbidden"

    with session_factory() as verify_session:
        db_post = verify_session.get(HolePost, post.id)
        assert db_post.status == "published"
        assert db_post.credential_valid is True
        assert len(list(verify_session.execute(select(RevocationLog)).scalars().all())) == 0
        assert len(list(verify_session.execute(select(AuditLog)).scalars().all())) == 0


def test_inactive_or_missing_operator(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        frozen_admin = create_user(session, role="admin", status="frozen")
        pending_admin = create_user(session, role="admin", status="pending_deletion")
        post = create_post(session)

    now = datetime(2026, 9, 9, 16, 0, 0, tzinfo=timezone.utc)

    # 1. Frozen admin
    with pytest.raises(HoleGovernanceError) as exc_frozen:
        service.withdraw_post(
            post_id=post.id,
            reason="Withdraw test",
            operator_id=frozen_admin.id,
            now=now,
        )
    assert exc_frozen.value.code == "unauthorized"

    # 2. Pending deletion admin
    with pytest.raises(HoleGovernanceError) as exc_pending:
        service.withdraw_post(
            post_id=post.id,
            reason="Withdraw test",
            operator_id=pending_admin.id,
            now=now,
        )
    assert exc_pending.value.code == "unauthorized"

    # 3. Non-existent operator UUID
    non_existent_id = str(uuid4())
    with pytest.raises(HoleGovernanceError) as exc_missing:
        service.withdraw_post(
            post_id=post.id,
            reason="Withdraw test",
            operator_id=non_existent_id,
            now=now,
        )
    assert exc_missing.value.code == "unauthorized"


def test_nonexistent_post_returns_not_found(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")

    now = datetime(2026, 9, 9, 16, 30, 0, tzinfo=timezone.utc)
    missing_post_id = str(uuid4())

    with pytest.raises(HoleGovernanceError) as exc_info:
        service.withdraw_post(
            post_id=missing_post_id,
            reason="Missing post",
            operator_id=admin.id,
            now=now,
        )
    assert exc_info.value.code == "post_not_found"


def test_invalid_reason_rejected(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session)

    now = datetime(2026, 9, 9, 17, 0, 0, tzinfo=timezone.utc)

    # Whitespace only
    with pytest.raises(HoleGovernanceError) as exc_blank:
        service.withdraw_post(
            post_id=post.id,
            reason="     ",
            operator_id=admin.id,
            now=now,
        )
    assert exc_blank.value.code == "invalid_reason"

    # Empty string
    with pytest.raises(HoleGovernanceError) as exc_empty:
        service.withdraw_post(
            post_id=post.id,
            reason="",
            operator_id=admin.id,
            now=now,
        )
    assert exc_empty.value.code == "invalid_reason"

    # Over 500 chars
    with pytest.raises(HoleGovernanceError) as exc_long:
        service.withdraw_post(
            post_id=post.id,
            reason="x" * 501,
            operator_id=admin.id,
            now=now,
        )
    assert exc_long.value.code == "invalid_reason"


def test_withdraw_idempotency_returns_original(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        teacher = create_user(session, role="teacher", status="active")
        post = create_post(session, content="Idempotency test post")

    ts1 = datetime(2026, 9, 9, 17, 30, 0, tzinfo=timezone.utc)
    reason1 = "Original Reason"

    # First withdrawal
    dto1 = service.withdraw_post(
        post_id=post.id,
        reason=reason1,
        operator_id=admin.id,
        now=ts1,
    )

    # Second withdrawal attempt with different reason, operator, and timestamp
    ts2 = datetime(2026, 9, 9, 18, 0, 0, tzinfo=timezone.utc)
    reason2 = "Different Reason Attempt"

    dto2 = service.withdraw_post(
        post_id=post.id,
        reason=reason2,
        operator_id=teacher.id,
        now=ts2,
    )

    # Idempotent return must match original exactly
    assert dto2.sn == dto1.sn
    assert dto2.reason == "Original Reason"
    assert dto2.hash_prev == dto1.hash_prev
    assert dto2.hash_curr == dto1.hash_curr
    assert dto2.timestamp == ts1

    # Database must retain only 1 RevocationLog and 1 AuditLog
    with session_factory() as verify_session:
        rev_logs = list(verify_session.execute(select(RevocationLog)).scalars().all())
        assert len(rev_logs) == 1
        assert rev_logs[0].reason == "Original Reason"
        assert rev_logs[0].operator == admin.id
        assert canonical_utc(rev_logs[0].ts) == canonical_utc(ts1)

        audit_logs = list(verify_session.execute(select(AuditLog)).scalars().all())
        assert len(audit_logs) == 1
        assert audit_logs[0].actor == admin.id
        assert canonical_utc(audit_logs[0].ts) == canonical_utc(ts1)


def test_past_period_post_can_be_withdrawn(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, credential_period="2026-08")

    now = datetime(2026, 9, 9, 18, 30, 0, tzinfo=timezone.utc)
    dto = service.withdraw_post(
        post_id=post.id,
        reason="Withdraw historical post",
        operator_id=admin.id,
        now=now,
    )

    assert dto.sn == post.credential_sn.hex().lower()
    with session_factory() as verify_session:
        db_post = verify_session.get(HolePost, post.id)
        assert db_post.status == "withdrawn"
        assert db_post.credential_valid is False


def test_invalid_uuid_parameters(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session)

    now = datetime(2026, 9, 9, 19, 0, 0, tzinfo=timezone.utc)

    # Invalid post_id
    with pytest.raises(HoleGovernanceError) as exc_p:
        service.withdraw_post(
            post_id="not-a-valid-uuid",
            reason="Valid reason",
            operator_id=admin.id,
            now=now,
        )
    assert exc_p.value.code == "invalid_param"

    # Invalid operator_id
    with pytest.raises(HoleGovernanceError) as exc_o:
        service.withdraw_post(
            post_id=post.id,
            reason="Valid reason",
            operator_id="not-a-valid-uuid",
            now=now,
        )
    assert exc_o.value.code == "invalid_param"


def test_invalid_service_rejected(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, credential_service="not_hole_post")

    now = datetime(2026, 9, 9, 19, 30, 0, tzinfo=timezone.utc)
    with pytest.raises(HoleGovernanceError) as exc_info:
        service.withdraw_post(
            post_id=post.id,
            reason="Valid reason",
            operator_id=admin.id,
            now=now,
        )
    assert exc_info.value.code == "invalid_service"


def test_multiple_posts_chain_integrity(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post1 = create_post(session, credential_sn=b"sn_1111111111111111")
        post2 = create_post(session, credential_sn=b"sn_2222222222222222")
        post3 = create_post(session, credential_sn=b"sn_3333333333333333")

    ts1 = datetime(2026, 9, 9, 20, 0, 0, tzinfo=timezone.utc)
    ts2 = datetime(2026, 9, 9, 20, 5, 0, tzinfo=timezone.utc)
    ts3 = datetime(2026, 9, 9, 20, 10, 0, tzinfo=timezone.utc)

    dto1 = service.withdraw_post(post_id=post1.id, reason="Reason 1", operator_id=admin.id, now=ts1)
    dto2 = service.withdraw_post(post_id=post2.id, reason="Reason 2", operator_id=admin.id, now=ts2)
    dto3 = service.withdraw_post(post_id=post3.id, reason="Reason 3", operator_id=admin.id, now=ts3)

    # Check chain linkage in DTOs
    assert dto1.hash_prev == base64.b64encode(GENESIS_HASH).decode("ascii")
    assert dto2.hash_prev == dto1.hash_curr
    assert dto3.hash_prev == dto2.hash_curr

    # Check in DB
    with session_factory() as verify_session:
        rev_logs = list(verify_session.execute(select(RevocationLog)).scalars().all())
        assert len(rev_logs) == 3
        # Ensure order_and_verify_chain passes
        ordered = order_and_verify_chain(rev_logs, crypto)
        assert ordered is not None
        assert len(ordered) == 3
        assert [e.sn for e in ordered] == [
            b"sn_1111111111111111",
            b"sn_2222222222222222",
            b"sn_3333333333333333",
        ]


def test_withdrawn_post_without_revocation_log_raises_integrity_error(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        # Inconsistent state: status is withdrawn but no RevocationLog exists
        post = create_post(session, status="withdrawn", credential_valid=False)

    now = datetime(2026, 9, 9, 21, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(HoleGovernanceError) as exc_info:
        service.withdraw_post(
            post_id=post.id,
            reason="Test",
            operator_id=admin.id,
            now=now,
        )
    assert exc_info.value.code == "integrity_error"


def test_published_post_with_existing_revocation_log_raises_integrity_error(governance_setup) -> None:
    session_factory, crypto, service = governance_setup
    sn = b"sn_already_revoked_12"
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, credential_sn=sn, status="published")
        # Inconsistent state: post is published but RevocationLog already exists
        rev = RevocationLog(
            hash_curr=b"\x99" * 32,
            hash_prev=GENESIS_HASH,
            sn=sn,
            reason="Premature revocation",
            operator=admin.id,
            ts=datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc),
        )
        session.add(rev)
        session.commit()

    now = datetime(2026, 9, 9, 21, 30, 0, tzinfo=timezone.utc)
    with pytest.raises(HoleGovernanceError) as exc_info:
        service.withdraw_post(
            post_id=post.id,
            reason="Test",
            operator_id=admin.id,
            now=now,
        )
    assert exc_info.value.code == "integrity_error"
