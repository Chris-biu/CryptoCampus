from datetime import datetime, timezone
import hashlib
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.db.session import create_session_factory, init_database
from app.models.audit import AuditLog, RevocationLog
from app.models.hole import HolePost
from app.models.user import User
from app.services.hole_governance import (
    HoleContentGovernanceService,
    HoleGovernanceError,
)
from app.services.revocation_log import REVOCATION_DOMAIN


class FaultInjectingCryptoEngine(MockCryptoEngine):
    def __init__(self) -> None:
        super().__init__()
        self.fail_on_revocation_hash: bool = False
        self.fail_on_audit_hash: bool = False

    def sm3_digest(self, message: bytes) -> bytes:
        if self.fail_on_revocation_hash and message.startswith(REVOCATION_DOMAIN):
            raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE)
        if self.fail_on_audit_hash and message.startswith(b"CryptoCampus-Hole-Withdraw-Audit-v1\x00"):
            raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE)
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


def create_user(session, *, role: str = "admin", status: str = "active") -> User:
    uid = str(uuid4())
    user = User(
        id=uid,
        email=f"admin-{uid[:8]}@campus.edu",
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
    session,
    *,
    content: str = "Strict original content before rollback",
    credential_sn: bytes = b"sn_rollback_test_123",
) -> HolePost:
    pid = str(uuid4())
    post = HolePost(
        id=pid,
        content=content,
        credential_sn=credential_sn,
        credential_service="hole_post",
        credential_period="2026-09",
        credential_signature=b"\x22" * 64,
        credential_prefix="cc",
        credential_valid=True,
        status="published",
    )
    session.add(post)
    session.commit()
    return post


@pytest.fixture
def rollback_env(db_engine):
    init_database(db_engine)
    session_factory = create_session_factory(db_engine)
    crypto = FaultInjectingCryptoEngine()
    service = HoleContentGovernanceService(session_factory, crypto)
    return session_factory, crypto, service


def test_rollback_on_sm3_revocation_hash_failure(rollback_env) -> None:
    session_factory, crypto, service = rollback_env
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, content="Original Post Content 1")

    # Inject failure during revocation hash calculation
    crypto.fail_on_revocation_hash = True

    now = datetime(2026, 9, 9, 22, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(HoleGovernanceError) as exc_info:
        service.withdraw_post(
            post_id=post.id,
            reason="Rollback reason test",
            operator_id=admin.id,
            now=now,
        )

    assert exc_info.value.code == "engine_unavailable"

    # Verify atomic rollback using independent session
    with session_factory() as verify_session:
        db_post = verify_session.get(HolePost, post.id)
        assert db_post is not None
        assert db_post.status == "published"
        assert db_post.credential_valid is True
        assert db_post.content == "Original Post Content 1"

        rev_logs = list(verify_session.execute(select(RevocationLog)).scalars().all())
        assert len(rev_logs) == 0

        audit_logs = list(verify_session.execute(select(AuditLog)).scalars().all())
        assert len(audit_logs) == 0


def test_rollback_on_sm3_audit_detail_hash_failure(rollback_env) -> None:
    session_factory, crypto, service = rollback_env
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, content="Original Post Content 2")

    # Inject failure during audit detail hash calculation
    crypto.fail_on_audit_hash = True

    now = datetime(2026, 9, 9, 22, 15, 0, tzinfo=timezone.utc)
    with pytest.raises(HoleGovernanceError) as exc_info:
        service.withdraw_post(
            post_id=post.id,
            reason="Audit failure test",
            operator_id=admin.id,
            now=now,
        )

    assert exc_info.value.code == "engine_unavailable"

    # Verify atomic rollback using independent session
    with session_factory() as verify_session:
        db_post = verify_session.get(HolePost, post.id)
        assert db_post is not None
        assert db_post.status == "published"
        assert db_post.credential_valid is True
        assert db_post.content == "Original Post Content 2"

        rev_logs = list(verify_session.execute(select(RevocationLog)).scalars().all())
        assert len(rev_logs) == 0

        audit_logs = list(verify_session.execute(select(AuditLog)).scalars().all())
        assert len(audit_logs) == 0


def test_rollback_on_database_flush_failure(db_engine) -> None:
    init_database(db_engine)
    real_session_factory = create_session_factory(db_engine)
    crypto = FaultInjectingCryptoEngine()

    with real_session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, content="Original Post Content 3")

    # Wrap session_factory to fail on flush
    def failing_session_factory():
        sess = real_session_factory()
        orig_flush = sess.flush

        def mock_flush(*args, **kwargs):
            raise SQLAlchemyError("Simulated database flush failure")

        sess.flush = mock_flush
        return sess

    service = HoleContentGovernanceService(failing_session_factory, crypto)

    now = datetime(2026, 9, 9, 22, 30, 0, tzinfo=timezone.utc)
    with pytest.raises(HoleGovernanceError) as exc_info:
        service.withdraw_post(
            post_id=post.id,
            reason="DB failure test",
            operator_id=admin.id,
            now=now,
        )

    assert exc_info.value.code == "conflict"

    # Verify atomic rollback using independent session
    with real_session_factory() as verify_session:
        db_post = verify_session.get(HolePost, post.id)
        assert db_post is not None
        assert db_post.status == "published"
        assert db_post.credential_valid is True
        assert db_post.content == "Original Post Content 3"

        rev_logs = list(verify_session.execute(select(RevocationLog)).scalars().all())
        assert len(rev_logs) == 0

        audit_logs = list(verify_session.execute(select(AuditLog)).scalars().all())
        assert len(audit_logs) == 0
