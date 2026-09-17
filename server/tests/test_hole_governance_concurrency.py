from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import threading
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

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
from app.services.revocation_log import GENESIS_HASH, order_and_verify_chain


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
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
    content: str = "Concurrent hole post content",
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
def concurrent_env(tmp_path):
    db_file = tmp_path / "concurrent.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False, "timeout": 30.0},
        poolclass=NullPool,
    )

    @event.listens_for(engine, "connect")
    def enable_sqlite_foreign_keys(dbapi_connection, connection_record) -> None:
        del connection_record
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    init_database(engine)
    session_factory = create_session_factory(engine)
    crypto = DeterministicMockCryptoEngine()
    service = HoleContentGovernanceService(session_factory, crypto)
    return engine, session_factory, crypto, service


def test_concurrent_withdrawal_same_post_idempotency(concurrent_env) -> None:
    """测试 1（同帖高并发撤下）:
    10+ 线程同时撤下同一篇 published 帖子。
    所有线程的调用必须全部成功返回，且返回的 RevocationEntryDTO 指向同一个 hash_curr、同一个 hash_prev、同一个 timestamp。
    使用独立连接核验数据库：数据库中严格只有 1 条 RevocationLog，严格只有 1 条 AuditLog，帖子状态为 withdrawn。
    """
    engine, session_factory, crypto, service = concurrent_env
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, content="Concurrent single post to withdraw")

    concurrency = 12
    barrier = threading.Barrier(concurrency)
    fixed_time = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)

    def worker(idx: int) -> RevocationEntryDTO:
        barrier.wait()
        return service.withdraw_post(
            post_id=post.id,
            reason=f"Concurrent withdraw attempt {idx}",
            operator_id=admin.id,
            now=fixed_time,
        )

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker, i) for i in range(concurrency)]
        results = [f.result() for f in futures]

    assert len(results) == concurrency
    first_dto = results[0]
    assert isinstance(first_dto, RevocationEntryDTO)
    assert first_dto.sn == post.credential_sn.hex().lower()

    for dto in results[1:]:
        assert dto.hash_curr == first_dto.hash_curr
        assert dto.hash_prev == first_dto.hash_prev
        assert dto.timestamp == first_dto.timestamp
        assert dto.sn == first_dto.sn

    # Verify with independent session
    with session_factory() as verify_session:
        db_post = verify_session.get(HolePost, post.id)
        assert db_post is not None
        assert db_post.status == "withdrawn"
        assert db_post.credential_valid is False

        rev_logs = list(verify_session.execute(select(RevocationLog)).scalars().all())
        assert len(rev_logs) == 1
        assert bytes(rev_logs[0].sn) == bytes(post.credential_sn)

        audit_logs = list(verify_session.execute(select(AuditLog)).scalars().all())
        assert len(audit_logs) == 1
        assert audit_logs[0].target == f"hole_post:{post.id}"


def test_concurrent_withdrawal_different_posts(concurrent_env) -> None:
    """测试 2（不同帖子高并发撤下）:
    预先创建 10 篇不同的 published 帖子。
    10 个并发线程同时撤下各自的帖子。
    所有 10 个撤帖操作全部成功。
    使用独立连接核验数据库：数据库中恰好有 10 条 RevocationLog 与 10 条 AuditLog。
    调用 Task 1 的 order_and_verify_chain 验证：从 GENESIS_HASH 出发能无缝遍历全部 10 条记录，整链无分叉、无环、无孤立记录。
    """
    engine, session_factory, crypto, service = concurrent_env
    posts_count = 10
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        posts = [
            create_post(
                session,
                content=f"Concurrent post content {i}",
                credential_sn=f"sn_concurr_{i:08d}".encode("ascii"),
            )
            for i in range(posts_count)
        ]

    barrier = threading.Barrier(posts_count)

    def worker(idx: int, p_id: str) -> RevocationEntryDTO:
        barrier.wait()
        now = datetime(2026, 9, 9, 12, 10, idx, tzinfo=timezone.utc)
        return service.withdraw_post(
            post_id=p_id,
            reason=f"Concurrent reason {idx}",
            operator_id=admin.id,
            now=now,
        )

    with ThreadPoolExecutor(max_workers=posts_count) as executor:
        futures = [executor.submit(worker, i, posts[i].id) for i in range(posts_count)]
        results = [f.result() for f in futures]

    assert len(results) == posts_count

    # Verify with independent session
    with session_factory() as verify_session:
        for p in posts:
            db_post = verify_session.get(HolePost, p.id)
            assert db_post is not None
            assert db_post.status == "withdrawn"
            assert db_post.credential_valid is False

        rev_logs = list(verify_session.execute(select(RevocationLog)).scalars().all())
        assert len(rev_logs) == posts_count

        audit_logs = list(verify_session.execute(select(AuditLog)).scalars().all())
        assert len(audit_logs) == posts_count

        # Order and verify the entire chain starting from GENESIS_HASH
        ordered = order_and_verify_chain(rev_logs, crypto)
        assert ordered is not None
        assert len(ordered) == posts_count
        assert bytes(ordered[0].hash_prev) == GENESIS_HASH


def test_concurrent_withdrawal_empty_chain_genesis_successor(concurrent_env) -> None:
    """测试 3（空链首次并发写入）:
    数据库初态为空（无任何撤销记录）。
    多个线程同时撤下不同帖子，验证仅能产生一条 hash_prev == GENESIS_HASH 的创世后继，
    其余请求在新链头上继续有序追加，形成无分叉单链。
    """
    engine, session_factory, crypto, service = concurrent_env
    posts_count = 10
    with session_factory() as session:
        # Confirm initial state has 0 revocation logs
        initial_rev_count = len(list(session.execute(select(RevocationLog)).scalars().all()))
        assert initial_rev_count == 0

        admin = create_user(session, role="admin", status="active")
        posts = [
            create_post(
                session,
                content=f"Empty chain post {i}",
                credential_sn=f"sn_empty_chain_{i:04d}".encode("ascii"),
            )
            for i in range(posts_count)
        ]

    barrier = threading.Barrier(posts_count)

    def worker(idx: int, p_id: str) -> RevocationEntryDTO:
        barrier.wait()
        now = datetime(2026, 9, 9, 12, 20, idx, tzinfo=timezone.utc)
        return service.withdraw_post(
            post_id=p_id,
            reason=f"Empty chain withdraw {idx}",
            operator_id=admin.id,
            now=now,
        )

    with ThreadPoolExecutor(max_workers=posts_count) as executor:
        futures = [executor.submit(worker, i, posts[i].id) for i in range(posts_count)]
        results = [f.result() for f in futures]

    assert len(results) == posts_count

    with session_factory() as verify_session:
        rev_logs = list(verify_session.execute(select(RevocationLog)).scalars().all())
        assert len(rev_logs) == posts_count

        # Exactly 1 record has hash_prev == GENESIS_HASH
        genesis_successors = [r for r in rev_logs if bytes(r.hash_prev) == GENESIS_HASH]
        assert len(genesis_successors) == 1

        # All records form an unbroken chain
        ordered = order_and_verify_chain(rev_logs, crypto)
        assert ordered is not None
        assert len(ordered) == posts_count
        assert bytes(ordered[0].hash_prev) == GENESIS_HASH


def test_retry_mechanism_and_exhaustion_conflict_simulation(concurrent_env) -> None:
    """测试 4（重试机制与冲突耗尽模拟）:
    模拟外部连续注入 IntegrityError 或锁定，确认重试次数达到 3 次后抛出 HoleGovernanceError(code="conflict")，
    不破坏已有数据。
    """
    engine, session_factory, crypto, _ = concurrent_env
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, content="Post to test retry exhaustion")

    commit_attempts = 0

    def mock_failing_session_factory():
        sess = session_factory()

        def failing_commit():
            nonlocal commit_attempts
            commit_attempts += 1
            # Inject retriable IntegrityError simulating chain head race
            raise IntegrityError(
                "Simulated uq_revocation_log_hash_prev conflict",
                orig=Exception("UNIQUE constraint failed: revocation_log.hash_prev"),
                params=None,
            )

        sess.commit = failing_commit
        return sess

    faulty_service = HoleContentGovernanceService(mock_failing_session_factory, crypto)
    now = datetime(2026, 9, 9, 12, 30, 0, tzinfo=timezone.utc)

    with pytest.raises(HoleGovernanceError) as exc_info:
        faulty_service.withdraw_post(
            post_id=post.id,
            reason="Test retry exhaustion",
            operator_id=admin.id,
            now=now,
        )

    assert exc_info.value.code == "conflict"
    assert "撤帖写入冲突，请稍后重试" in exc_info.value.message
    # 1 initial attempt + 3 retries = 4 attempts total
    assert commit_attempts == 4

    # Verify existing data is undamaged
    with session_factory() as verify_session:
        db_post = verify_session.get(HolePost, post.id)
        assert db_post is not None
        assert db_post.status == "published"
        assert db_post.credential_valid is True

        rev_logs = list(verify_session.execute(select(RevocationLog)).scalars().all())
        assert len(rev_logs) == 0

        audit_logs = list(verify_session.execute(select(AuditLog)).scalars().all())
        assert len(audit_logs) == 0


def test_retry_mechanism_exhaustion_on_locked_database(concurrent_env) -> None:
    """测试 4 变体: 模拟持续 SQLite OperationalError: database is locked，重试 3 次耗尽后抛出 conflict"""
    engine, session_factory, crypto, _ = concurrent_env
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, content="Post to test lock exhaustion")

    commit_attempts = 0

    def mock_locked_session_factory():
        sess = session_factory()

        def failing_commit():
            nonlocal commit_attempts
            commit_attempts += 1
            raise OperationalError(
                "database is locked",
                orig=Exception("database is locked"),
                params=None,
            )

        sess.commit = failing_commit
        return sess

    faulty_service = HoleContentGovernanceService(mock_locked_session_factory, crypto)
    now = datetime(2026, 9, 9, 12, 35, 0, tzinfo=timezone.utc)

    with pytest.raises(HoleGovernanceError) as exc_info:
        faulty_service.withdraw_post(
            post_id=post.id,
            reason="Test lock exhaustion",
            operator_id=admin.id,
            now=now,
        )

    assert exc_info.value.code == "conflict"
    assert "撤帖写入冲突，请稍后重试" in exc_info.value.message
    assert commit_attempts == 4

    with session_factory() as verify_session:
        db_post = verify_session.get(HolePost, post.id)
        assert db_post is not None
        assert db_post.status == "published"
        assert db_post.credential_valid is True
        assert len(list(verify_session.execute(select(RevocationLog)).scalars().all())) == 0


def test_retry_mechanism_succeeds_after_transient_failures(concurrent_env) -> None:
    """测试重试机制在经历 2 次瞬态失败后第 3 次尝试成功"""
    engine, session_factory, crypto, _ = concurrent_env
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, content="Post transient failure success")

    commit_attempts = 0

    def mock_transient_session_factory():
        sess = session_factory()
        orig_commit = sess.commit

        def maybe_failing_commit():
            nonlocal commit_attempts
            commit_attempts += 1
            if commit_attempts <= 2:
                raise OperationalError(
                    "database is locked",
                    orig=Exception("database is locked"),
                    params=None,
                )
            orig_commit()

        sess.commit = maybe_failing_commit
        return sess

    service = HoleContentGovernanceService(mock_transient_session_factory, crypto)
    now = datetime(2026, 9, 9, 12, 40, 0, tzinfo=timezone.utc)

    dto = service.withdraw_post(
        post_id=post.id,
        reason="Transient failure retry",
        operator_id=admin.id,
        now=now,
    )

    assert isinstance(dto, RevocationEntryDTO)
    assert commit_attempts == 3

    with session_factory() as verify_session:
        db_post = verify_session.get(HolePost, post.id)
        assert db_post is not None
        assert db_post.status == "withdrawn"
        assert db_post.credential_valid is False
        assert len(list(verify_session.execute(select(RevocationLog)).scalars().all())) == 1


def test_invalid_credential_sn_defensive_check(concurrent_env) -> None:
    """测试防御性校验: if not post.credential_sn or len(post.credential_sn) < 16: raise integrity_error"""
    engine, session_factory, crypto, service = concurrent_env
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post_short = create_post(session, credential_sn=b"short_sn_123")  # len 12 < 16
        post_empty = create_post(session, credential_sn=b"")

    now = datetime(2026, 9, 9, 12, 45, 0, tzinfo=timezone.utc)

    with pytest.raises(HoleGovernanceError) as exc_short:
        service.withdraw_post(
            post_id=post_short.id,
            reason="Short SN test",
            operator_id=admin.id,
            now=now,
        )
    assert exc_short.value.code == "integrity_error"
    assert "帖子凭据 SN 格式不合法" in exc_short.value.message

    with pytest.raises(HoleGovernanceError) as exc_empty:
        service.withdraw_post(
            post_id=post_empty.id,
            reason="Empty SN test",
            operator_id=admin.id,
            now=now,
        )
    assert exc_empty.value.code == "integrity_error"
    assert "帖子凭据 SN 格式不合法" in exc_empty.value.message


def test_integrity_error_idempotent_recovery_when_already_withdrawn(concurrent_env) -> None:
    """测试当 commit 发生 IntegrityError 时，检测到该帖子已被成功撤下，幂等返回已有记录的 DTO"""
    engine, session_factory, crypto, _ = concurrent_env
    with session_factory() as session:
        admin = create_user(session, role="admin", status="active")
        post = create_post(session, content="Concurrent race test post")

    # We simulate a race: attempt 1 raises IntegrityError on commit,
    # rolls back, and during check_session, the post has been withdrawn by another worker.
    attempt_count = 0

    def mock_race_session_factory():
        nonlocal attempt_count
        attempt_count += 1
        if attempt_count == 1:
            sess = session_factory()

            def failing_commit():
                raise IntegrityError(
                    "UNIQUE constraint failed: revocation_log.sn",
                    orig=Exception("UNIQUE constraint failed: revocation_log.sn"),
                    params=None,
                )

            sess.commit = failing_commit
            return sess
        elif attempt_count == 2:
            # check_session: at this point sess 1 has rolled back and unlocked SQLite.
            # Withdraw the post using another worker now.
            with session_factory() as other_sess:
                other_service = HoleContentGovernanceService(session_factory, crypto)
                other_service.withdraw_post(
                    post_id=post.id,
                    reason="Winner of the race",
                    operator_id=admin.id,
                    now=datetime(2026, 9, 9, 12, 50, 0, tzinfo=timezone.utc),
                )
            return session_factory()
        return session_factory()

    service = HoleContentGovernanceService(mock_race_session_factory, crypto)
    dto = service.withdraw_post(
        post_id=post.id,
        reason="Losing racer",
        operator_id=admin.id,
        now=datetime(2026, 9, 9, 12, 50, 10, tzinfo=timezone.utc),
    )

    # Must idempotently return the winner's DTO
    assert isinstance(dto, RevocationEntryDTO)
    assert dto.reason == "Winner of the race"

    with session_factory() as verify_session:
        rev_logs = list(verify_session.execute(select(RevocationLog)).scalars().all())
        assert len(rev_logs) == 1
        assert rev_logs[0].reason == "Winner of the race"
