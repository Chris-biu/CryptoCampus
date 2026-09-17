import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
import uuid
import pytest

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.db.session import create_db_engine, create_session_factory, init_database
from app.models.audit import AuditLog
from app.models.credential import CredentialLedger
from app.models.user import User
from app.models.vote import VoteCreateIdempotency, VoteCredentialIssue, VoteOption, VoteRecord
from app.schemas.vote import CreateVoteOption, CreateVoteRequest
from app.services.vote_credentials import (
    VoteCredentialIssuanceError,
    VoteCredentialIssuanceService,
)
from app.services.votes import VoteService, VoteServiceError


class MockVoteSignerMaterialProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x66" * SM2_PRIVATE_KEY_SIZE)

    def get_signer_private_key(self, *, vote_id: str) -> bytes | None:
        return self.key

    def get_signer_public_key(self, *, vote_id: str) -> bytes | None:
        return b"\x88" * 64


class DynamicMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            seed = f"hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


def _create_user(session_factory, role="student", email="student@campus.edu.cn") -> str:
    with session_factory() as session:
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            role=role,
            status="active",
        )
        session.add(user)
        session.commit()
        return user.id


def _create_vote(session_factory, creator_id: str) -> str:
    with session_factory() as session:
        now = datetime.now(timezone.utc)
        vote = VoteRecord(
            id=str(uuid.uuid4()),
            creator_id=creator_id,
            title="并发选举测试",
            scope="public",
            closes_at=now + timedelta(days=5),
            status="open",
            created_at=now,
        )
        opt1 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="选项A", position=0)
        opt2 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="选项B", position=1)
        session.add_all([vote, opt1, opt2])
        session.commit()
        return vote.id


def test_concurrent_issuance_same_user_different_keys_only_one_succeeds(tmp_path):
    db_file = tmp_path / "vote_conc_diff_keys.db"
    engine = create_db_engine(f"sqlite+pysqlite:///{db_file.as_posix()}?timeout=30.0")
    init_database(engine)
    session_factory = create_session_factory(engine)

    creator_id = _create_user(session_factory, role="teacher", email="teacher1@example.com")
    voter_id = _create_user(session_factory, role="student", email="student1@example.com")
    vote_id = _create_vote(session_factory, creator_id)

    num_threads = 10
    barrier = Barrier(num_threads)
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    crypto = DynamicMockCryptoEngine()
    crypto.set_result("blind_sign", b"\x77" * 64)
    signer_provider = MockVoteSignerMaterialProvider()

    def run_issuance(idx: int) -> str:
        with session_factory() as session:
            service = VoteCredentialIssuanceService(
                session=session,
                crypto_engine=crypto,
                signer_provider=signer_provider,
            )
            blinded_b64 = base64.b64encode(f"msg-{idx}".encode("utf-8")).decode("ascii")
            idemp_key = f"key-conc-diff-{idx:03d}-12345"
            barrier.wait()
            try:
                res = service.issue(
                    user_id=voter_id,
                    vote_id=vote_id,
                    service="vote_ballot",
                    period=vote_id,
                    blinded_message_b64=blinded_b64,
                    idempotency_key=idemp_key,
                    now=now,
                )
                return "success"
            except VoteCredentialIssuanceError as err:
                return err.code

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        outcomes = list(executor.map(run_issuance, range(num_threads)))

    assert outcomes.count("success") == 1
    assert outcomes.count("credential_already_issued") == num_threads - 1

    with session_factory() as session:
        issue_count = session.query(VoteCredentialIssue).filter_by(user_id=voter_id, vote_id=vote_id).count()
        assert issue_count == 1
        ledger = session.query(CredentialLedger).filter_by(user_id=voter_id, service="vote_ballot", period=vote_id).one()
        assert ledger.issued_count == 1


def test_concurrent_issuance_same_user_same_key_all_succeed(tmp_path):
    db_file = tmp_path / "vote_conc_same_key.db"
    engine = create_db_engine(f"sqlite+pysqlite:///{db_file.as_posix()}?timeout=30.0")
    init_database(engine)
    session_factory = create_session_factory(engine)

    creator_id = _create_user(session_factory, role="teacher", email="teacher2@example.com")
    voter_id = _create_user(session_factory, role="student", email="student2@example.com")
    vote_id = _create_vote(session_factory, creator_id)

    num_threads = 8
    barrier = Barrier(num_threads)
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    idemp_key = "shared-same-key-0000000001"
    blinded_b64 = base64.b64encode(b"consistent-blinded-message").decode("ascii")

    crypto = DynamicMockCryptoEngine()
    crypto.set_result("blind_sign", b"\x99" * 64)
    signer_provider = MockVoteSignerMaterialProvider()

    def run_issuance(idx: int) -> tuple[str, bytes]:
        with session_factory() as session:
            service = VoteCredentialIssuanceService(
                session=session,
                crypto_engine=crypto,
                signer_provider=signer_provider,
            )
            barrier.wait()
            try:
                res = service.issue(
                    user_id=voter_id,
                    vote_id=vote_id,
                    service="vote_ballot",
                    period=vote_id,
                    blinded_message_b64=blinded_b64,
                    idempotency_key=idemp_key,
                    now=now,
                )
                return ("success", res.blind_signature)
            except VoteCredentialIssuanceError as err:
                return (err.code, b"")

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        results = list(executor.map(run_issuance, range(num_threads)))

    assert all(status == "success" for status, _ in results)
    signatures = [sig for _, sig in results]
    assert all(sig == signatures[0] for sig in signatures)

    with session_factory() as session:
        issue_count = session.query(VoteCredentialIssue).filter_by(user_id=voter_id, vote_id=vote_id).count()
        assert issue_count == 1
        ledger = session.query(CredentialLedger).filter_by(user_id=voter_id, service="vote_ballot", period=vote_id).one()
        assert ledger.issued_count == 1


def test_concurrent_issuance_different_users_all_succeed(tmp_path):
    db_file = tmp_path / "vote_conc_diff_users.db"
    engine = create_db_engine(f"sqlite+pysqlite:///{db_file.as_posix()}?timeout=30.0")
    init_database(engine)
    session_factory = create_session_factory(engine)

    creator_id = _create_user(session_factory, role="teacher", email="teacher3@example.com")
    vote_id = _create_vote(session_factory, creator_id)

    num_users = 5
    user_ids = [_create_user(session_factory, role="student", email=f"student_{i}@example.com") for i in range(num_users)]

    barrier = Barrier(num_users)
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    crypto = DynamicMockCryptoEngine()
    crypto.set_result("blind_sign", b"\x55" * 64)
    signer_provider = MockVoteSignerMaterialProvider()

    def run_issuance(user_id: str) -> str:
        with session_factory() as session:
            service = VoteCredentialIssuanceService(
                session=session,
                crypto_engine=crypto,
                signer_provider=signer_provider,
            )
            blinded_b64 = base64.b64encode(f"msg-for-{user_id}".encode("utf-8")).decode("ascii")
            barrier.wait()
            try:
                res = service.issue(
                    user_id=user_id,
                    vote_id=vote_id,
                    service="vote_ballot",
                    period=vote_id,
                    blinded_message_b64=blinded_b64,
                    idempotency_key=f"idemp-diff-user-{user_id[:16]}",
                    now=now,
                )
                return "success"
            except VoteCredentialIssuanceError as err:
                return err.code

    with ThreadPoolExecutor(max_workers=num_users) as executor:
        outcomes = list(executor.map(run_issuance, user_ids))

    assert outcomes == ["success"] * num_users

    with session_factory() as session:
        issue_count = session.query(VoteCredentialIssue).filter_by(vote_id=vote_id).count()
        assert issue_count == num_users


def test_concurrent_vote_creation_same_key_produces_single_vote(tmp_path):
    db_file = tmp_path / "vote_conc_creation.db"
    engine = create_db_engine(f"sqlite+pysqlite:///{db_file.as_posix()}?timeout=30.0")
    init_database(engine)
    session_factory = create_session_factory(engine)

    creator_id = _create_user(session_factory, role="teacher", email="creator_conc@example.com")

    num_threads = 8
    barrier = Barrier(num_threads)
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    idemp_key = "conc-vote-create-key-00000001"
    req = CreateVoteRequest(
        title="并发创建选举",
        description="并发创建测试",
        options=[CreateVoteOption(label="选项1"), CreateVoteOption(label="选项2")],
        scope="public",
        closes_at=now + timedelta(days=2),
    )

    crypto = DynamicMockCryptoEngine()

    def run_create(idx: int) -> str:
        with session_factory() as session:
            service = VoteService(session=session, crypto_engine=crypto)
            barrier.wait()
            try:
                vote = service.create(
                    creator_id=creator_id,
                    request=req,
                    idempotency_key=idemp_key,
                    now=now,
                )
                return vote.id
            except VoteServiceError as err:
                return err.code

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        vote_ids = list(executor.map(run_create, range(num_threads)))

    # All threads successfully returned the same vote id
    assert len(set(vote_ids)) == 1
    single_vote_id = vote_ids[0]

    with session_factory() as session:
        assert session.query(VoteRecord).count() == 1
        assert session.query(VoteCreateIdempotency).count() == 1
        assert session.query(AuditLog).filter_by(action="vote.create").count() == 1
        options = session.query(VoteOption).filter_by(vote_id=single_vote_id).order_by(VoteOption.position).all()
        assert len(options) == 2
        assert [opt.label for opt in options] == ["选项1", "选项2"]
