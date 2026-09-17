import base64
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.db.session import create_db_engine, init_database
from app.models.audit import AuditLog
from app.models.credential import CredentialLedger
from app.models.user import User
from app.models.vote import VoteCreateIdempotency, VoteCredentialIssue, VoteOption, VoteRecord
from app.schemas.vote import CreateVoteOption, CreateVoteRequest
from app.services.quota import QuotaService
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


def _setup_test_db():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    sm = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = sm()

    creator = User(email="creator_rb@example.com", role="teacher", status="active")
    voter = User(email="voter_rb@example.com", role="student", status="active")
    session.add_all([creator, voter])
    session.commit()

    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    vote = VoteRecord(
        creator_id=creator.id,
        title="回滚测试投票",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now,
    )
    opt1 = VoteOption(vote_id=vote.id, label="选项A", position=0)
    opt2 = VoteOption(vote_id=vote.id, label="选项B", position=1)
    session.add_all([vote, opt1, opt2])
    session.commit()

    return session, sm, creator, voter, vote, now


def test_rollback_on_blind_sign_failure():
    session, sm, creator, voter, vote, now = _setup_test_db()
    crypto = DynamicMockCryptoEngine()
    crypto.set_error("blind_sign", CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))
    signer_provider = MockVoteSignerMaterialProvider()

    service = VoteCredentialIssuanceService(
        session=session,
        crypto_engine=crypto,
        signer_provider=signer_provider,
    )

    blinded_b64 = base64.b64encode(b"test-msg").decode("ascii")

    with pytest.raises(VoteCredentialIssuanceError) as exc:
        service.issue(
            user_id=voter.id,
            vote_id=vote.id,
            service="vote_ballot",
            period=vote.id,
            blinded_message_b64=blinded_b64,
            idempotency_key="key-rb-blind-fail-0001",
            now=now,
        )
    assert exc.value.code == "engine_unavailable"

    # In independent session, verify completely rolled back
    verify_session = sm()
    assert verify_session.query(VoteCredentialIssue).count() == 0
    assert verify_session.query(CredentialLedger).filter_by(user_id=voter.id, service="vote_ballot").count() == 0
    assert verify_session.query(AuditLog).filter_by(action="vote.credential.issue").count() == 0


def test_rollback_on_audit_write_failure_during_issuance():
    session, sm, creator, voter, vote, now = _setup_test_db()
    crypto = DynamicMockCryptoEngine()
    crypto.set_result("blind_sign", b"\x55" * 64)
    signer_provider = MockVoteSignerMaterialProvider()

    service = VoteCredentialIssuanceService(
        session=session,
        crypto_engine=crypto,
        signer_provider=signer_provider,
    )

    blinded_b64 = base64.b64encode(b"test-msg").decode("ascii")

    # Inject failure during flush
    with patch.object(session, "flush", side_effect=OperationalError("disk failure", None, None)):
        with pytest.raises(Exception):
            service.issue(
                user_id=voter.id,
                vote_id=vote.id,
                service="vote_ballot",
                period=vote.id,
                blinded_message_b64=blinded_b64,
                idempotency_key="key-rb-flush-fail-0001",
                now=now,
            )

    # In independent session, verify completely rolled back
    verify_session = sm()
    assert verify_session.query(VoteCredentialIssue).count() == 0
    assert verify_session.query(CredentialLedger).filter_by(user_id=voter.id, service="vote_ballot").count() == 0
    assert verify_session.query(AuditLog).filter_by(action="vote.credential.issue").count() == 0


def test_rollback_on_vote_creation_failure():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    sm = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = sm()

    creator = User(email="creator_fail@example.com", role="teacher", status="active")
    session.add(creator)
    session.commit()

    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    crypto = DynamicMockCryptoEngine()
    service = VoteService(session=session, crypto_engine=crypto)

    req = CreateVoteRequest(
        title="即将失败的创建",
        options=[CreateVoteOption(label="1"), CreateVoteOption(label="2")],
        scope="public",
        closes_at=now + timedelta(days=1),
    )

    # Patch session.flush to simulate failure during creation transaction
    with patch.object(session, "flush", side_effect=OperationalError("flush failed", None, None)):
        with pytest.raises(Exception):
            service.create(
                creator_id=creator.id,
                request=req,
                idempotency_key="key-creation-fail-0001",
                now=now,
            )

    # Verify no orphan vote, options, idempotency or audit records exist
    verify_session = sm()
    assert verify_session.query(VoteRecord).filter_by(title="即将失败的创建").count() == 0
    assert verify_session.query(VoteCreateIdempotency).count() == 0
    assert verify_session.query(AuditLog).filter_by(action="vote.create").count() == 0
