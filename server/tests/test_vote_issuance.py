import base64
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy.orm import sessionmaker

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.db.session import create_db_engine, init_database
from app.models.audit import AuditLog
from app.models.credential import CredentialLedger
from app.models.user import User
from app.models.vote import VoteCredentialIssue, VoteOption, VoteRecord
from app.services.vote_credentials import (
    IssuedCredential,
    VoteCredentialIssuanceError,
    VoteCredentialIssuanceService,
)
from app.services.vote_signer import DefaultVoteSignerMaterialProvider, VoteSignerMaterialProvider


class MockVoteSignerMaterialProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x66" * SM2_PRIVATE_KEY_SIZE)

    def get_signer_private_key(self, *, vote_id: str) -> bytes | None:
        return self.key

    def get_signer_public_key(self, *, vote_id: str) -> bytes | None:
        return b"\x88" * 64


class DeterministicMockCryptoEngine(MockCryptoEngine):
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


def _setup_issuance_env():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    sm = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = sm()

    crypto = DeterministicMockCryptoEngine()
    crypto.set_result("blind_sign", b"\x99" * 64)
    signer_provider = MockVoteSignerMaterialProvider()

    service = VoteCredentialIssuanceService(
        session=session,
        crypto_engine=crypto,
        signer_provider=signer_provider,
    )
    return session, crypto, signer_provider, service


def test_vote_credential_issue_success_and_idempotent_replay():
    session, crypto, signer, service = _setup_issuance_env()

    creator = User(email="creator@example.com", role="teacher", status="active")
    voter = User(email="voter@example.com", role="student", status="active")
    session.add_all([creator, voter])
    session.commit()

    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    closes_at = now + timedelta(days=2)

    vote = VoteRecord(
        creator_id=creator.id,
        title="评优投票",
        scope="public",
        closes_at=closes_at,
        status="open",
        created_at=now - timedelta(hours=1),
    )
    opt1 = VoteOption(vote_id=vote.id, label="候选人甲", position=0)
    opt2 = VoteOption(vote_id=vote.id, label="候选人乙", position=1)
    session.add_all([vote, opt1, opt2])
    session.commit()

    raw_blinded = b"\x33" * 64
    blinded_b64 = base64.b64encode(raw_blinded).decode("ascii")
    idemp_key = "voter-idemp-key-00000000001"

    # First issuance: 201 success
    result1 = service.issue(
        user_id=voter.id,
        vote_id=vote.id,
        service="vote_ballot",
        period=vote.id,
        blinded_message_b64=blinded_b64,
        idempotency_key=idemp_key,
        now=now,
    )

    assert isinstance(result1, IssuedCredential)
    assert result1.blind_signature == b"\x99" * 64
    assert result1.algorithm == "SM2-BLIND-PROTOCOL-V1"

    # Exactly 1 VoteCredentialIssue record
    issue_rec = session.query(VoteCredentialIssue).filter_by(user_id=voter.id, vote_id=vote.id).one()
    assert issue_rec.blind_signature == b"\x99" * 64

    # Exactly 1 CredentialLedger record with issued_count == 1
    ledger = session.query(CredentialLedger).filter_by(
        user_id=voter.id, service="vote_ballot", period=vote.id
    ).one()
    assert ledger.issued_count == 1

    # Exactly 1 AuditLog record
    audit = session.query(AuditLog).filter_by(action="vote.credential.issue").one()
    assert audit.actor == voter.id
    assert audit.target == f"vote:{vote.id}"

    # Replay with same key and exact same request -> identical result, no quota/blind_sign increment
    crypto.set_result("blind_sign", b"\xaa" * 64)  # change mock result to verify blind_sign is NOT called
    result2 = service.issue(
        user_id=voter.id,
        vote_id=vote.id,
        service="vote_ballot",
        period=vote.id,
        blinded_message_b64=blinded_b64,
        idempotency_key=idemp_key,
        now=now + timedelta(minutes=10),
    )
    assert result2.blind_signature == b"\x99" * 64  # returned cached signature
    session.refresh(ledger)
    assert ledger.issued_count == 1
    assert session.query(VoteCredentialIssue).count() == 1


def test_vote_credential_conflict_on_different_key_or_message():
    session, crypto, signer, service = _setup_issuance_env()

    voter = User(email="voter2@example.com", role="student", status="active")
    creator = User(email="creator2@example.com", role="teacher", status="active")
    session.add_all([voter, creator])
    session.commit()

    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    vote = VoteRecord(
        creator_id=creator.id,
        title="评优投票2",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now,
    )
    session.add(vote)
    session.commit()

    blinded_b64_1 = base64.b64encode(b"\x11" * 64).decode("ascii")
    blinded_b64_2 = base64.b64encode(b"\x22" * 64).decode("ascii")

    # Issue once
    service.issue(
        user_id=voter.id,
        vote_id=vote.id,
        service="vote_ballot",
        period=vote.id,
        blinded_message_b64=blinded_b64_1,
        idempotency_key="key-00000000000000000001",
        now=now,
    )

    # Re-issue same user same vote with DIFFERENT key -> 409 Conflict
    with pytest.raises(VoteCredentialIssuanceError) as exc_key:
        service.issue(
            user_id=voter.id,
            vote_id=vote.id,
            service="vote_ballot",
            period=vote.id,
            blinded_message_b64=blinded_b64_1,
            idempotency_key="key-00000000000000000002",
            now=now,
        )
    assert exc_key.value.code == "credential_already_issued"

    # Re-issue same user same vote same key with DIFFERENT blinded message -> 409 Conflict
    with pytest.raises(VoteCredentialIssuanceError) as exc_msg:
        service.issue(
            user_id=voter.id,
            vote_id=vote.id,
            service="vote_ballot",
            period=vote.id,
            blinded_message_b64=blinded_b64_2,
            idempotency_key="key-00000000000000000001",
            now=now,
        )
    assert exc_msg.value.code == "credential_already_issued"


def test_vote_credential_ledger_reset_cannot_bypass_unique_constraint():
    session, crypto, signer, service = _setup_issuance_env()

    voter = User(email="voter3@example.com", role="student", status="active")
    creator = User(email="creator3@example.com", role="teacher", status="active")
    session.add_all([voter, creator])
    session.commit()

    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    vote = VoteRecord(
        creator_id=creator.id,
        title="评优投票3",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now,
    )
    session.add(vote)
    session.commit()

    blinded_b64 = base64.b64encode(b"\x55" * 64).decode("ascii")

    # Issue once
    service.issue(
        user_id=voter.id,
        vote_id=vote.id,
        service="vote_ballot",
        period=vote.id,
        blinded_message_b64=blinded_b64,
        idempotency_key="key-ledger-test-0000000001",
        now=now,
    )

    # Admin resets or deletes CredentialLedger
    session.query(CredentialLedger).filter_by(user_id=voter.id, service="vote_ballot").delete()
    session.commit()

    # Attempting to issue again with a new key MUST still fail due to VoteCredentialIssue unique constraint
    with pytest.raises(VoteCredentialIssuanceError) as exc:
        service.issue(
            user_id=voter.id,
            vote_id=vote.id,
            service="vote_ballot",
            period=vote.id,
            blinded_message_b64=blinded_b64,
            idempotency_key="key-ledger-test-0000000002",
            now=now,
        )
    assert exc.value.code == "credential_already_issued"


def test_vote_credential_validation_failures():
    session, crypto, signer, service = _setup_issuance_env()

    voter = User(email="voter4@example.com", role="student", status="active")
    creator = User(email="creator4@example.com", role="teacher", status="active")
    session.add_all([voter, creator])
    session.commit()

    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    vote = VoteRecord(
        creator_id=creator.id,
        title="评优投票4",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now,
    )
    session.add(vote)
    session.commit()

    blinded_b64 = base64.b64encode(b"\x77" * 64).decode("ascii")
    valid_key = "valid-idemp-key-0000000001"

    # 1. Invalid service (must be vote_ballot)
    with pytest.raises(VoteCredentialIssuanceError) as exc_svc:
        service.issue(
            user_id=voter.id,
            vote_id=vote.id,
            service="hole_post",
            period=vote.id,
            blinded_message_b64=blinded_b64,
            idempotency_key=valid_key,
            now=now,
        )
    assert exc_svc.value.code == "invalid_service"

    # 2. Invalid period (must match vote_id)
    with pytest.raises(VoteCredentialIssuanceError) as exc_per:
        service.issue(
            user_id=voter.id,
            vote_id=vote.id,
            service="vote_ballot",
            period="wrong-period-value",
            blinded_message_b64=blinded_b64,
            idempotency_key=valid_key,
            now=now,
        )
    assert exc_per.value.code == "invalid_period"

    # 3. Vote not found
    with pytest.raises(VoteCredentialIssuanceError) as exc_nv:
        service.issue(
            user_id=voter.id,
            vote_id="non-existent-vote-id",
            service="vote_ballot",
            period="non-existent-vote-id",
            blinded_message_b64=blinded_b64,
            idempotency_key=valid_key,
            now=now,
        )
    assert exc_nv.value.code == "vote_not_found"

    # 4. Vote closed (now >= closes_at)
    with pytest.raises(VoteCredentialIssuanceError) as exc_closed:
        service.issue(
            user_id=voter.id,
            vote_id=vote.id,
            service="vote_ballot",
            period=vote.id,
            blinded_message_b64=blinded_b64,
            idempotency_key=valid_key,
            now=now + timedelta(days=3),
        )
    assert exc_closed.value.code == "vote_closed"

    # 5. Invalid base64
    with pytest.raises(VoteCredentialIssuanceError) as exc_b64:
        service.issue(
            user_id=voter.id,
            vote_id=vote.id,
            service="vote_ballot",
            period=vote.id,
            blinded_message_b64="!!!not-base64!!!",
            idempotency_key=valid_key,
            now=now,
        )
    assert exc_b64.value.code == "invalid_blinded_message"

    # 6. Default provider fail-closed (returns None -> engine_unavailable 503)
    fail_closed_service = VoteCredentialIssuanceService(
        session=session,
        crypto_engine=crypto,
        signer_provider=DefaultVoteSignerMaterialProvider(),
    )
    with pytest.raises(VoteCredentialIssuanceError) as exc_prov:
        fail_closed_service.issue(
            user_id=voter.id,
            vote_id=vote.id,
            service="vote_ballot",
            period=vote.id,
            blinded_message_b64=blinded_b64,
            idempotency_key=valid_key,
            now=now,
        )
    assert exc_prov.value.code == "engine_unavailable"
