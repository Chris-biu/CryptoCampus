import base64
from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE
from app.db.base import Base
from app.models.user import User
from app.models.vote import VoteCredentialIssue, VoteOption, VoteRecord
from app.schemas.vote import VoteCredentialProof
from app.services.vote_ballot_verification import (
    BALLOT_MESSAGE_DOMAIN,
    VerifiedBallotCredential,
    VoteBallotVerificationError,
    encode_vote_ballot_message,
    verify_vote_ballot,
)
from app.services.vote_signer import VoteSignerMaterialProvider


class MockPerVoteSignerMaterialProvider:
    def __init__(self, key_map: dict[str, bytes] | None = None) -> None:
        self.key_map = key_map or {}

    def set_key(self, vote_id: str, public_key: bytes) -> None:
        self.key_map[vote_id] = public_key

    def get_signer_private_key(self, *, vote_id: str) -> bytes | None:
        return None

    def get_signer_public_key(self, *, vote_id: str) -> bytes | None:
        return self.key_map.get(vote_id)


class BallotCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.valid_signatures: set[tuple[bytes, bytes, bytes]] = set()

    def add_valid_signature(self, message: bytes, signature: bytes, public_key: bytes) -> None:
        self.valid_signatures.add((message, signature, public_key))

    def blind_verify(self, *, message: bytes, signature: bytes, signer_public_key: bytes) -> bool:
        return (message, signature, signer_public_key) in self.valid_signatures


def _setup_db() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def _seed_env():
    session = _setup_db()
    crypto = BallotCryptoEngine()
    signer_provider = MockPerVoteSignerMaterialProvider()

    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    creator = User(email="vote_creator@edu.cn", role="teacher", status="active")
    session.add(creator)
    session.commit()

    vote = VoteRecord(
        creator_id=creator.id,
        title="学生会选举",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now - timedelta(hours=1),
    )
    opt1 = VoteOption(vote_id=vote.id, label="张三", position=0)
    opt2 = VoteOption(vote_id=vote.id, label="李四", position=1)
    session.add_all([vote, opt1, opt2])
    session.commit()

    vote_pubkey = b"\x04" + b"\x44" * (SM2_PUBLIC_KEY_SIZE - 1)
    signer_provider.set_key(vote.id, vote_pubkey)

    sn_hex = "11223344556677889900aabbccddeeff"
    sig_bytes = b"\x77" * 64
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    # Correct message encoding
    canonical_msg = encode_vote_ballot_message(
        sn_hex=sn_hex,
        service="vote_ballot",
        vote_id=vote.id,
        option_id=opt1.id,
    )
    crypto.add_valid_signature(canonical_msg, sig_bytes, vote_pubkey)

    valid_proof = VoteCredentialProof(
        sn=sn_hex,
        service="vote_ballot",
        period=vote.id,
        signature=sig_b64,
    )

    return session, crypto, signer_provider, vote, opt1, opt2, valid_proof, now


def test_verify_vote_ballot_success():
    session, crypto, signer_provider, vote, opt1, opt2, proof, now = _seed_env()

    verified = verify_vote_ballot(
        session=session,
        crypto_engine=crypto,
        signer_provider=signer_provider,
        vote_id=vote.id,
        option_id=opt1.id,
        credential=proof,
        now=now,
    )

    assert isinstance(verified, VerifiedBallotCredential)
    assert verified.normalized_sn == proof.sn
    assert verified.service == "vote_ballot"
    assert verified.period == vote.id
    assert verified.vote_id == vote.id
    assert verified.option_id == opt1.id


def test_verify_vote_ballot_cryptographic_negative_vectors():
    session, crypto, signer_provider, vote, opt1, opt2, proof, now = _seed_env()

    # 1. Cross-option: same credential submitted for opt2
    with pytest.raises(VoteBallotVerificationError) as exc_opt:
        verify_vote_ballot(
            session=session,
            crypto_engine=crypto,
            signer_provider=signer_provider,
            vote_id=vote.id,
            option_id=opt2.id,
            credential=proof,
            now=now,
        )
    assert exc_opt.value.code == "invalid_signature"

    # 2. Cross-vote: create another vote and try submitting same credential
    vote_other = VoteRecord(
        creator_id=vote.creator_id,
        title="另一投票",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now,
    )
    opt_other = VoteOption(vote_id=vote_other.id, label="其它", position=0)
    session.add_all([vote_other, opt_other])
    session.commit()
    signer_provider.set_key(vote_other.id, b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1))

    # Cross-vote with period mismatch
    with pytest.raises(VoteBallotVerificationError) as exc_v1:
        verify_vote_ballot(
            session=session,
            crypto_engine=crypto,
            signer_provider=signer_provider,
            vote_id=vote_other.id,
            option_id=opt_other.id,
            credential=proof,  # proof.period == vote.id != vote_other.id
            now=now,
        )
    assert exc_v1.value.code == "invalid_period"

    # Cross-vote with updated period but signature signed for vote.id
    proof_other = VoteCredentialProof(
        sn=proof.sn,
        service="vote_ballot",
        period=vote_other.id,
        signature=proof.signature,
    )
    with pytest.raises(VoteBallotVerificationError) as exc_v2:
        verify_vote_ballot(
            session=session,
            crypto_engine=crypto,
            signer_provider=signer_provider,
            vote_id=vote_other.id,
            option_id=opt_other.id,
            credential=proof_other,
            now=now,
        )
    assert exc_v2.value.code == "invalid_signature"

    # 3. Tampered SN
    tampered_sn = "22223344556677889900aabbccddeeff"
    proof_tampered_sn = VoteCredentialProof(
        sn=tampered_sn,
        service="vote_ballot",
        period=vote.id,
        signature=proof.signature,
    )
    with pytest.raises(VoteBallotVerificationError) as exc_sn:
        verify_vote_ballot(
            session=session,
            crypto_engine=crypto,
            signer_provider=signer_provider,
            vote_id=vote.id,
            option_id=opt1.id,
            credential=proof_tampered_sn,
            now=now,
        )
    assert exc_sn.value.code == "invalid_signature"

    # 4. Tampered signature
    bad_sig_b64 = base64.b64encode(b"\x00" * 64).decode("ascii")
    proof_tampered_sig = VoteCredentialProof(
        sn=proof.sn,
        service="vote_ballot",
        period=vote.id,
        signature=bad_sig_b64,
    )
    with pytest.raises(VoteBallotVerificationError) as exc_sig:
        verify_vote_ballot(
            session=session,
            crypto_engine=crypto,
            signer_provider=signer_provider,
            vote_id=vote.id,
            option_id=opt1.id,
            credential=proof_tampered_sig,
            now=now,
        )
    assert exc_sig.value.code == "invalid_signature"


def test_verify_vote_ballot_business_rejections_without_db_writes():
    session, crypto, signer_provider, vote, opt1, opt2, proof, now = _seed_env()

    # 1. Option does not belong to vote
    opt_alien = VoteOption(vote_id=str(uuid.uuid4()), label="外部选项", position=0)
    session.add(opt_alien)
    session.commit()

    with pytest.raises(VoteBallotVerificationError) as exc_opt:
        verify_vote_ballot(
            session=session,
            crypto_engine=crypto,
            signer_provider=signer_provider,
            vote_id=vote.id,
            option_id=opt_alien.id,
            credential=proof,
            now=now,
        )
    assert exc_opt.value.code == "option_not_found"

    # 2. Vote closed or expired
    vote.status = "closed"
    session.commit()
    with pytest.raises(VoteBallotVerificationError) as exc_closed:
        verify_vote_ballot(
            session=session,
            crypto_engine=crypto,
            signer_provider=signer_provider,
            vote_id=vote.id,
            option_id=opt1.id,
            credential=proof,
            now=now,
        )
    assert exc_closed.value.code == "vote_closed"

    vote.status = "open"
    session.commit()
    # now >= closes_at
    with pytest.raises(VoteBallotVerificationError) as exc_exp:
        verify_vote_ballot(
            session=session,
            crypto_engine=crypto,
            signer_provider=signer_provider,
            vote_id=vote.id,
            option_id=opt1.id,
            credential=proof,
            now=vote.closes_at,
        )
    assert exc_exp.value.code == "vote_closed"

    # 3. Provider unavailable
    empty_provider = MockPerVoteSignerMaterialProvider()
    with pytest.raises(VoteBallotVerificationError) as exc_un:
        verify_vote_ballot(
            session=session,
            crypto_engine=crypto,
            signer_provider=empty_provider,
            vote_id=vote.id,
            option_id=opt1.id,
            credential=proof,
            now=now,
        )
    assert exc_un.value.code == "engine_unavailable"


def test_verify_vote_ballot_queries_no_user_or_issuance_records():
    session, crypto, signer_provider, vote, opt1, opt2, proof, now = _seed_env()

    # Record all SQL queries or check entity states
    queries = []
    from sqlalchemy import event

    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        queries.append(statement)

    event.listen(session.bind, "before_cursor_execute", before_cursor_execute)

    verify_vote_ballot(
        session=session,
        crypto_engine=crypto,
        signer_provider=signer_provider,
        vote_id=vote.id,
        option_id=opt1.id,
        credential=proof,
        now=now,
    )

    event.remove(session.bind, "before_cursor_execute", before_cursor_execute)

    # Assert no query mentions user or vote_credential_issues
    for q in queries:
        q_lower = q.lower()
        assert "users" not in q_lower
        assert "vote_credential_issues" not in q_lower
        assert "credential_ledger" not in q_lower
        assert "user_sessions" not in q_lower
        assert "insert" not in q_lower
        assert "update" not in q_lower
        assert "delete" not in q_lower
