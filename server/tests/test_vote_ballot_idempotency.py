import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE, SM2_PUBLIC_KEY_SIZE
from app.db.base import Base
from app.models.credential import ConsumedSN
from app.models.user import User
from app.models.vote import AnonymousBallot, BallotIdempotency, VoteOption, VoteRecord, VoteResultSnapshot
from app.schemas.vote import Accepted, VoteCredentialProof
from app.services.vote_ballot_verification import encode_vote_ballot_message
from app.services.vote_ballots import AnonymousBallotService, AnonymousBallotServiceError
from app.services.vote_tally_provider import VoteTallyMaterial


class IdempMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.valid_signatures: set[tuple[bytes, bytes, bytes]] = set()

    def add_valid_signature(self, message: bytes, signature: bytes, public_key: bytes) -> None:
        self.valid_signatures.add((message, signature, public_key))

    def blind_verify(self, *, message: bytes, signature: bytes, signer_public_key: bytes) -> bool:
        return (message, signature, signer_public_key) in self.valid_signatures

    def sm3_digest(self, message: bytes) -> bytes:
        import hashlib
        return hashlib.sha256(message).digest()

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right

    def sm2_sign(self, private_key: bytes, digest: bytes) -> bytes:
        return b"\x88" * 64

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        return signature == (b"\x88" * 64)


class MockTallyMaterialProvider:
    def __init__(self, material: VoteTallyMaterial) -> None:
        self.material = material

    @contextmanager
    def unlocked(self):
        yield self.material


class MockSignerProvider:
    def __init__(self, key_map: dict[str, bytes]) -> None:
        self.key_map = key_map

    def get_signer_private_key(self, *, vote_id: str) -> bytes | None:
        return None

    def get_signer_public_key(self, *, vote_id: str) -> bytes | None:
        return self.key_map.get(vote_id)


def _setup_env():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    sm = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = sm()

    crypto = IdempMockCryptoEngine()
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    creator = User(email="creator_idemp@edu.cn", role="teacher", status="active")
    sys_user = User(email="tally_sys_idemp@edu.cn", role="system", status="active")
    session.add_all([creator, sys_user])
    session.commit()

    vote = VoteRecord(
        creator_id=creator.id,
        title="幂等测试投票",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now - timedelta(hours=2),
    )
    opt1 = VoteOption(vote_id=vote.id, label="选项A", position=0)
    opt2 = VoteOption(vote_id=vote.id, label="选项B", position=1)
    session.add_all([vote, opt1, opt2])
    session.commit()

    vote_pubkey = b"\x04" + b"\x44" * (SM2_PUBLIC_KEY_SIZE - 1)
    signer_provider = MockSignerProvider({vote.id: vote_pubkey})

    tally_mat = VoteTallyMaterial(
        system_user_id=sys_user.id,
        certificate_serial="tally-cert-idemp-01",
        certificate_der=b"DER-CERT-TALLY",
        public_key=b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1),
        private_key=b"\x12" * SM2_PRIVATE_KEY_SIZE,
    )
    tally_provider = MockTallyMaterialProvider(tally_mat)

    service = AnonymousBallotService(
        session_factory=sm,
        crypto_engine=crypto,
        signer_provider=signer_provider,
        tally_material_provider=tally_provider,
    )

    return engine, sm, session, crypto, signer_provider, tally_provider, vote, opt1, opt2, vote_pubkey, now


def test_idempotent_replay_same_key_same_request_returns_201_without_duplicate():
    engine, sm, session, crypto, signer, tally, vote, opt1, opt2, pubkey, now = _setup_env()

    sn_hex = "11112233445566778899aabbccddeeff"
    sig_bytes = b"\x77" * 64
    msg = encode_vote_ballot_message(sn_hex=sn_hex, service="vote_ballot", vote_id=vote.id, option_id=opt1.id)
    crypto.add_valid_signature(msg, sig_bytes, pubkey)

    cred = VoteCredentialProof(
        sn=sn_hex,
        service="vote_ballot",
        period=vote.id,
        signature=base64.b64encode(sig_bytes).decode("ascii"),
    )

    service = AnonymousBallotService(
        session_factory=sm,
        crypto_engine=crypto,
        signer_provider=signer,
        tally_material_provider=tally,
    )

    # First submit
    res1 = service.submit(vote_id=vote.id, option_id=opt1.id, credential=cred, idempotency_key="idemp-key-same-01", now=now)
    assert res1.accepted is True

    verify_session = sm()
    assert verify_session.query(AnonymousBallot).count() == 1
    assert verify_session.query(VoteResultSnapshot).count() == 1

    # Replay same key same request
    res2 = service.submit(
        vote_id=vote.id,
        option_id=opt1.id,
        credential=cred,
        idempotency_key="idemp-key-same-01",
        now=now + timedelta(minutes=10),
    )
    assert res2.accepted is True

    # Check that counts did not increase
    assert verify_session.query(AnonymousBallot).count() == 1
    assert verify_session.query(VoteResultSnapshot).count() == 1


def test_idempotency_conflict_same_key_different_request():
    engine, sm, session, crypto, signer, tally, vote, opt1, opt2, pubkey, now = _setup_env()

    sn1 = "11112233445566778899aabbccddeeff"
    sig1 = b"\x77" * 64
    crypto.add_valid_signature(encode_vote_ballot_message(sn_hex=sn1, service="vote_ballot", vote_id=vote.id, option_id=opt1.id), sig1, pubkey)
    cred1 = VoteCredentialProof(sn=sn1, service="vote_ballot", period=vote.id, signature=base64.b64encode(sig1).decode("ascii"))

    service = AnonymousBallotService(
        session_factory=sm,
        crypto_engine=crypto,
        signer_provider=signer,
        tally_material_provider=tally,
    )

    service.submit(vote_id=vote.id, option_id=opt1.id, credential=cred1, idempotency_key="idemp-key-conflict-01", now=now)

    # Same key, but different option (opt2) and different credential
    sn2 = "22222233445566778899aabbccddeeff"
    sig2 = b"\x66" * 64
    crypto.add_valid_signature(encode_vote_ballot_message(sn_hex=sn2, service="vote_ballot", vote_id=vote.id, option_id=opt2.id), sig2, pubkey)
    cred2 = VoteCredentialProof(sn=sn2, service="vote_ballot", period=vote.id, signature=base64.b64encode(sig2).decode("ascii"))

    with pytest.raises(AnonymousBallotServiceError) as exc:
        service.submit(vote_id=vote.id, option_id=opt2.id, credential=cred2, idempotency_key="idemp-key-conflict-01", now=now)
    assert exc.value.code == "idempotency_conflict"


def test_same_sn_different_key_returns_409():
    engine, sm, session, crypto, signer, tally, vote, opt1, opt2, pubkey, now = _setup_env()

    sn = "33332233445566778899aabbccddeeff"
    sig = b"\x77" * 64
    crypto.add_valid_signature(encode_vote_ballot_message(sn_hex=sn, service="vote_ballot", vote_id=vote.id, option_id=opt1.id), sig, pubkey)
    cred = VoteCredentialProof(sn=sn, service="vote_ballot", period=vote.id, signature=base64.b64encode(sig).decode("ascii"))

    service = AnonymousBallotService(
        session_factory=sm,
        crypto_engine=crypto,
        signer_provider=signer,
        tally_material_provider=tally,
    )

    service.submit(vote_id=vote.id, option_id=opt1.id, credential=cred, idempotency_key="idemp-key-sn-00001", now=now)

    # Same SN, different idempotency key
    with pytest.raises(AnonymousBallotServiceError) as exc:
        service.submit(vote_id=vote.id, option_id=opt1.id, credential=cred, idempotency_key="idemp-key-sn-00002", now=now)
    assert exc.value.code in ("credential_consumed", "conflict")


def test_successful_request_replay_after_vote_closes_returns_original_success():
    engine, sm, session, crypto, signer, tally, vote, opt1, opt2, pubkey, now = _setup_env()

    sn = "44442233445566778899aabbccddeeff"
    sig = b"\x77" * 64
    crypto.add_valid_signature(encode_vote_ballot_message(sn_hex=sn, service="vote_ballot", vote_id=vote.id, option_id=opt1.id), sig, pubkey)
    cred = VoteCredentialProof(sn=sn, service="vote_ballot", period=vote.id, signature=base64.b64encode(sig).decode("ascii"))

    service = AnonymousBallotService(
        session_factory=sm,
        crypto_engine=crypto,
        signer_provider=signer,
        tally_material_provider=tally,
    )

    # Submit when open
    res1 = service.submit(vote_id=vote.id, option_id=opt1.id, credential=cred, idempotency_key="idemp-key-close-replay-01", now=now)
    assert res1.accepted is True

    # Vote closes
    closed_time = vote.closes_at + timedelta(hours=1)

    # Replay same key after vote closes: should still return Accepted without error
    res2 = service.submit(vote_id=vote.id, option_id=opt1.id, credential=cred, idempotency_key="idemp-key-close-replay-01", now=closed_time)
    assert res2.accepted is True
