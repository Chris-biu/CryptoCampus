import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE, SM2_PUBLIC_KEY_SIZE
from app.db.base import Base
from app.models.audit import AuditLog
from app.models.credential import ConsumedSN
from app.models.user import User
from app.models.vote import (
    AnonymousBallot,
    BallotIdempotency,
    VoteOption,
    VoteRecord,
    VoteResultSnapshot,
)
from app.schemas.vote import Accepted, VoteCredentialProof
from app.services.vote_ballot_verification import encode_vote_ballot_message
from app.services.vote_ballots import AnonymousBallotService
from app.services.vote_tally_provider import VoteTallyMaterial


class SubmitMockCryptoEngine(MockCryptoEngine):
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

    crypto = SubmitMockCryptoEngine()
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    creator = User(email="creator_sub@edu.cn", role="teacher", status="active")
    sys_user = User(email="tally_sys@edu.cn", role="system", status="active")
    session.add_all([creator, sys_user])
    session.commit()

    vote = VoteRecord(
        creator_id=creator.id,
        title="理事会投票",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now - timedelta(hours=2),
    )
    opt1 = VoteOption(vote_id=vote.id, label="同意", position=0)
    opt2 = VoteOption(vote_id=vote.id, label="反对", position=1)
    session.add_all([vote, opt1, opt2])
    session.commit()

    vote_pubkey = b"\x04" + b"\x44" * (SM2_PUBLIC_KEY_SIZE - 1)
    signer_provider = MockSignerProvider({vote.id: vote_pubkey})

    tally_mat = VoteTallyMaterial(
        system_user_id=sys_user.id,
        certificate_serial="tally-cert-01",
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

    return engine, sm, session, crypto, signer_provider, tally_provider, vote, opt1, opt2, vote_pubkey, now, sys_user


def test_submit_ballot_creates_records_and_snapshot_version_1():
    engine, sm, session, crypto, signer, tally, vote, opt1, opt2, pubkey, now, sys_user = _setup_env()

    sn_hex = "00112233445566778899aabbccddeeff"
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

    res = service.submit(
        vote_id=vote.id,
        option_id=opt1.id,
        credential=cred,
        idempotency_key="idemp-key-ballot-00000001",
        now=now,
    )
    assert isinstance(res, Accepted)
    assert res.accepted is True

    # Use independent session to verify persistence
    verify_session = sm()

    # 1. ConsumedSN exists
    consumed = verify_session.get(ConsumedSN, (bytes.fromhex(sn_hex), "vote_ballot"))
    assert consumed is not None

    # 2. AnonymousBallot exists
    ballot = verify_session.query(AnonymousBallot).filter_by(vote_id=vote.id).one()
    assert ballot.option_id == opt1.id
    assert ballot.credential_sn == bytes.fromhex(sn_hex)

    # 3. BallotIdempotency exists
    idemp = verify_session.query(BallotIdempotency).filter_by(ballot_id=ballot.id).one()
    assert idemp is not None

    # 4. VoteResultSnapshot version=1 exists
    snapshot = verify_session.query(VoteResultSnapshot).filter_by(vote_id=vote.id, version=1).one()
    assert snapshot.total == 1
    counts = json.loads(snapshot.counts_json)
    assert counts[opt1.id] == 1
    assert counts[opt2.id] == 0
    assert snapshot.signature == b"\x88" * 64

    # 5. AuditLog exists
    audit = verify_session.query(AuditLog).filter_by(action="vote.result.sign").one()
    assert audit.actor == sys_user.id
    assert audit.target == f"vote:{vote.id}"
    assert audit.detail_hash == snapshot.result_digest


def test_second_ballot_increments_snapshot_to_version_2():
    engine, sm, session, crypto, signer, tally, vote, opt1, opt2, pubkey, now, sys_user = _setup_env()

    service = AnonymousBallotService(
        session_factory=sm,
        crypto_engine=crypto,
        signer_provider=signer,
        tally_material_provider=tally,
    )

    # First ballot: opt1
    sn1 = "00112233445566778899aabbccddeeff"
    sig1 = b"\x77" * 64
    crypto.add_valid_signature(
        encode_vote_ballot_message(sn_hex=sn1, service="vote_ballot", vote_id=vote.id, option_id=opt1.id),
        sig1,
        pubkey,
    )
    cred1 = VoteCredentialProof(sn=sn1, service="vote_ballot", period=vote.id, signature=base64.b64encode(sig1).decode("ascii"))
    service.submit(vote_id=vote.id, option_id=opt1.id, credential=cred1, idempotency_key="idemp-key-ballot-00000001", now=now)

    # Second ballot: opt2
    sn2 = "ffffeeddccbbaa998877665544332211"
    sig2 = b"\x66" * 64
    crypto.add_valid_signature(
        encode_vote_ballot_message(sn_hex=sn2, service="vote_ballot", vote_id=vote.id, option_id=opt2.id),
        sig2,
        pubkey,
    )
    cred2 = VoteCredentialProof(sn=sn2, service="vote_ballot", period=vote.id, signature=base64.b64encode(sig2).decode("ascii"))
    service.submit(vote_id=vote.id, option_id=opt2.id, credential=cred2, idempotency_key="idemp-key-ballot-00000002", now=now + timedelta(minutes=1))

    # Verify latest snapshot version=2
    verify_session = sm()
    snap2 = (
        verify_session.query(VoteResultSnapshot)
        .filter_by(vote_id=vote.id)
        .order_by(VoteResultSnapshot.version.desc())
        .first()
    )
    assert snap2.version == 2
    assert snap2.total == 2
    counts = json.loads(snap2.counts_json)
    assert counts[opt1.id] == 1
    assert counts[opt2.id] == 1
