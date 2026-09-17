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
from app.models.audit import AuditLog
from app.models.credential import ConsumedSN
from app.models.user import User
from app.models.vote import AnonymousBallot, BallotIdempotency, VoteOption, VoteRecord, VoteResultSnapshot
from app.schemas.vote import VoteCredentialProof
from app.services.vote_ballot_verification import encode_vote_ballot_message
from app.services.vote_ballots import AnonymousBallotService, AnonymousBallotServiceError
from app.services.vote_tally_provider import VoteTallyMaterial, VoteTallyMaterialUnavailableError


class RollbackMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.valid_signatures: set[tuple[bytes, bytes, bytes]] = set()
        self.fail_sign = False
        self.fail_verify = False

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
        if self.fail_sign:
            raise RuntimeError("SM2 sign injected error")
        return b"\x88" * 64

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        if self.fail_verify:
            return False
        return signature == (b"\x88" * 64)


class MockTallyMaterialProvider:
    def __init__(self, material: VoteTallyMaterial) -> None:
        self.material = material
        self.fail_unlock = False

    @contextmanager
    def unlocked(self):
        if self.fail_unlock:
            raise VoteTallyMaterialUnavailableError("engine_unavailable", "Injected unlock failure")
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

    crypto = RollbackMockCryptoEngine()
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    creator = User(email="creator_rb@edu.cn", role="teacher", status="active")
    sys_user = User(email="tally_sys_rb@edu.cn", role="system", status="active")
    session.add_all([creator, sys_user])
    session.commit()

    vote = VoteRecord(
        creator_id=creator.id,
        title="回滚测试投票",
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
        certificate_serial="tally-cert-rb-01",
        certificate_der=b"DER-CERT-TALLY",
        public_key=b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1),
        private_key=b"\x12" * SM2_PRIVATE_KEY_SIZE,
    )
    tally_provider = MockTallyMaterialProvider(tally_mat)

    return engine, sm, session, crypto, signer_provider, tally_provider, vote, opt1, opt2, vote_pubkey, now


def _make_valid_cred(crypto, vote_id, option_id, pubkey, sn_hex):
    sig_bytes = b"\x77" * 64
    msg = encode_vote_ballot_message(sn_hex=sn_hex, service="vote_ballot", vote_id=vote_id, option_id=option_id)
    crypto.add_valid_signature(msg, sig_bytes, pubkey)
    return VoteCredentialProof(
        sn=sn_hex,
        service="vote_ballot",
        period=vote_id,
        signature=base64.b64encode(sig_bytes).decode("ascii"),
    )


def test_rollback_on_tally_provider_unlock_failure():
    engine, sm, session, crypto, signer, tally, vote, opt1, opt2, pubkey, now = _setup_env()

    tally.fail_unlock = True
    cred = _make_valid_cred(crypto, vote.id, opt1.id, pubkey, "00110011001100110011001100110011")

    service = AnonymousBallotService(
        session_factory=sm,
        crypto_engine=crypto,
        signer_provider=signer,
        tally_material_provider=tally,
    )

    with pytest.raises(AnonymousBallotServiceError) as exc:
        service.submit(vote_id=vote.id, option_id=opt1.id, credential=cred, idempotency_key="idemp-rb-unlock-01", now=now)
    assert exc.value.code == "engine_unavailable"

    verify_session = sm()
    assert verify_session.query(ConsumedSN).count() == 0
    assert verify_session.query(AnonymousBallot).count() == 0
    assert verify_session.query(BallotIdempotency).count() == 0
    assert verify_session.query(VoteResultSnapshot).count() == 0
    assert verify_session.query(AuditLog).filter_by(action="vote.result.sign").count() == 0


def test_rollback_on_tally_signing_failure():
    engine, sm, session, crypto, signer, tally, vote, opt1, opt2, pubkey, now = _setup_env()

    crypto.fail_sign = True
    cred = _make_valid_cred(crypto, vote.id, opt1.id, pubkey, "00220022002200220022002200220022")

    service = AnonymousBallotService(
        session_factory=sm,
        crypto_engine=crypto,
        signer_provider=signer,
        tally_material_provider=tally,
    )

    with pytest.raises(Exception):
        service.submit(vote_id=vote.id, option_id=opt1.id, credential=cred, idempotency_key="idemp-rb-sign-01", now=now)

    verify_session = sm()
    assert verify_session.query(ConsumedSN).count() == 0
    assert verify_session.query(AnonymousBallot).count() == 0
    assert verify_session.query(BallotIdempotency).count() == 0
    assert verify_session.query(VoteResultSnapshot).count() == 0
    assert verify_session.query(AuditLog).filter_by(action="vote.result.sign").count() == 0


def test_rollback_on_tally_self_verify_failure():
    engine, sm, session, crypto, signer, tally, vote, opt1, opt2, pubkey, now = _setup_env()

    crypto.fail_verify = True
    cred = _make_valid_cred(crypto, vote.id, opt1.id, pubkey, "00330033003300330033003300330033")

    service = AnonymousBallotService(
        session_factory=sm,
        crypto_engine=crypto,
        signer_provider=signer,
        tally_material_provider=tally,
    )

    with pytest.raises(AnonymousBallotServiceError) as exc:
        service.submit(vote_id=vote.id, option_id=opt1.id, credential=cred, idempotency_key="idemp-rb-selfver-01", now=now)
    assert exc.value.code in ("signature_self_verify_failed", "internal_error")

    verify_session = sm()
    assert verify_session.query(ConsumedSN).count() == 0
    assert verify_session.query(AnonymousBallot).count() == 0
    assert verify_session.query(BallotIdempotency).count() == 0
    assert verify_session.query(VoteResultSnapshot).count() == 0
    assert verify_session.query(AuditLog).filter_by(action="vote.result.sign").count() == 0
