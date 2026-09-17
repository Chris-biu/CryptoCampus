import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import threading
import uuid
import pytest
from sqlalchemy.orm import sessionmaker

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE, SM2_PUBLIC_KEY_SIZE
from app.db.session import create_db_engine, init_database
from app.models.credential import ConsumedSN
from app.models.user import User
from app.models.vote import AnonymousBallot, BallotIdempotency, VoteOption, VoteRecord, VoteResultSnapshot
from app.schemas.vote import VoteCredentialProof
from app.services.vote_ballot_verification import encode_vote_ballot_message
from app.services.vote_ballots import AnonymousBallotService, AnonymousBallotServiceError
from app.services.vote_tally_provider import VoteTallyMaterial


class ConcurrencyMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.valid_signatures: set[tuple[bytes, bytes, bytes]] = set()
        self._lock = threading.Lock()

    def add_valid_signature(self, message: bytes, signature: bytes, public_key: bytes) -> None:
        with self._lock:
            self.valid_signatures.add((message, signature, public_key))

    def blind_verify(self, *, message: bytes, signature: bytes, signer_public_key: bytes) -> bool:
        with self._lock:
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


def _setup_concurrency_env(tmp_path):
    db_file = tmp_path / f"test_concurrency_{uuid.uuid4().hex}.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    init_database(engine)
    sm = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = sm()

    crypto = ConcurrencyMockCryptoEngine()
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    creator = User(email="creator_conc@edu.cn", role="teacher", status="active")
    sys_user = User(email="tally_conc_sys@edu.cn", role="system", status="active")
    session.add_all([creator, sys_user])
    session.commit()

    vote = VoteRecord(
        creator_id=creator.id,
        title="并发计票测试",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now - timedelta(hours=2),
    )
    opt1 = VoteOption(vote_id=vote.id, label="选项甲", position=0)
    opt2 = VoteOption(vote_id=vote.id, label="选项乙", position=1)
    session.add_all([vote, opt1, opt2])
    session.commit()

    vote_pubkey = b"\x04" + b"\x44" * (SM2_PUBLIC_KEY_SIZE - 1)
    signer_provider = MockSignerProvider({vote.id: vote_pubkey})

    tally_mat = VoteTallyMaterial(
        system_user_id=sys_user.id,
        certificate_serial="tally-conc-01",
        certificate_der=b"DER-CERT-TALLY",
        public_key=b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1),
        private_key=b"\x12" * SM2_PRIVATE_KEY_SIZE,
    )
    tally_provider = MockTallyMaterialProvider(tally_mat)

    return sm, crypto, signer_provider, tally_provider, vote, opt1, opt2, vote_pubkey, now


def test_concurrent_same_sn_different_keys_persists_only_one(tmp_path):
    sm, crypto, signer, tally, vote, opt1, opt2, pubkey, now = _setup_concurrency_env(tmp_path)

    sn_hex = "55552233445566778899aabbccddeeff"
    sig_bytes = b"\x77" * 64
    msg = encode_vote_ballot_message(sn_hex=sn_hex, service="vote_ballot", vote_id=vote.id, option_id=opt1.id)
    crypto.add_valid_signature(msg, sig_bytes, pubkey)
    cred = VoteCredentialProof(sn=sn_hex, service="vote_ballot", period=vote.id, signature=base64.b64encode(sig_bytes).decode("ascii"))

    num_threads = 10
    barrier = threading.Barrier(num_threads)
    results = []
    errors = []

    def worker(i: int):
        service = AnonymousBallotService(
            session_factory=sm,
            crypto_engine=crypto,
            signer_provider=signer,
            tally_material_provider=tally,
        )
        barrier.wait()
        try:
            res = service.submit(
                vote_id=vote.id,
                option_id=opt1.id,
                credential=cred,
                idempotency_key=f"idemp-same-sn-{i:04d}-00001",
                now=now,
            )
            results.append(res)
        except AnonymousBallotServiceError as err:
            errors.append(err)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, i) for i in range(num_threads)]
        for f in futures:
            f.result()

    # Exactly one thread succeeds
    assert len(results) == 1
    assert len(errors) == num_threads - 1
    for err in errors:
        assert err.code in ("credential_consumed", "conflict")

    # In database: exactly 1 ballot, 1 consumed SN, 1 snapshot
    verify_session = sm()
    assert verify_session.query(AnonymousBallot).filter_by(vote_id=vote.id).count() == 1
    assert verify_session.query(ConsumedSN).filter_by(sn=bytes.fromhex(sn_hex)).count() == 1
    assert verify_session.query(VoteResultSnapshot).filter_by(vote_id=vote.id).count() == 1


def test_concurrent_same_key_same_request_all_consistent(tmp_path):
    sm, crypto, signer, tally, vote, opt1, opt2, pubkey, now = _setup_concurrency_env(tmp_path)

    sn_hex = "66662233445566778899aabbccddeeff"
    sig_bytes = b"\x77" * 64
    msg = encode_vote_ballot_message(sn_hex=sn_hex, service="vote_ballot", vote_id=vote.id, option_id=opt1.id)
    crypto.add_valid_signature(msg, sig_bytes, pubkey)
    cred = VoteCredentialProof(sn=sn_hex, service="vote_ballot", period=vote.id, signature=base64.b64encode(sig_bytes).decode("ascii"))

    num_threads = 10
    barrier = threading.Barrier(num_threads)
    results = []

    def worker():
        service = AnonymousBallotService(
            session_factory=sm,
            crypto_engine=crypto,
            signer_provider=signer,
            tally_material_provider=tally,
        )
        barrier.wait()
        res = service.submit(
            vote_id=vote.id,
            option_id=opt1.id,
            credential=cred,
            idempotency_key="idemp-same-key-all-000001",
            now=now,
        )
        results.append(res)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker) for _ in range(num_threads)]
        for f in futures:
            f.result()

    # All 10 return Accepted
    assert len(results) == num_threads
    for r in results:
        assert r.accepted is True

    # In database: exactly 1 ballot, 1 consumed SN, 1 idempotency, 1 snapshot
    verify_session = sm()
    assert verify_session.query(AnonymousBallot).filter_by(vote_id=vote.id).count() == 1
    assert verify_session.query(ConsumedSN).filter_by(sn=bytes.fromhex(sn_hex)).count() == 1
    assert verify_session.query(BallotIdempotency).count() == 1
    assert verify_session.query(VoteResultSnapshot).filter_by(vote_id=vote.id).count() == 1


def test_concurrent_different_credentials_no_vote_lost(tmp_path):
    sm, crypto, signer, tally, vote, opt1, opt2, pubkey, now = _setup_concurrency_env(tmp_path)

    num_voters = 10
    voters = []

    for i in range(num_voters):
        sn_hex = f"{i:02d}aabbccddeeff001122334455667788"
        target_opt = opt1 if i % 2 == 0 else opt2
        sig_bytes = b"\x77" * 64
        msg = encode_vote_ballot_message(sn_hex=sn_hex, service="vote_ballot", vote_id=vote.id, option_id=target_opt.id)
        crypto.add_valid_signature(msg, sig_bytes, pubkey)
        cred = VoteCredentialProof(sn=sn_hex, service="vote_ballot", period=vote.id, signature=base64.b64encode(sig_bytes).decode("ascii"))
        idemp_key = f"idemp-conc-diff-{i:04d}-0001"
        voters.append((target_opt.id, cred, idemp_key))

    barrier = threading.Barrier(num_voters)
    results = []

    def worker(opt_id, cred, key):
        service = AnonymousBallotService(
            session_factory=sm,
            crypto_engine=crypto,
            signer_provider=signer,
            tally_material_provider=tally,
        )
        barrier.wait()
        res = service.submit(
            vote_id=vote.id,
            option_id=opt_id,
            credential=cred,
            idempotency_key=key,
            now=now,
        )
        results.append(res)

    with ThreadPoolExecutor(max_workers=num_voters) as executor:
        futures = [executor.submit(worker, opt_id, cred, key) for opt_id, cred, key in voters]
        for f in futures:
            f.result()

    # All 10 voters succeed
    assert len(results) == num_voters

    # Verify database state
    verify_session = sm()
    ballots = verify_session.query(AnonymousBallot).filter_by(vote_id=vote.id).all()
    assert len(ballots) == num_voters

    consumed = verify_session.query(ConsumedSN).filter_by(service="vote_ballot").all()
    assert len(consumed) == num_voters

    snapshots = (
        verify_session.query(VoteResultSnapshot)
        .filter_by(vote_id=vote.id)
        .order_by(VoteResultSnapshot.version.asc())
        .all()
    )
    # Versions must be 1 to 10 consecutive
    versions = [s.version for s in snapshots]
    assert versions == list(range(1, num_voters + 1))

    # Latest snapshot
    latest = snapshots[-1]
    assert latest.version == num_voters
    assert latest.total == num_voters
    counts = json.loads(latest.counts_json)
    assert counts[opt1.id] == 5
    assert counts[opt2.id] == 5
    assert sum(counts.values()) == num_voters

    # Each snapshot's signature is valid
    for s in snapshots:
        assert crypto.sm2_verify(s.signer_public_key, s.result_digest, s.signature) is True
