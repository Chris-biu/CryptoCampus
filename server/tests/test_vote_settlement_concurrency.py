import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import threading
import uuid
import pytest
from sqlalchemy import create_engine, event
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
    VoteOption,
    VoteRecord,
    VoteResultSnapshot,
)
from app.schemas.vote import VoteCredentialProof
from app.services.vote_ballots import AnonymousBallotService, AnonymousBallotServiceError
from app.services.vote_settlement import (
    FakeClock,
    VoteSettlementError,
    VoteSettlementService,
)
from app.services.vote_signer import VoteSignerMaterialProvider
from app.services.vote_tally_provider import (
    VoteTallyMaterial,
    VoteTallyMaterialUnavailableError,
)


class ConcurrencyCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fail_sign = False
        self.fail_verify = False
        self.valid_signatures = set()
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
        if self.fail_sign:
            raise RuntimeError("Injected SM2 signing failure")
        return b"\x77" * 64

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        if self.fail_verify:
            return False
        return signature == (b"\x77" * 64)


class MockTallyMaterialProvider:
    def __init__(self, material: VoteTallyMaterial) -> None:
        self.material = material

    @contextmanager
    def unlocked(self):
        yield self.material


class MockSignerProvider:
    def get_signer_private_key(self, *, vote_id: str) -> bytes | None:
        return None


@pytest.fixture
def db_session_factory():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return factory


@pytest.fixture
def tally_material():
    return VoteTallyMaterial(
        system_user_id="sys-user-concurrency-01",
        certificate_serial="cert-concurrency-01",
        certificate_der=b"DER-CONCURRENCY-CERT",
        public_key=b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1),
        private_key=b"\x12" * SM2_PRIVATE_KEY_SIZE,
    )


def test_concurrent_settlement_produces_single_snapshot_and_identical_results(
    db_session_factory, tally_material
):
    session: Session = db_session_factory()
    creator = User(email="creator_conc@example.com", role="teacher", status="active")
    session.add(creator)
    session.commit()

    t0 = datetime(2026, 9, 10, 8, 0, 0, tzinfo=timezone.utc)
    closes_at = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

    vote = VoteRecord(
        creator_id=creator.id,
        title="并发结算测试",
        scope="public",
        closes_at=closes_at,
        status="open",
        created_at=t0,
    )
    session.add(vote)
    session.commit()

    opt1 = VoteOption(vote_id=vote.id, label="A", position=0)
    opt2 = VoteOption(vote_id=vote.id, label="B", position=1)
    session.add_all([opt1, opt2])
    session.commit()

    # Add 2 ballots
    b1 = AnonymousBallot(
        vote_id=vote.id,
        option_id=opt1.id,
        credential_sn=b"\x01" * 16,
        credential_service="vote_ballot",
        credential_period="2026-09",
        credential_signature=b"\x11" * 64,
        created_at=closes_at - timedelta(minutes=5),
    )
    b2 = AnonymousBallot(
        vote_id=vote.id,
        option_id=opt2.id,
        credential_sn=b"\x02" * 16,
        credential_service="vote_ballot",
        credential_period="2026-09",
        credential_signature=b"\x12" * 64,
        created_at=closes_at - timedelta(minutes=2),
    )
    session.add_all([b1, b2])
    session.commit()
    vote_id = vote.id
    session.close()

    crypto = ConcurrencyCryptoEngine()
    settle_time = closes_at + timedelta(minutes=5)
    clock = FakeClock(settle_time)
    tally_prov = MockTallyMaterialProvider(tally_material)

    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto,
        tally_material_provider=tally_prov,
        clock=clock,
    )

    results = []
    errors = []

    def worker():
        try:
            snap = service.settle(vote_id=vote_id)
            results.append(snap)
        except Exception as e:
            errors.append(e)

    # Concurrently launch 4 threads attempting to settle the exact same vote
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(worker) for _ in range(4)]
        for f in futures:
            f.result()

    assert len(errors) == 0
    assert len(results) == 4

    # All threads got the exact same snapshot id and signature
    first_id = results[0].id
    first_sig = results[0].signature
    for r in results:
        assert r.id == first_id
        assert r.signature == first_sig
        assert r.is_final is True
        assert r.total == 2

    # Verify DB state: exactly 1 snapshot, 1 audit log, status published
    sess = db_session_factory()
    v_db = sess.get(VoteRecord, vote_id)
    assert v_db.status == "published"
    assert v_db.final_snapshot_id == first_id

    final_snaps = sess.query(VoteResultSnapshot).filter_by(vote_id=vote_id, is_final=True).all()
    assert len(final_snaps) == 1

    audits = sess.query(AuditLog).filter_by(action="vote.settle", target=f"vote:{vote_id}").all()
    assert len(audits) == 1
    sess.close()


def test_rollback_on_signing_failure(db_session_factory, tally_material):
    session: Session = db_session_factory()
    creator = User(email="creator_rb1@example.com", role="teacher", status="active")
    session.add(creator)
    session.commit()

    closes_at = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    vote = VoteRecord(
        creator_id=creator.id,
        title="签名失败回滚测试",
        scope="public",
        closes_at=closes_at,
        status="open",
        created_at=closes_at - timedelta(hours=1),
    )
    session.add(vote)
    session.commit()

    opt = VoteOption(vote_id=vote.id, label="A", position=0)
    session.add(opt)
    session.commit()
    vote_id = vote.id
    session.close()

    crypto = ConcurrencyCryptoEngine()
    crypto.fail_sign = True  # Inject failure in SM2 sign

    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto,
        tally_material_provider=MockTallyMaterialProvider(tally_material),
        clock=FakeClock(closes_at + timedelta(minutes=1)),
    )

    with pytest.raises(Exception):
        service.settle(vote_id=vote_id)

    # Verify complete rollback
    sess = db_session_factory()
    v_db = sess.get(VoteRecord, vote_id)
    assert v_db.status == "open"
    assert v_db.settled_at is None
    assert v_db.final_snapshot_id is None
    assert sess.query(VoteResultSnapshot).filter_by(vote_id=vote_id).count() == 0
    assert sess.query(AuditLog).filter_by(action="vote.settle", target=f"vote:{vote_id}").count() == 0
    sess.close()


def test_rollback_on_self_verify_failure(db_session_factory, tally_material):
    session: Session = db_session_factory()
    creator = User(email="creator_rb2@example.com", role="teacher", status="active")
    session.add(creator)
    session.commit()

    closes_at = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    vote = VoteRecord(
        creator_id=creator.id,
        title="自验失败回滚测试",
        scope="public",
        closes_at=closes_at,
        status="open",
        created_at=closes_at - timedelta(hours=1),
    )
    session.add(vote)
    session.commit()

    opt = VoteOption(vote_id=vote.id, label="A", position=0)
    session.add(opt)
    session.commit()
    vote_id = vote.id
    session.close()

    crypto = ConcurrencyCryptoEngine()
    crypto.fail_verify = True  # Inject failure in SM2 self-verify

    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto,
        tally_material_provider=MockTallyMaterialProvider(tally_material),
        clock=FakeClock(closes_at + timedelta(minutes=1)),
    )

    with pytest.raises(VoteSettlementError) as exc_info:
        service.settle(vote_id=vote_id)

    assert exc_info.value.code == "signature_self_verify_failed"

    # Verify complete rollback
    sess = db_session_factory()
    v_db = sess.get(VoteRecord, vote_id)
    assert v_db.status == "open"
    assert v_db.settled_at is None
    assert v_db.final_snapshot_id is None
    assert sess.query(VoteResultSnapshot).filter_by(vote_id=vote_id).count() == 0
    assert sess.query(AuditLog).filter_by(action="vote.settle", target=f"vote:{vote_id}").count() == 0
    sess.close()


def test_settle_and_ballot_submission_race(db_session_factory, tally_material):
    session: Session = db_session_factory()
    creator = User(email="creator_race@example.com", role="teacher", status="active")
    session.add(creator)
    session.commit()

    closes_at = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    vote = VoteRecord(
        creator_id=creator.id,
        title="结算与提交选票竞争",
        scope="public",
        closes_at=closes_at,
        status="open",
        created_at=closes_at - timedelta(hours=1),
    )
    session.add(vote)
    session.commit()

    opt = VoteOption(vote_id=vote.id, label="A", position=0)
    session.add(opt)
    session.commit()

    vote_id = vote.id
    opt_id = opt.id
    session.close()

    crypto = ConcurrencyCryptoEngine()
    tally_prov = MockTallyMaterialProvider(tally_material)
    signer_prov = MockSignerProvider()

    settle_service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto,
        tally_material_provider=tally_prov,
        clock=FakeClock(closes_at + timedelta(seconds=1)),
    )
    ballot_service = AnonymousBallotService(
        crypto_engine=crypto,
        signer_provider=signer_prov,
        tally_material_provider=tally_prov,
        session_factory=db_session_factory,
    )

    # First settle the vote to published
    final_snap = settle_service.settle(vote_id=vote_id)
    assert final_snap.is_final is True

    # Now attempt ballot submission on published vote
    proof = VoteCredentialProof(
        sn="01" * 16,
        service="vote_ballot",
        period="2026-09",
        signature=base64.b64encode(b"\x99" * 64).decode("ascii"),
    )

    with pytest.raises(AnonymousBallotServiceError) as exc_info:
        ballot_service.submit(
            vote_id=vote_id,
            option_id=opt_id,
            credential=proof,
            idempotency_key="idempotency-key-race-01",
            now=closes_at + timedelta(seconds=2),
        )

    # Should be rejected because vote is no longer open / already closed
    assert exc_info.value.code == "vote_closed"
