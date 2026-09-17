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
    VoteOption,
    VoteRecord,
    VoteResultSnapshot,
)
from app.services.vote_settlement import (
    FakeClock,
    VoteSettlementError,
    VoteSettlementService,
)
from app.services.vote_tally_provider import (
    VoteTallyMaterial,
    VoteTallyMaterialUnavailableError,
)


class SettlementMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        import hashlib
        return hashlib.sha256(message).digest()

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right

    def sm2_sign(self, private_key: bytes, digest: bytes) -> bytes:
        return b"\x77" * 64

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        return signature == (b"\x77" * 64)


class MockTallyMaterialProvider:
    def __init__(self, material: VoteTallyMaterial | None = None, should_fail: bool = False) -> None:
        self.material = material
        self.should_fail = should_fail

    @contextmanager
    def unlocked(self):
        if self.should_fail or self.material is None:
            raise VoteTallyMaterialUnavailableError("Material unavailable")
        yield self.material


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
def crypto_engine():
    return SettlementMockCryptoEngine()


@pytest.fixture
def tally_material():
    return VoteTallyMaterial(
        system_user_id="sys-user-settle-01",
        certificate_serial="cert-settle-01",
        certificate_der=b"DER-SETTLE-CERT",
        public_key=b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1),
        private_key=b"\x12" * SM2_PRIVATE_KEY_SIZE,
    )


@pytest.fixture
def sample_vote(db_session_factory):
    session: Session = db_session_factory()
    creator = User(email="creator_settle@example.com", role="teacher", status="active")
    session.add(creator)
    session.commit()

    t0 = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    closes_at = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    vote = VoteRecord(
        creator_id=creator.id,
        title="结算测试投票",
        scope="public",
        closes_at=closes_at,
        status="open",
        created_at=t0,
    )
    session.add(vote)
    session.commit()

    opt1 = VoteOption(vote_id=vote.id, label="Option A", position=0)
    opt2 = VoteOption(vote_id=vote.id, label="Option B", position=1)
    session.add_all([opt1, opt2])
    session.commit()

    vote_id = vote.id
    opt1_id = opt1.id
    opt2_id = opt2.id
    session.close()
    return {"vote_id": vote_id, "opt1_id": opt1_id, "opt2_id": opt2_id, "closes_at": closes_at}


def test_settle_before_closes_at_fails(db_session_factory, crypto_engine, tally_material, sample_vote):
    vote_id = sample_vote["vote_id"]
    closes_at = sample_vote["closes_at"]

    clock = FakeClock(closes_at - timedelta(seconds=1))
    tally_provider = MockTallyMaterialProvider(tally_material)

    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto_engine,
        tally_material_provider=tally_provider,
        clock=clock,
    )

    with pytest.raises(VoteSettlementError) as exc_info:
        service.settle(vote_id=vote_id)

    assert exc_info.value.code == "vote_not_closed"

    session = db_session_factory()
    vote = session.get(VoteRecord, vote_id)
    assert vote.status == "open"
    assert vote.settled_at is None
    assert vote.final_snapshot_id is None
    assert session.query(VoteResultSnapshot).filter_by(vote_id=vote_id).count() == 0
    session.close()


def test_settle_exactly_at_closes_at_succeeds(db_session_factory, crypto_engine, tally_material, sample_vote):
    vote_id = sample_vote["vote_id"]
    closes_at = sample_vote["closes_at"]

    clock = FakeClock(closes_at)
    tally_provider = MockTallyMaterialProvider(tally_material)

    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto_engine,
        tally_material_provider=tally_provider,
        clock=clock,
    )

    snapshot = service.settle(vote_id=vote_id)

    assert snapshot is not None
    assert snapshot.is_final is True
    assert snapshot.vote_id == vote_id
    assert snapshot.total == 0
    assert snapshot.version == 1

    session = db_session_factory()
    vote = session.get(VoteRecord, vote_id)
    assert vote.status == "published"
    settled_at_utc = (
        vote.settled_at.replace(tzinfo=timezone.utc)
        if vote.settled_at.tzinfo is None
        else vote.settled_at
    )
    assert settled_at_utc == closes_at
    assert vote.final_snapshot_id == snapshot.id

    # Verify audit log recorded
    audit = session.query(AuditLog).filter_by(action="vote.settle", target=f"vote:{vote_id}").one_or_none()
    assert audit is not None
    assert audit.actor == tally_material.system_user_id
    assert audit.detail_hash == snapshot.result_digest
    session.close()


def test_settle_after_closes_at_with_ballots(db_session_factory, crypto_engine, tally_material, sample_vote):
    vote_id = sample_vote["vote_id"]
    opt1_id = sample_vote["opt1_id"]
    opt2_id = sample_vote["opt2_id"]
    closes_at = sample_vote["closes_at"]

    session = db_session_factory()
    # Insert 2 ballots for opt1, 1 ballot for opt2 before closes_at
    b1 = AnonymousBallot(
        vote_id=vote_id,
        option_id=opt1_id,
        credential_sn=b"\x01" * 16,
        credential_service="vote_ballot",
        credential_period="2026-09",
        credential_signature=b"\x11" * 64,
        created_at=closes_at - timedelta(minutes=10),
    )
    b2 = AnonymousBallot(
        vote_id=vote_id,
        option_id=opt1_id,
        credential_sn=b"\x02" * 16,
        credential_service="vote_ballot",
        credential_period="2026-09",
        credential_signature=b"\x12" * 64,
        created_at=closes_at - timedelta(minutes=5),
    )
    b3 = AnonymousBallot(
        vote_id=vote_id,
        option_id=opt2_id,
        credential_sn=b"\x03" * 16,
        credential_service="vote_ballot",
        credential_period="2026-09",
        credential_signature=b"\x13" * 64,
        created_at=closes_at - timedelta(minutes=1),
    )
    # Existing intermediate snapshot from submission
    snap_intermediate = VoteResultSnapshot(
        vote_id=vote_id,
        version=3,
        counts_json=json.dumps({opt1_id: 2, opt2_id: 1}),
        total=3,
        result_digest=b"\xaa" * 32,
        signature=b"\x77" * 64,
        signer_certificate=tally_material.certificate_der,
        signer_public_key=tally_material.public_key,
        published_at=closes_at - timedelta(minutes=1),
        is_final=False,
    )
    session.add_all([b1, b2, b3, snap_intermediate])
    session.commit()
    session.close()

    settle_time = closes_at + timedelta(minutes=15)
    clock = FakeClock(settle_time)
    tally_provider = MockTallyMaterialProvider(tally_material)

    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto_engine,
        tally_material_provider=tally_provider,
        clock=clock,
    )

    final_snap = service.settle(vote_id=vote_id)

    assert final_snap.is_final is True
    assert final_snap.version == 4  # intermediate was 3, final is 4
    assert final_snap.total == 3
    counts = final_snap.get_counts()
    assert counts[opt1_id] == 2
    assert counts[opt2_id] == 1


def test_settle_defensive_filter_excludes_late_ballots(db_session_factory, crypto_engine, tally_material, sample_vote):
    vote_id = sample_vote["vote_id"]
    opt1_id = sample_vote["opt1_id"]
    opt2_id = sample_vote["opt2_id"]
    closes_at = sample_vote["closes_at"]

    session = db_session_factory()
    # 1 valid ballot before closes_at
    b_valid = AnonymousBallot(
        vote_id=vote_id,
        option_id=opt1_id,
        credential_sn=b"\x01" * 16,
        credential_service="vote_ballot",
        credential_period="2026-09",
        credential_signature=b"\x11" * 64,
        created_at=closes_at - timedelta(seconds=1),
    )
    # 1 late ballot created after closes_at (defensive filter test)
    b_late = AnonymousBallot(
        vote_id=vote_id,
        option_id=opt2_id,
        credential_sn=b"\x02" * 16,
        credential_service="vote_ballot",
        credential_period="2026-09",
        credential_signature=b"\x12" * 64,
        created_at=closes_at + timedelta(seconds=1),
    )
    session.add_all([b_valid, b_late])
    session.commit()
    session.close()

    clock = FakeClock(closes_at + timedelta(minutes=5))
    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto_engine,
        tally_material_provider=MockTallyMaterialProvider(tally_material),
        clock=clock,
    )

    final_snap = service.settle(vote_id=vote_id)

    assert final_snap.total == 1
    counts = final_snap.get_counts()
    assert counts[opt1_id] == 1
    assert counts[opt2_id] == 0


def test_settle_idempotent_replay(db_session_factory, crypto_engine, tally_material, sample_vote):
    vote_id = sample_vote["vote_id"]
    closes_at = sample_vote["closes_at"]

    clock = FakeClock(closes_at + timedelta(minutes=1))
    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto_engine,
        tally_material_provider=MockTallyMaterialProvider(tally_material),
        clock=clock,
    )

    first_snap = service.settle(vote_id=vote_id)

    # Advance clock by 10 minutes and call again
    clock.advance(timedelta(minutes=10))
    second_snap = service.settle(vote_id=vote_id)

    assert first_snap.id == second_snap.id
    assert first_snap.published_at == second_snap.published_at
    assert first_snap.signature == second_snap.signature

    session = db_session_factory()
    # Ensure only 1 snapshot and 1 audit log exist
    assert session.query(VoteResultSnapshot).filter_by(vote_id=vote_id).count() == 1
    assert session.query(AuditLog).filter_by(action="vote.settle", target=f"vote:{vote_id}").count() == 1
    session.close()


def test_settle_nonexistent_vote_fails(db_session_factory, crypto_engine, tally_material):
    clock = FakeClock(datetime.now(timezone.utc))
    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto_engine,
        tally_material_provider=MockTallyMaterialProvider(tally_material),
        clock=clock,
    )

    with pytest.raises(VoteSettlementError) as exc_info:
        service.settle(vote_id=str(uuid.uuid4()))

    assert exc_info.value.code == "vote_not_found"


def test_settle_tally_material_unavailable_fails(db_session_factory, crypto_engine, sample_vote):
    vote_id = sample_vote["vote_id"]
    closes_at = sample_vote["closes_at"]

    clock = FakeClock(closes_at + timedelta(minutes=1))
    failing_provider = MockTallyMaterialProvider(should_fail=True)

    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto_engine,
        tally_material_provider=failing_provider,
        clock=clock,
    )

    with pytest.raises(VoteSettlementError) as exc_info:
        service.settle(vote_id=vote_id)

    assert exc_info.value.code == "engine_unavailable"

    # Transaction rolled back: vote status still open
    session = db_session_factory()
    vote = session.get(VoteRecord, vote_id)
    assert vote.status == "open"
    assert vote.settled_at is None
    assert vote.final_snapshot_id is None
    session.close()


def test_settle_due_scans_and_settles_due_votes(db_session_factory, crypto_engine, tally_material):
    session = db_session_factory()
    creator = User(email="creator_due@example.com", role="teacher", status="active")
    session.add(creator)
    session.commit()

    t0 = datetime(2026, 9, 10, 8, 0, 0, tzinfo=timezone.utc)
    t_due1 = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    t_due2 = datetime(2026, 9, 10, 11, 0, 0, tzinfo=timezone.utc)
    t_future = datetime(2026, 9, 10, 13, 0, 0, tzinfo=timezone.utc)

    v1 = VoteRecord(creator_id=creator.id, title="V1 Due", scope="public", closes_at=t_due1, status="open", created_at=t0)
    v2 = VoteRecord(creator_id=creator.id, title="V2 Due", scope="public", closes_at=t_due2, status="open", created_at=t0)
    v3 = VoteRecord(creator_id=creator.id, title="V3 Not Due", scope="public", closes_at=t_future, status="open", created_at=t0)
    session.add_all([v1, v2, v3])
    session.commit()

    opt1 = VoteOption(vote_id=v1.id, label="A", position=0)
    opt2 = VoteOption(vote_id=v2.id, label="A", position=0)
    opt3 = VoteOption(vote_id=v3.id, label="A", position=0)
    session.add_all([opt1, opt2, opt3])
    session.commit()
    session.close()

    scan_time = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    clock = FakeClock(scan_time)
    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto_engine,
        tally_material_provider=MockTallyMaterialProvider(tally_material),
        clock=clock,
    )

    settled_list = service.settle_due(limit=10)

    assert len(settled_list) == 2
    settled_ids = {s.vote_id for s in settled_list}
    assert settled_ids == {v1.id, v2.id}

    session = db_session_factory()
    assert session.get(VoteRecord, v1.id).status == "published"
    assert session.get(VoteRecord, v2.id).status == "published"
    assert session.get(VoteRecord, v3.id).status == "open"
    session.close()


def test_settle_due_respects_limit(db_session_factory, crypto_engine, tally_material):
    session = db_session_factory()
    creator = User(email="creator_limit@example.com", role="teacher", status="active")
    session.add(creator)
    session.commit()

    t0 = datetime(2026, 9, 10, 8, 0, 0, tzinfo=timezone.utc)
    v1 = VoteRecord(creator_id=creator.id, title="V1", scope="public", closes_at=t0 + timedelta(hours=1), status="open", created_at=t0)
    v2 = VoteRecord(creator_id=creator.id, title="V2", scope="public", closes_at=t0 + timedelta(hours=2), status="open", created_at=t0)
    v3 = VoteRecord(creator_id=creator.id, title="V3", scope="public", closes_at=t0 + timedelta(hours=3), status="open", created_at=t0)
    session.add_all([v1, v2, v3])
    session.commit()

    opt1 = VoteOption(vote_id=v1.id, label="A", position=0)
    opt2 = VoteOption(vote_id=v2.id, label="A", position=0)
    opt3 = VoteOption(vote_id=v3.id, label="A", position=0)
    session.add_all([opt1, opt2, opt3])
    session.commit()
    session.close()

    scan_time = t0 + timedelta(hours=5)
    clock = FakeClock(scan_time)
    service = VoteSettlementService(
        session_factory=db_session_factory,
        crypto_engine=crypto_engine,
        tally_material_provider=MockTallyMaterialProvider(tally_material),
        clock=clock,
    )

    settled_list = service.settle_due(limit=2)
    assert len(settled_list) == 2
    # Should settle v1 and v2 first (earliest closes_at)
    settled_ids = [s.vote_id for s in settled_list]
    assert settled_ids == [v1.id, v2.id]
