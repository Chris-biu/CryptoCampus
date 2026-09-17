from datetime import datetime, timedelta, timezone
import json
import threading
import time
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE, SM2_PUBLIC_KEY_SIZE
from app.db.base import Base
from app.models.user import User
from app.models.vote import AnonymousBallot, VoteOption, VoteRecord, VoteResultSnapshot
from app.services.vote_scheduler import VoteSettlementScheduler
from app.services.vote_settlement import FakeClock, VoteSettlementService
from app.services.vote_tally_provider import VoteTallyMaterial


class SchedulerMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        import hashlib
        return hashlib.sha256(message).digest()

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right

    def sm2_sign(self, private_key: bytes, digest: bytes) -> bytes:
        return b"\x55" * 64

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        return signature == (b"\x55" * 64)


class MockTallyMaterialProvider:
    def __init__(self, material: VoteTallyMaterial) -> None:
        self.material = material

    from contextlib import contextmanager
    @contextmanager
    def unlocked(self):
        yield self.material


@pytest.fixture
def db_factory():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def tally_material():
    return VoteTallyMaterial(
        system_user_id="sys-user-sched-01",
        certificate_serial="cert-sched-01",
        certificate_der=b"DER-SCHED-CERT",
        public_key=b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1),
        private_key=b"\x12" * SM2_PRIVATE_KEY_SIZE,
    )


def test_scheduler_run_once_and_idempotence(db_factory, tally_material):
    session: Session = db_factory()
    creator = User(email="creator_sched@example.com", role="teacher", status="active")
    session.add(creator)
    session.commit()

    t0 = datetime(2026, 9, 10, 8, 0, 0, tzinfo=timezone.utc)
    closes_at = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

    vote = VoteRecord(
        creator_id=creator.id,
        title="调度结算测试",
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
    session.close()

    crypto = SchedulerMockCryptoEngine()
    clock = FakeClock(closes_at + timedelta(minutes=5))
    service = VoteSettlementService(
        session_factory=db_factory,
        crypto_engine=crypto,
        tally_material_provider=MockTallyMaterialProvider(tally_material),
        clock=clock,
    )

    scheduler = VoteSettlementScheduler(
        settlement_service=service,
        interval_seconds=1,
        batch_size=10,
    )

    # 1. Run once: settles the expired vote
    settled_first = scheduler.run_once(now=clock.now())
    assert len(settled_first) == 1
    snap1 = settled_first[0]
    assert snap1.vote_id == vote.id
    assert snap1.is_final is True

    # 2. Run second time on same expired vote: idempotent, nothing new to settle
    settled_second = scheduler.run_once(now=clock.now())
    assert len(settled_second) == 0

    session = db_factory()
    # Confirm DB only has 1 snapshot
    assert session.query(VoteResultSnapshot).filter_by(vote_id=vote.id).count() == 1
    v_db = session.get(VoteRecord, vote.id)
    assert v_db.status == "published"
    assert v_db.final_snapshot_id == snap1.id
    session.close()


def test_scheduler_background_thread_start_and_stop(db_factory, tally_material):
    crypto = SchedulerMockCryptoEngine()
    clock = FakeClock(datetime.now(timezone.utc))
    service = VoteSettlementService(
        session_factory=db_factory,
        crypto_engine=crypto,
        tally_material_provider=MockTallyMaterialProvider(tally_material),
        clock=clock,
    )

    scheduler = VoteSettlementScheduler(
        settlement_service=service,
        interval_seconds=1,
        batch_size=10,
    )

    assert not scheduler.is_running()
    scheduler.start()
    assert scheduler.is_running()
    # Double start is no-op
    scheduler.start()
    assert scheduler.is_running()

    time.sleep(0.05)
    scheduler.stop()
    assert not scheduler.is_running()
    # Double stop is no-op
    scheduler.stop()
    assert not scheduler.is_running()


def test_get_vote_results_triggers_controlled_settlement_on_expired_vote(db_factory, tally_material):
    from fastapi.testclient import TestClient
    from app.crypto.dependencies import get_crypto_engine
    from app.db.session import get_db
    from app.main import create_app
    from app.services.vote_tally_provider import get_vote_tally_provider

    session: Session = db_factory()
    creator = User(email="creator_getres@example.com", role="teacher", status="active")
    session.add(creator)
    session.commit()

    t0 = datetime(2026, 9, 10, 8, 0, 0, tzinfo=timezone.utc)
    closes_at = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

    # Expired vote without snapshots
    vote = VoteRecord(
        creator_id=creator.id,
        title="已截止投票结果获取",
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

    crypto = SchedulerMockCryptoEngine()
    tally_provider = MockTallyMaterialProvider(tally_material)

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_vote_tally_provider] = lambda: tally_provider

    client = TestClient(app)

    # Calling GET /results on expired vote triggers controlled settlement and returns 200
    res = client.get(f"/api/v1/votes/{vote.id}/results")
    assert res.status_code == 200
    data = res.json()
    assert data["vote_id"] == vote.id
    assert data["total"] == 0
    assert data["counts"] == {opt1.id: 0, opt2.id: 0}

    # Verify DB status updated to published
    assert session.get(VoteRecord, vote.id).status == "published"
