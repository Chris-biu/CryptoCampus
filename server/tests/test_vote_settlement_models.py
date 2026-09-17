from datetime import datetime, timezone
import json
import uuid
import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.user import User
from app.models.vote import (
    AnonymousBallot,
    VoteOption,
    VoteRecord,
    VoteResultSnapshot,
)


def _create_db_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_vote_settlement_model_columns_presence():
    """Verify is_final on VoteResultSnapshot, settled_at and final_snapshot_id on VoteRecord."""
    snapshot_cols = {c.name: c for c in VoteResultSnapshot.__table__.columns}
    assert "is_final" in snapshot_cols, "VoteResultSnapshot must have is_final column"
    assert snapshot_cols["is_final"].nullable is False

    vote_cols = {c.name: c for c in VoteRecord.__table__.columns}
    assert "settled_at" in vote_cols, "VoteRecord must have settled_at column"
    assert "final_snapshot_id" in vote_cols, "VoteRecord must have final_snapshot_id column"
    assert vote_cols["settled_at"].nullable is True
    assert vote_cols["final_snapshot_id"].nullable is True


def test_vote_result_snapshot_is_final_default_false():
    session = _create_db_session()
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    creator = User(email="creator_mod@example.edu", role="teacher", status="active")
    session.add(creator)
    session.commit()

    vote = VoteRecord(
        creator_id=creator.id,
        title="测试快照模型",
        scope="public",
        closes_at=now,
        status="open",
        created_at=now,
    )
    opt1 = VoteOption(vote_id=vote.id, label="选项A", position=0)
    session.add_all([vote, opt1])
    session.commit()

    # Default is_final must be False
    snap = VoteResultSnapshot(
        vote_id=vote.id,
        version=1,
        counts_json=json.dumps({opt1.id: 1}),
        total=1,
        result_digest=b"\x01" * 32,
        signature=b"\x02" * 64,
        signer_certificate=b"CERT",
        signer_public_key=b"\x04" + b"\x03" * 64,
        published_at=now,
    )
    session.add(snap)
    session.commit()

    saved_snap = session.get(VoteResultSnapshot, snap.id)
    assert saved_snap is not None
    assert saved_snap.is_final is False


def test_single_final_snapshot_per_vote_constraint():
    """Verify that multiple is_final=False snapshots are allowed, but only at most one is_final=True."""
    session = _create_db_session()
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    creator = User(email="creator_final@example.edu", role="teacher", status="active")
    session.add(creator)
    session.commit()

    vote = VoteRecord(
        creator_id=creator.id,
        title="测试唯一最终快照",
        scope="public",
        closes_at=now,
        status="open",
        created_at=now,
    )
    opt1 = VoteOption(vote_id=vote.id, label="选项A", position=0)
    session.add_all([vote, opt1])
    session.commit()

    # 1. Multiple is_final=False snapshots MUST succeed
    snap1 = VoteResultSnapshot(
        vote_id=vote.id,
        version=1,
        counts_json=json.dumps({opt1.id: 1}),
        total=1,
        result_digest=b"\x11" * 32,
        signature=b"\x12" * 64,
        signer_certificate=b"CERT",
        signer_public_key=b"\x04" + b"\x13" * 64,
        published_at=now,
        is_final=False,
    )
    snap2 = VoteResultSnapshot(
        vote_id=vote.id,
        version=2,
        counts_json=json.dumps({opt1.id: 2}),
        total=2,
        result_digest=b"\x21" * 32,
        signature=b"\x22" * 64,
        signer_certificate=b"CERT",
        signer_public_key=b"\x04" + b"\x23" * 64,
        published_at=now,
        is_final=False,
    )
    session.add_all([snap1, snap2])
    session.commit()

    # 2. First is_final=True snapshot succeeds
    snap_final_1 = VoteResultSnapshot(
        vote_id=vote.id,
        version=3,
        counts_json=json.dumps({opt1.id: 2}),
        total=2,
        result_digest=b"\x31" * 32,
        signature=b"\x32" * 64,
        signer_certificate=b"CERT",
        signer_public_key=b"\x04" + b"\x33" * 64,
        published_at=now,
        is_final=True,
    )
    session.add(snap_final_1)
    session.commit()

    # 3. Second is_final=True snapshot for the same vote MUST fail unique constraint
    snap_final_2 = VoteResultSnapshot(
        vote_id=vote.id,
        version=4,
        counts_json=json.dumps({opt1.id: 2}),
        total=2,
        result_digest=b"\x41" * 32,
        signature=b"\x42" * 64,
        signer_certificate=b"CERT",
        signer_public_key=b"\x04" + b"\x43" * 64,
        published_at=now,
        is_final=True,
    )
    session.add(snap_final_2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_vote_record_published_requires_final_snapshot():
    """Verify that a vote cannot be published without referencing a final_snapshot_id."""
    session = _create_db_session()
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    creator = User(email="creator_pub@example.edu", role="teacher", status="active")
    session.add(creator)
    session.commit()

    # Vote with status='published' but final_snapshot_id is NULL must violate CheckConstraint
    vote_invalid = VoteRecord(
        creator_id=creator.id,
        title="未引用快照的发布",
        scope="public",
        closes_at=now,
        status="published",
        final_snapshot_id=None,
        created_at=now,
    )
    session.add(vote_invalid)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_final_snapshot_counts_validation_allows_version_greater_than_total():
    """Verify that validate_counts allows version != total when is_final=True."""
    opt_id = str(uuid.uuid4())
    counts = {opt_id: 5}

    # Final snapshot where version=6 (max_version + 1), but total=5
    final_snap = VoteResultSnapshot(
        vote_id=str(uuid.uuid4()),
        version=6,
        counts_json=json.dumps(counts),
        total=5,
        result_digest=b"\x01" * 32,
        signature=b"\x02" * 64,
        signer_certificate=b"CERT",
        signer_public_key=b"\x04" + b"\x03" * 64,
        published_at=datetime.now(timezone.utc),
        is_final=True,
    )
    assert final_snap.validate_counts(expected_options=[opt_id]) is True
