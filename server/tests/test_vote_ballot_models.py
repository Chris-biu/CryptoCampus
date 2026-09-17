from datetime import datetime, timezone
import json
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.user import User
from app.models.vote import (
    AnonymousBallot,
    BallotIdempotency,
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


def test_models_anonymity_schema_audit():
    # Strict audit: verify no user or tracking fields exist in AnonymousBallot or BallotIdempotency
    forbidden_field_substrings = [
        "user", "creator", "member", "student", "teacher", "author",
        "ip", "device", "ua", "agent", "session", "token", "header",
        "credential_issue", "ledger", "account",
    ]

    ballot_cols = {c.name.lower() for c in AnonymousBallot.__table__.columns}
    idemp_cols = {c.name.lower() for c in BallotIdempotency.__table__.columns}
    snapshot_cols = {c.name.lower() for c in VoteResultSnapshot.__table__.columns}

    for col in ballot_cols:
        for f in forbidden_field_substrings:
            assert f not in col, f"Forbidden substring '{f}' found in AnonymousBallot column '{col}'"

    for col in idemp_cols:
        for f in forbidden_field_substrings:
            assert f not in col, f"Forbidden substring '{f}' found in BallotIdempotency column '{col}'"

    # Make sure raw idempotency key is not stored
    assert "key" not in idemp_cols or idemp_cols == {"id", "key_hash", "request_hash", "ballot_id", "created_at"}
    assert "raw_key" not in idemp_cols
    assert "idempotency_key" not in idemp_cols


def test_anonymous_ballot_and_idempotency_persistence_and_uniqueness():
    session = _create_db_session()
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    creator = User(email="creator@example.edu", role="teacher", status="active")
    session.add(creator)
    session.commit()

    vote = VoteRecord(
        creator_id=creator.id,
        title="测试投票",
        scope="public",
        closes_at=now,
        status="open",
        created_at=now,
    )
    opt1 = VoteOption(vote_id=vote.id, label="选项1", position=0)
    session.add_all([vote, opt1])
    session.commit()

    sn_bytes = b"\x01" * 16
    sig_bytes = b"\x02" * 64

    ballot = AnonymousBallot(
        vote_id=vote.id,
        option_id=opt1.id,
        credential_sn=sn_bytes,
        credential_service="vote_ballot",
        credential_period=vote.id,
        credential_signature=sig_bytes,
        created_at=now,
    )
    session.add(ballot)
    session.commit()

    key_hash = b"\x11" * 32
    req_hash = b"\x22" * 32
    idemp = BallotIdempotency(
        key_hash=key_hash,
        request_hash=req_hash,
        ballot_id=ballot.id,
        created_at=now,
    )
    session.add(idemp)
    session.commit()

    # 1. Duplicate (credential_sn, credential_service) must fail
    dup_ballot = AnonymousBallot(
        vote_id=vote.id,
        option_id=opt1.id,
        credential_sn=sn_bytes,
        credential_service="vote_ballot",
        credential_period=vote.id,
        credential_signature=b"\x03" * 64,
        created_at=now,
    )
    session.add(dup_ballot)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

    # 2. Duplicate key_hash in BallotIdempotency must fail
    dup_idemp = BallotIdempotency(
        key_hash=key_hash,
        request_hash=b"\x33" * 32,
        ballot_id=ballot.id,
        created_at=now,
    )
    session.add(dup_idemp)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_vote_result_snapshot_persistence_and_version_uniqueness():
    session = _create_db_session()
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    creator = User(email="creator2@example.edu", role="teacher", status="active")
    session.add(creator)
    session.commit()

    vote = VoteRecord(
        creator_id=creator.id,
        title="测试投票快照",
        scope="public",
        closes_at=now,
        status="open",
        created_at=now,
    )
    opt1 = VoteOption(vote_id=vote.id, label="选项1", position=0)
    opt2 = VoteOption(vote_id=vote.id, label="选项2", position=1)
    session.add_all([vote, opt1, opt2])
    session.commit()

    counts = {opt1.id: 2, opt2.id: 3}
    snapshot = VoteResultSnapshot(
        vote_id=vote.id,
        version=5,
        counts_json=json.dumps(counts),
        total=5,
        result_digest=b"\x44" * 32,
        signature=b"\x55" * 64,
        signer_certificate=b"CERT-DER",
        signer_public_key=b"\x04" + b"\x66" * 64,
        published_at=now,
    )
    session.add(snapshot)
    session.commit()

    # Verify counts parsing and validation
    parsed = snapshot.get_counts()
    assert parsed == counts
    assert snapshot.validate_counts(expected_options=[opt1.id, opt2.id]) is True

    # Duplicate (vote_id, version) must fail
    dup_snapshot = VoteResultSnapshot(
        vote_id=vote.id,
        version=5,
        counts_json=json.dumps(counts),
        total=5,
        result_digest=b"\x77" * 32,
        signature=b"\x88" * 64,
        signer_certificate=b"CERT-DER",
        signer_public_key=b"\x04" + b"\x66" * 64,
        published_at=now,
    )
    session.add(dup_snapshot)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_snapshot_counts_validation_mismatch():
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    opt1_id = str(uuid.uuid4())
    opt2_id = str(uuid.uuid4())

    # Total != version
    snap_bad_version = VoteResultSnapshot(
        vote_id=str(uuid.uuid4()),
        version=6,  # mismatch with total=5
        counts_json=json.dumps({opt1_id: 2, opt2_id: 3}),
        total=5,
        result_digest=b"\x11" * 32,
        signature=b"\x22" * 64,
        signer_certificate=b"CERT",
        signer_public_key=b"\x04" + b"\x33" * 64,
        published_at=now,
    )
    assert snap_bad_version.validate_counts(expected_options=[opt1_id, opt2_id]) is False

    # Sum of counts != total
    snap_bad_sum = VoteResultSnapshot(
        vote_id=str(uuid.uuid4()),
        version=5,
        counts_json=json.dumps({opt1_id: 1, opt2_id: 3}),  # sum is 4 != 5
        total=5,
        result_digest=b"\x11" * 32,
        signature=b"\x22" * 64,
        signer_certificate=b"CERT",
        signer_public_key=b"\x04" + b"\x33" * 64,
        published_at=now,
    )
    assert snap_bad_sum.validate_counts(expected_options=[opt1_id, opt2_id]) is False

    # Missing option
    snap_missing_opt = VoteResultSnapshot(
        vote_id=str(uuid.uuid4()),
        version=5,
        counts_json=json.dumps({opt1_id: 5}),  # missing opt2_id
        total=5,
        result_digest=b"\x11" * 32,
        signature=b"\x22" * 64,
        signer_certificate=b"CERT",
        signer_public_key=b"\x04" + b"\x33" * 64,
        published_at=now,
    )
    assert snap_missing_opt.validate_counts(expected_options=[opt1_id, opt2_id]) is False
