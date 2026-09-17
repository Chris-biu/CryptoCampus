import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models.credential import ConsumedSN
from app.models.hole import HolePost, HolePostIdempotency


FORBIDDEN_ANONYMOUS_FIELDS = {
    "user_id",
    "author_id",
    "email",
    "session_id",
    "ip",
    "device",
    "issuance_id",
    "credential_ledger_id",
    "token",
}


def test_hole_post_and_idempotency_have_no_identity_columns():
    hole_post_cols = set(HolePost.__table__.columns.keys())
    assert not (hole_post_cols & FORBIDDEN_ANONYMOUS_FIELDS), (
        f"HolePost contains forbidden identity columns: {hole_post_cols & FORBIDDEN_ANONYMOUS_FIELDS}"
    )

    consumed_sn_cols = set(ConsumedSN.__table__.columns.keys())
    assert not (consumed_sn_cols & FORBIDDEN_ANONYMOUS_FIELDS), (
        f"ConsumedSN contains forbidden identity columns: {consumed_sn_cols & FORBIDDEN_ANONYMOUS_FIELDS}"
    )

    idemp_cols = set(HolePostIdempotency.__table__.columns.keys())
    assert not (idemp_cols & FORBIDDEN_ANONYMOUS_FIELDS), (
        f"HolePostIdempotency contains forbidden identity columns: {idemp_cols & FORBIDDEN_ANONYMOUS_FIELDS}"
    )


def test_database_initialization_and_table_schema():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    # Verify HolePost table existence and insertion
    post_id = str(uuid.uuid4())
    sn_bytes = bytes.fromhex("00112233445566778899aabbccddeeff")
    sig_bytes = b"\x77" * 64
    now = datetime.now(timezone.utc)

    post = HolePost(
        id=post_id,
        content="Hello anonymous hole!",
        credential_sn=sn_bytes,
        credential_service="hole_post",
        credential_period="2026-09-09",
        credential_signature=sig_bytes,
        credential_prefix="00112233",
        credential_valid=True,
        status="published",
        created_at=now,
    )
    session.add(post)
    session.commit()

    retrieved = session.get(HolePost, post_id)
    assert retrieved is not None
    assert retrieved.content == "Hello anonymous hole!"
    assert retrieved.credential_prefix == "00112233"
    assert retrieved.status == "published"
    assert retrieved.credential_valid is True

    # Verify HolePostIdempotency insertion
    idemp_id = str(uuid.uuid4())
    key_hash = b"\x11" * 32
    req_hash = b"\x22" * 32

    idemp = HolePostIdempotency(
        id=idemp_id,
        key_hash=key_hash,
        request_hash=req_hash,
        post_id=post_id,
        created_at=now,
    )
    session.add(idemp)
    session.commit()

    retrieved_idemp = session.get(HolePostIdempotency, idemp_id)
    assert retrieved_idemp is not None
    assert retrieved_idemp.post_id == post_id
    assert retrieved_idemp.key_hash == key_hash


def test_hole_post_duplicate_sn_and_service_rejected():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    sn_bytes = bytes.fromhex("aabbccddeeff00112233445566778899")
    sig_bytes = b"\x88" * 64
    now = datetime.now(timezone.utc)

    post1 = HolePost(
        id=str(uuid.uuid4()),
        content="First post",
        credential_sn=sn_bytes,
        credential_service="hole_post",
        credential_period="2026-09-09",
        credential_signature=sig_bytes,
        credential_prefix="aabbccdd",
        credential_valid=True,
        status="published",
        created_at=now,
    )
    session.add(post1)
    session.commit()

    post2 = HolePost(
        id=str(uuid.uuid4()),
        content="Second post with duplicate SN",
        credential_sn=sn_bytes,
        credential_service="hole_post",
        credential_period="2026-09-09",
        credential_signature=sig_bytes,
        credential_prefix="aabbccdd",
        credential_valid=True,
        status="published",
        created_at=now,
    )
    session.add(post2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_hole_post_idempotency_duplicate_key_hash_rejected():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    now = datetime.now(timezone.utc)
    post = HolePost(
        id=str(uuid.uuid4()),
        content="Parent post",
        credential_sn=bytes.fromhex("11223344556677889900aabbccddeeff"),
        credential_service="hole_post",
        credential_period="2026-09-09",
        credential_signature=b"\x99" * 64,
        credential_prefix="11223344",
        credential_valid=True,
        status="published",
        created_at=now,
    )
    session.add(post)
    session.commit()

    key_hash = b"\x55" * 32
    idemp1 = HolePostIdempotency(
        id=str(uuid.uuid4()),
        key_hash=key_hash,
        request_hash=b"\x66" * 32,
        post_id=post.id,
        created_at=now,
    )
    session.add(idemp1)
    session.commit()

    idemp2 = HolePostIdempotency(
        id=str(uuid.uuid4()),
        key_hash=key_hash,
        request_hash=b"\x77" * 32,
        post_id=post.id,
        created_at=now,
    )
    session.add(idemp2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
