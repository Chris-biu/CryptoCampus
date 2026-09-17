import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models.hole import (
    HolePost,
    HolePostIdempotency,
    HoleComment,
    HoleLike,
    HoleCommentIdempotency,
    HoleLikeIdempotency,
)


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


def test_interaction_models_have_no_identity_columns():
    comment_cols = set(HoleComment.__table__.columns.keys())
    assert not (comment_cols & FORBIDDEN_ANONYMOUS_FIELDS), (
        f"HoleComment contains forbidden identity columns: {comment_cols & FORBIDDEN_ANONYMOUS_FIELDS}"
    )

    like_cols = set(HoleLike.__table__.columns.keys())
    assert not (like_cols & FORBIDDEN_ANONYMOUS_FIELDS), (
        f"HoleLike contains forbidden identity columns: {like_cols & FORBIDDEN_ANONYMOUS_FIELDS}"
    )

    comment_idemp_cols = set(HoleCommentIdempotency.__table__.columns.keys())
    assert not (comment_idemp_cols & FORBIDDEN_ANONYMOUS_FIELDS), (
        f"HoleCommentIdempotency contains forbidden identity columns: {comment_idemp_cols & FORBIDDEN_ANONYMOUS_FIELDS}"
    )

    like_idemp_cols = set(HoleLikeIdempotency.__table__.columns.keys())
    assert not (like_idemp_cols & FORBIDDEN_ANONYMOUS_FIELDS), (
        f"HoleLikeIdempotency contains forbidden identity columns: {like_idemp_cols & FORBIDDEN_ANONYMOUS_FIELDS}"
    )


def test_interaction_database_initialization_and_table_schema():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    # 1. Create a published post
    post = HolePost(
        id=str(uuid.uuid4()),
        content="Published post for interactions",
        credential_sn=bytes.fromhex("11" * 16),
        credential_service="hole_post",
        credential_period="2026-09-09",
        credential_signature=b"\x11" * 64,
        credential_prefix="11" * 4,
        credential_valid=True,
        status="published",
        created_at=datetime.now(timezone.utc),
    )
    session.add(post)
    session.commit()

    # 2. Add a comment
    comment_sn = bytes.fromhex("22" * 16)
    comment = HoleComment(
        id=str(uuid.uuid4()),
        post_id=post.id,
        content="Great anonymous post!",
        credential_sn=comment_sn,
        credential_service="hole_comment",
        credential_period="2026-09-09",
        credential_signature=b"\x22" * 64,
        credential_prefix="22" * 4,
        credential_valid=True,
        created_at=datetime.now(timezone.utc),
    )
    session.add(comment)

    # 3. Add a comment idempotency record
    comment_idemp = HoleCommentIdempotency(
        id=str(uuid.uuid4()),
        key_hash=b"\x01" * 32,
        request_hash=b"\x02" * 32,
        comment_id=comment.id,
        created_at=datetime.now(timezone.utc),
    )
    session.add(comment_idemp)

    # 4. Add a like
    like_sn = bytes.fromhex("33" * 16)
    like = HoleLike(
        id=str(uuid.uuid4()),
        post_id=post.id,
        credential_sn=like_sn,
        credential_service="hole_like",
        credential_period="2026-09-09",
        credential_signature=b"\x33" * 64,
        created_at=datetime.now(timezone.utc),
    )
    session.add(like)

    # 5. Add a like idempotency record
    like_idemp = HoleLikeIdempotency(
        id=str(uuid.uuid4()),
        key_hash=b"\x03" * 32,
        request_hash=b"\x04" * 32,
        like_id=like.id,
        created_at=datetime.now(timezone.utc),
    )
    session.add(like_idemp)

    session.commit()

    # Verify query
    fetched_comment = session.get(HoleComment, comment.id)
    assert fetched_comment is not None
    assert fetched_comment.content == "Great anonymous post!"
    assert fetched_comment.credential_service == "hole_comment"

    fetched_like = session.get(HoleLike, like.id)
    assert fetched_like is not None
    assert fetched_like.credential_service == "hole_like"


def test_hole_comment_duplicate_sn_and_service_rejected():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    post = HolePost(
        id=str(uuid.uuid4()),
        content="Post for duplicate comment test",
        credential_sn=bytes.fromhex("44" * 16),
        credential_service="hole_post",
        credential_period="2026-09-09",
        credential_signature=b"\x44" * 64,
        credential_prefix="44" * 4,
        credential_valid=True,
        status="published",
        created_at=datetime.now(timezone.utc),
    )
    session.add(post)
    session.commit()

    sn = bytes.fromhex("55" * 16)
    c1 = HoleComment(
        id=str(uuid.uuid4()),
        post_id=post.id,
        content="First comment",
        credential_sn=sn,
        credential_service="hole_comment",
        credential_period="2026-09-09",
        credential_signature=b"\x55" * 64,
        credential_prefix="55" * 4,
        credential_valid=True,
        created_at=datetime.now(timezone.utc),
    )
    session.add(c1)
    session.commit()

    c2 = HoleComment(
        id=str(uuid.uuid4()),
        post_id=post.id,
        content="Second comment duplicate SN",
        credential_sn=sn,
        credential_service="hole_comment",
        credential_period="2026-09-09",
        credential_signature=b"\x55" * 64,
        credential_prefix="55" * 4,
        credential_valid=True,
        created_at=datetime.now(timezone.utc),
    )
    session.add(c2)
    with pytest.raises(IntegrityError):
        session.commit()


def test_hole_like_duplicate_sn_and_service_rejected():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    post = HolePost(
        id=str(uuid.uuid4()),
        content="Post for duplicate like test",
        credential_sn=bytes.fromhex("66" * 16),
        credential_service="hole_post",
        credential_period="2026-09-09",
        credential_signature=b"\x66" * 64,
        credential_prefix="66" * 4,
        credential_valid=True,
        status="published",
        created_at=datetime.now(timezone.utc),
    )
    session.add(post)
    session.commit()

    sn = bytes.fromhex("77" * 16)
    l1 = HoleLike(
        id=str(uuid.uuid4()),
        post_id=post.id,
        credential_sn=sn,
        credential_service="hole_like",
        credential_period="2026-09-09",
        credential_signature=b"\x77" * 64,
        created_at=datetime.now(timezone.utc),
    )
    session.add(l1)
    session.commit()

    l2 = HoleLike(
        id=str(uuid.uuid4()),
        post_id=post.id,
        credential_sn=sn,
        credential_service="hole_like",
        credential_period="2026-09-09",
        credential_signature=b"\x77" * 64,
        created_at=datetime.now(timezone.utc),
    )
    session.add(l2)
    with pytest.raises(IntegrityError):
        session.commit()


def test_idempotency_key_hash_uniqueness():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    post = HolePost(
        id=str(uuid.uuid4()),
        content="Post for idemp uniqueness",
        credential_sn=bytes.fromhex("88" * 16),
        credential_service="hole_post",
        credential_period="2026-09-09",
        credential_signature=b"\x88" * 64,
        credential_prefix="88" * 4,
        credential_valid=True,
        status="published",
        created_at=datetime.now(timezone.utc),
    )
    session.add(post)
    session.commit()

    c1 = HoleComment(
        id=str(uuid.uuid4()),
        post_id=post.id,
        content="Comment 1",
        credential_sn=bytes.fromhex("99" * 16),
        credential_service="hole_comment",
        credential_period="2026-09-09",
        credential_signature=b"\x99" * 64,
        credential_prefix="99" * 4,
        credential_valid=True,
        created_at=datetime.now(timezone.utc),
    )
    c2 = HoleComment(
        id=str(uuid.uuid4()),
        post_id=post.id,
        content="Comment 2",
        credential_sn=bytes.fromhex("aa" * 16),
        credential_service="hole_comment",
        credential_period="2026-09-09",
        credential_signature=b"\xaa" * 64,
        credential_prefix="aa" * 4,
        credential_valid=True,
        created_at=datetime.now(timezone.utc),
    )
    session.add_all([c1, c2])
    session.commit()

    key_hash = b"\xde\xad\xbe\xef" * 8
    idemp1 = HoleCommentIdempotency(
        id=str(uuid.uuid4()),
        key_hash=key_hash,
        request_hash=b"\x11" * 32,
        comment_id=c1.id,
        created_at=datetime.now(timezone.utc),
    )
    session.add(idemp1)
    session.commit()

    idemp2 = HoleCommentIdempotency(
        id=str(uuid.uuid4()),
        key_hash=key_hash,
        request_hash=b"\x22" * 32,
        comment_id=c2.id,
        created_at=datetime.now(timezone.utc),
    )
    session.add(idemp2)
    with pytest.raises(IntegrityError):
        session.commit()
