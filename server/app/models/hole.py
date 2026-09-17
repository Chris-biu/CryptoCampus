from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class HolePost(Base):
    __tablename__ = "hole_posts"
    __table_args__ = (
        UniqueConstraint("credential_sn", "credential_service", name="uq_hole_post_sn_service"),
        Index("ix_hole_post_status_created_id", "status", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    content: Mapped[str] = mapped_column(String(5000), nullable=False)
    credential_sn: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    credential_service: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_period: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_signature: Mapped[bytes] = mapped_column(LargeBinary(64), nullable=False)
    credential_prefix: Mapped[str] = mapped_column(String(8), nullable=False)
    credential_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="published")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class HoleComment(Base):
    __tablename__ = "hole_comments"
    __table_args__ = (
        UniqueConstraint("credential_sn", "credential_service", name="uq_hole_comment_sn_service"),
        Index("ix_hole_comment_post_created_id", "post_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    post_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("hole_posts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    content: Mapped[str] = mapped_column(String(2000), nullable=False)
    credential_sn: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    credential_service: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_period: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_signature: Mapped[bytes] = mapped_column(LargeBinary(64), nullable=False)
    credential_prefix: Mapped[str] = mapped_column(String(8), nullable=False)
    credential_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class HoleLike(Base):
    __tablename__ = "hole_likes"
    __table_args__ = (
        UniqueConstraint("credential_sn", "credential_service", name="uq_hole_like_sn_service"),
        Index("ix_hole_like_post_created", "post_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    post_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("hole_posts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    credential_sn: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    credential_service: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_period: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_signature: Mapped[bytes] = mapped_column(LargeBinary(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class HoleCommentIdempotency(Base):
    __tablename__ = "hole_comment_idempotency"
    __table_args__ = (
        UniqueConstraint("key_hash", name="uq_hole_comment_idemp_key_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True, index=True)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    comment_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("hole_comments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class HoleLikeIdempotency(Base):
    __tablename__ = "hole_like_idempotency"
    __table_args__ = (
        UniqueConstraint("key_hash", name="uq_hole_like_idemp_key_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True, index=True)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    like_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("hole_likes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class HolePostIdempotency(Base):
    __tablename__ = "hole_post_idempotency"
    __table_args__ = (
        UniqueConstraint("key_hash", name="uq_hole_post_idempotency_key_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True, index=True)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    post_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("hole_posts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
