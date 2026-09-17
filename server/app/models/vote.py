from collections.abc import Sequence
from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class VoteScopeUnit(Base):
    __tablename__ = "vote_scope_units"
    __table_args__ = (
        CheckConstraint("kind IN ('class', 'group')", name="ck_vote_scope_units_kind"),
        UniqueConstraint("kind", "name", name="uq_vote_scope_units_kind_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __init__(self, **kwargs) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid4())
        super().__init__(**kwargs)


class VoteScopeMember(Base):
    __tablename__ = "vote_scope_members"
    __table_args__ = (
        UniqueConstraint("scope_id", "user_id", name="uq_vote_scope_members_scope_user"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scope_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vote_scope_units.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __init__(self, **kwargs) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid4())
        super().__init__(**kwargs)


class VoteRecord(Base):
    __tablename__ = "votes"
    __table_args__ = (
        CheckConstraint(
            "scope IN ('public', 'class', 'group')",
            name="ck_votes_scope",
        ),
        CheckConstraint(
            "status IN ('open', 'closed', 'published')",
            name="ck_votes_status",
        ),
        CheckConstraint(
            "(scope = 'public' AND scope_id IS NULL) OR "
            "(scope IN ('class', 'group') AND scope_id IS NOT NULL)",
            name="ck_votes_scope_id_presence",
        ),
        CheckConstraint(
            "(status != 'published') OR (status = 'published' AND final_snapshot_id IS NOT NULL)",
            name="ck_votes_published_final_snapshot",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    creator_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("vote_scope_units.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    closes_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    settled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    final_snapshot_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    options: Mapped[List["VoteOption"]] = relationship(
        "VoteOption",
        back_populates="vote",
        cascade="all, delete-orphan",
        order_by="VoteOption.position",
    )

    def __init__(self, **kwargs) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid4())
        super().__init__(**kwargs)


class VoteOption(Base):
    __tablename__ = "vote_options"
    __table_args__ = (
        UniqueConstraint("vote_id", "position", name="uq_vote_options_vote_position"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    vote_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("votes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False)

    vote: Mapped["VoteRecord"] = relationship("VoteRecord", back_populates="options")

    def __init__(self, **kwargs) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid4())
        super().__init__(**kwargs)


class VoteCreateIdempotency(Base):
    __tablename__ = "vote_create_idempotency"
    __table_args__ = (
        UniqueConstraint("creator_id", "key_hash", name="uq_vote_create_idemp_creator_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    creator_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False, index=True
    )
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    vote_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("votes.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __init__(self, **kwargs) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid4())
        super().__init__(**kwargs)


class VoteCredentialIssue(Base):
    __tablename__ = "vote_credential_issues"
    __table_args__ = (
        UniqueConstraint("user_id", "vote_id", name="uq_vote_credential_issue_user_vote"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    vote_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("votes.id"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False, index=True
    )
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    blind_signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="SM2-BLIND-PROTOCOL-V1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __init__(self, **kwargs) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid4())
        super().__init__(**kwargs)


class AnonymousBallot(Base):
    __tablename__ = "anonymous_ballots"
    __table_args__ = (
        UniqueConstraint("credential_sn", "credential_service", name="uq_anonymous_ballots_sn_service"),
        Index("ix_anonymous_ballots_vote_option", "vote_id", "option_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    vote_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("votes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    option_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vote_options.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_sn: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    credential_service: Mapped[str] = mapped_column(String(32), nullable=False, default="vote_ballot")
    credential_period: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __init__(self, **kwargs) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid4())
        super().__init__(**kwargs)


class BallotIdempotency(Base):
    __tablename__ = "ballot_idempotencies"
    __table_args__ = (
        UniqueConstraint("key_hash", name="uq_ballot_idemp_key_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, index=True)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    ballot_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("anonymous_ballots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __init__(self, **kwargs) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid4())
        super().__init__(**kwargs)


class VoteResultSnapshot(Base):
    __tablename__ = "vote_result_snapshots"
    __table_args__ = (
        UniqueConstraint("vote_id", "version", name="uq_vote_result_snapshots_vote_version"),
        Index("ix_vote_result_snapshots_vote_version", "vote_id", "version"),
        Index(
            "uq_vote_result_snapshots_final",
            "vote_id",
            unique=True,
            sqlite_where=text("is_final = 1"),
            postgresql_where=text("is_final = TRUE"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    vote_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("votes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    counts_json: Mapped[str] = mapped_column(Text, nullable=False)
    total: Mapped[int] = mapped_column(Integer, nullable=False)
    result_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary(64), nullable=False)
    signer_certificate: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signer_public_key: Mapped[bytes] = mapped_column(LargeBinary(65), nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_final: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    def __init__(self, **kwargs) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid4())
        super().__init__(**kwargs)

    def get_counts(self) -> dict[str, int]:
        import json
        return json.loads(self.counts_json)

    def validate_counts(self, expected_options: Sequence[str] | None = None) -> bool:
        if not self.is_final and self.version != self.total:
            return False
        try:
            counts = self.get_counts()
        except Exception:
            return False
        if not isinstance(counts, dict):
            return False
        if sum(counts.values()) != self.total:
            return False
        if any(c < 0 for c in counts.values()):
            return False
        if expected_options is not None:
            if set(counts.keys()) != set(expected_options):
                return False
        return True

