from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class VoteAuditFlag(Base):
    """
    Model for recording anomalous voting audit flags.
    Never alters ballot validity or exposes voter identity.
    """
    __tablename__ = "vote_audit_flags"
    __table_args__ = (
        UniqueConstraint("vote_id", "actor_id", "reason_hash", name="uq_vote_audit_flags_actor_reason"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    vote_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("votes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    reason_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
