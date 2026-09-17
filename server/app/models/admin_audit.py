from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AdminAuditEntry(Base):
    __tablename__ = "admin_audit_entries"
    __table_args__ = (
        UniqueConstraint("hash_prev", name="uq_admin_audit_entries_hash_prev"),
        UniqueConstraint("hash_curr", name="uq_admin_audit_entries_hash_curr"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    actor_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    detail_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    hash_prev: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    hash_curr: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
