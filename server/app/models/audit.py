from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RevocationLog(Base):
    __tablename__ = "revocation_log"
    __table_args__ = (
        UniqueConstraint("sn", name="uq_revocation_log_sn"),
        UniqueConstraint("hash_prev", name="uq_revocation_log_hash_prev"),
    )

    hash_curr: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    hash_prev: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    sn: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    operator: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    actor: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    detail_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
