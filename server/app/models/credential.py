from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CredentialLedger(Base):
    __tablename__ = "credential_ledger"
    __table_args__ = (
        UniqueConstraint("user_id", "service", "period", name="uq_credential_ledger_user_service_period"),
        CheckConstraint("issued_count >= 0", name="ck_credential_ledger_issued_count"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    service: Mapped[str] = mapped_column(String(64), nullable=False)
    period: Mapped[str] = mapped_column(String(128), nullable=False)
    issued_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ConsumedSN(Base):
    __tablename__ = "consumed_sn"

    sn: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    service: Mapped[str] = mapped_column(String(64), primary_key=True)
    consumed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class CredentialIssueIdempotency(Base):
    __tablename__ = "credential_issue_idempotency"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "service",
            "period",
            "key_hash",
            name="uq_credential_issue_idemp_user_svc_per_key",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    service: Mapped[str] = mapped_column(String(64), nullable=False)
    period: Mapped[str] = mapped_column(String(128), nullable=False)
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    blind_signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
