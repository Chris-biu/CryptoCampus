from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CertificateRecord(Base):
    __tablename__ = "certificates"
    __table_args__ = (
        CheckConstraint("not_after > not_before", name="ck_certificates_validity"),
        CheckConstraint(
            "kind IN ('platform_ca', 'user_identity')", name="ck_certificates_kind"
        ),
        CheckConstraint(
            "status IN ('active', 'revoked', 'expired')", name="ck_certificates_status"
        ),
        CheckConstraint(
            "(status = 'revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL) "
            "OR (status != 'revoked' AND revoked_at IS NULL AND revocation_reason IS NULL)",
            name="ck_certificates_revocation",
        ),
    )

    serial: Mapped[str] = mapped_column(String(128), primary_key=True)
    subject_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    issuer_serial: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    certificate_der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_usage: Mapped[str] = mapped_column(String(255), nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )


class CrlSnapshot(Base):
    __tablename__ = "crl_snapshots"
    __table_args__ = (
        CheckConstraint("next_update > this_update", name="ck_crl_snapshots_validity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    issuer_serial: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    crl_der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    this_update: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    next_update: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
