from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class VerificationRecord(Base):
    __tablename__ = "verification_records"
    __table_args__ = (
        CheckConstraint("length(file_digest) = 32", name="ck_verification_records_file_digest_length"),
        CheckConstraint("signature_algorithm IN ('SM3-with-SM2', 'ML-DSA-65')", name="ck_verification_records_signature_algorithm"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    record_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, index=True)
    file_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    seal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    signature_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    digest_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    signature_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    certificate_chain_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    timestamp_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    revocation_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
