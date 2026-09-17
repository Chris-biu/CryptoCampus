from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Seal(Base):
    __tablename__ = "seals"
    __table_args__ = (
        UniqueConstraint("signer_user_id", "idempotency_key_digest", name="uq_seals_signer_idempotency"),
        CheckConstraint("seal_profile IN ('personal', 'department', 'academic')", name="ck_seals_profile"),
        CheckConstraint("digest_algorithm = 'SM3'", name="ck_seals_digest_algorithm"),
        CheckConstraint("signature_algorithm IN ('SM3-with-SM2', 'ML-DSA-65')", name="ck_seals_signature_algorithm"),
        CheckConstraint("output_format IN ('sidecar', 'qr', 'pdf_signature_page')", name="ck_seals_output_format"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    signer_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    seal_profile: Mapped[str] = mapped_column(String(32), nullable=False)
    digest_algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="SM3")
    digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="SM3-with-SM2")
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    certificate_der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    output_format: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, index=True)
    request_fingerprint: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
