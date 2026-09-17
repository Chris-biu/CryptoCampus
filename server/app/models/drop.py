from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Drop(Base):
    __tablename__ = "drops"
    __table_args__ = (
        CheckConstraint("kind IN ('text', 'file')", name="ck_drops_kind"),
        CheckConstraint(
            "status IN ('available', 'consumed', 'expired', 'destroyed', 'cooling_down')",
            name="ck_drops_status",
        ),
        CheckConstraint(
            "ttl_policy IN ('burn_after_read', 'hours_24', 'days_7')",
            name="ck_drops_ttl_policy",
        ),
        CheckConstraint(
            "content_size > 0 AND content_size <= 104857600",
            name="ck_drops_content_size_bounds",
        ),
        CheckConstraint(
            "failed_attempts >= 0 AND failed_attempts <= 5",
            name="ck_drops_failed_attempts",
        ),
        Index("ix_drops_owner_created", "owner_user_id", "created_at"),
        Index("ix_drops_recipient_status", "recipient_user_id", "status"),
        Index("ix_drops_expires_status", "expires_at", "status"),
        Index("ix_drops_status_cooldown", "status", "cooldown_until"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    owner_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    recipient_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    link_code_hash: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, unique=True, index=True
    )
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    envelope_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    nonce: Mapped[bytes | None] = mapped_column(LargeBinary(12), nullable=True)
    tag: Mapped[bytes | None] = mapped_column(LargeBinary(16), nullable=True)
    enc_key_sm2: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    enc_key_mlkem: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    sender_signature: Mapped[bytes | None] = mapped_column(LargeBinary(64), nullable=True)
    sender_certificate_der: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    sender_cert_serial: Mapped[str] = mapped_column(String(128), nullable=False)
    recipient_sm2_fingerprint: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    recipient_mlkem_fingerprint: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    access_code_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    access_factor_salt: Mapped[bytes | None] = mapped_column(LargeBinary(16), nullable=True)
    ttl_policy: Mapped[str] = mapped_column(String(16), nullable=False)
    burn_after_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_size: Mapped[int] = mapped_column(Integer, nullable=False)
    pqc_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="available")
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cooldown_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class DropIdempotency(Base):
    __tablename__ = "drop_idempotency"
    __table_args__ = (
        UniqueConstraint(
            "owner_user_id", "operation", "key_hash", name="uq_drop_idemp_owner_op_key"
        ),
        CheckConstraint(
            "operation IN ('create_text', 'create_file')",
            name="ck_drop_idemp_operation",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    owner_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    drop_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("drops.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class DropExtractIdempotency(Base):
    __tablename__ = "drop_extract_idempotency"
    __table_args__ = (
        UniqueConstraint("drop_id", "key_hash", name="uq_drop_extract_idemp_drop_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    drop_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("drops.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    inspect_record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

