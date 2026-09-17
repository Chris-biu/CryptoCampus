from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "role IN ('student', 'admin', 'teacher', 'system')",
            name="ck_users_role",
        ),
        CheckConstraint(
            "status IN ('active', 'frozen', 'pending_deletion')",
            name="ck_users_status",
        ),
        CheckConstraint(
            "(pqc_pubkey IS NULL) = (enc_pqc_sk IS NULL)",
            name="ck_users_pqc_key_pair",
        ),
        CheckConstraint(
            "failed_login_count >= 0",
            name="ck_users_failed_login_count_nonnegative",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    email: Mapped[str | None] = mapped_column(String(254), nullable=True, unique=True, index=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="student")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    salt_a: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    auth_hash: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    salt_k: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    enc_sk: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    pubkey: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    cert_serial: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True, index=True)
    pqc_pubkey: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    enc_pqc_sk: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
