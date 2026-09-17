from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ChatSession(Base):
    __tablename__ = "chat_sessions"
    __table_args__ = (
        CheckConstraint(
            "participant_a_id < participant_b_id",
            name="ck_chat_sessions_ordered_participants",
        ),
        CheckConstraint(
            "(pqc_mode = 0 AND key_agreement = 'SM2-ECDH') OR "
            "(pqc_mode = 1 AND key_agreement = 'X25519-ML-KEM-768')",
            name="ck_chat_sessions_key_agreement",
        ),
        UniqueConstraint(
            "participant_a_id",
            "participant_b_id",
            "pqc_mode",
            name="uq_chat_sessions_participants_mode",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    participant_a_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    participant_b_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    pqc_mode: Mapped[bool] = mapped_column(Boolean, nullable=False)
    key_agreement: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __init__(self, **kwargs) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid4())
        if "key_agreement" not in kwargs and "pqc_mode" in kwargs:
            kwargs["key_agreement"] = (
                "X25519-ML-KEM-768" if kwargs["pqc_mode"] else "SM2-ECDH"
            )
        super().__init__(**kwargs)


class ChatSessionIdempotency(Base):
    __tablename__ = "chat_session_idempotency"
    __table_args__ = (
        UniqueConstraint(
            "owner_user_id", "key_hash", name="uq_chat_session_idemp_owner_key"
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    owner_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    chat_session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False
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


class EncryptedMessage(Base):
    __tablename__ = "encrypted_messages"
    __table_args__ = (
        CheckConstraint("sequence >= 1", name="ck_encrypted_messages_sequence_positive"),
        CheckConstraint("length(ciphertext) BETWEEN 1 AND 65536", name="ck_encrypted_messages_ciphertext_size"),
        CheckConstraint("length(nonce) = 12", name="ck_encrypted_messages_nonce_size"),
        CheckConstraint("length(tag) = 16", name="ck_encrypted_messages_tag_size"),
        CheckConstraint("length(signature) BETWEEN 1 AND 4096", name="ck_encrypted_messages_signature_size"),
        UniqueConstraint(
            "session_id",
            "sender_id",
            "sequence",
            name="uq_encrypted_messages_session_sender_sequence",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sender_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    tag: Mapped[bytes] = mapped_column(LargeBinary(16), nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    def __init__(self, **kwargs) -> None:
        if "id" not in kwargs:
            kwargs["id"] = str(uuid4())
        super().__init__(**kwargs)
