from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class InspectRecordEntity(Base):
    __tablename__ = "inspect_records"
    __table_args__ = (
        CheckConstraint("owner IN ('self', 'system')", name="ck_inspect_records_owner"),
        CheckConstraint("status IN ('passed', 'failed')", name="ck_inspect_records_status"),
        Index("ix_inspect_records_owner_created", "owner_user_id", "created_at"),
        Index("ix_inspect_records_created_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    owner_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    owner: Mapped[str] = mapped_column(String(16), nullable=False, default="self")
    operation: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="passed", index=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    steps_json: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    redacted_values_json: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    steps: Mapped[list[InspectStepEntity]] = relationship(
        "InspectStepEntity",
        back_populates="record",
        cascade="all, delete-orphan",
        order_by="InspectStepEntity.order",
        lazy="selectin",
    )


class InspectStepEntity(Base):
    __tablename__ = "inspect_steps"
    __table_args__ = (
        UniqueConstraint("record_id", "order", name="uq_inspect_steps_record_order"),
        CheckConstraint('"order" >= 1 AND "order" <= 32', name="ck_inspect_steps_order_bounds"),
        CheckConstraint("result IN ('passed', 'failed', 'skipped')", name="ck_inspect_steps_result"),
        CheckConstraint("length(redacted_values_json) <= 4096", name="ck_inspect_steps_json_len"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    record_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("inspect_records.id", ondelete="CASCADE"), nullable=False, index=True
    )
    order: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(100), nullable=False)
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    redacted_values_json: Mapped[str] = mapped_column(Text, nullable=False)

    record: Mapped[InspectRecordEntity] = relationship(
        "InspectRecordEntity",
        back_populates="steps",
    )


InspectRecord = InspectRecordEntity
