from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.crypto.engine import CryptoEngine


class BenchmarkJob(Base):
    __tablename__ = "benchmark_jobs"
    __table_args__ = (
        CheckConstraint("iterations >= 10 AND iterations <= 10000", name="ck_benchmark_jobs_iterations"),
        CheckConstraint("status IN ('queued', 'running', 'completed', 'failed')", name="ck_benchmark_jobs_status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    iterations: Mapped[int] = mapped_column(Integer, nullable=False)
    include_pqc: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued", index=True)
    engine_version: Mapped[str] = mapped_column(String(100), nullable=False, default="unknown")
    provider_snapshot_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    metrics: Mapped[list[BenchmarkMetricEntity]] = relationship(
        "BenchmarkMetricEntity",
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="BenchmarkMetricEntity.id",
    )


class BenchmarkMetricEntity(Base):
    __tablename__ = "benchmark_metrics"
    __table_args__ = (
        UniqueConstraint("job_id", "operation", name="uq_benchmark_metrics_job_operation"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("benchmark_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    operation: Mapped[str] = mapped_column(String(100), nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    mean_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    p99_ns: Mapped[int] = mapped_column(BigInteger, nullable=False)
    pqc_overhead_basis_points: Mapped[int | None] = mapped_column(Integer, nullable=True)

    job: Mapped[BenchmarkJob] = relationship("BenchmarkJob", back_populates="metrics")


class BenchmarkIdempotency(Base):
    __tablename__ = "benchmark_idempotency"
    __table_args__ = (
        UniqueConstraint("actor_id", "key_hash", name="uq_benchmark_idempotency_actor_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    job_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("benchmark_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


def compute_benchmark_request_hash(
    crypto_engine: CryptoEngine,
    actor_id: str,
    iterations: int,
    include_pqc: bool,
) -> bytes:
    """
    Canonical request hash for benchmark creation idempotency.
    Domain: b"benchmark:" + actor UUID + iterations uint32be + include_pqc byte (1 or 0).
    Uses CryptoEngine.sm3_digest.
    """
    pqc_byte = b"\x01" if include_pqc else b"\x00"
    payload = b"benchmark:" + actor_id.encode("utf-8") + iterations.to_bytes(4, byteorder="big") + pqc_byte
    return crypto_engine.sm3_digest(payload)
