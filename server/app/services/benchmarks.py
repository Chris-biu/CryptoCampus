from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import json
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.benchmarks.executor import BenchmarkExecutor, QueueFullError
from app.benchmarks.registry import get_benchmark_operations
from app.benchmarks.statistics import basis_points_to_percent, ns_to_ms
from app.crypto.engine import CryptoEngine
from app.models.audit import AuditLog
from app.models.benchmark import (
    BenchmarkIdempotency,
    BenchmarkJob,
    BenchmarkMetricEntity,
    compute_benchmark_request_hash,
)
from app.schemas.benchmark import (
    BenchmarkMetricResponse,
    BenchmarkResultResponse,
    JobResponse,
)


class BenchmarkServiceError(Exception):
    def __init__(self, message: str, status_code: int = 400, code: str = "ERROR") -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


class BenchmarkService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        executor: BenchmarkExecutor,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.executor = executor

    def create_job(
        self,
        *,
        actor_id: str,
        iterations: int,
        include_pqc: bool,
        idempotency_key: str,
        now: datetime,
    ) -> JobResponse:
        # 1. Check engine availability
        status = self.crypto_engine.provider_status()
        if status.state != "online":
            raise BenchmarkServiceError(
                "密码引擎不可用或离线",
                status_code=503,
                code="ENGINE_UNAVAILABLE",
            )

        # 2. If PQC requested, check capabilities
        if include_pqc:
            pqc_available = bool(status.capabilities.get("hybrid_envelope", False))
            if not pqc_available:
                raise BenchmarkServiceError(
                    "所请求的抗量子 Provider 能力不可用",
                    status_code=503,
                    code="PQC_UNAVAILABLE",
                )

        # 3. Check idempotency
        key_hash = self.crypto_engine.sm3_digest(idempotency_key.encode("utf-8"))
        req_hash = compute_benchmark_request_hash(self.crypto_engine, actor_id, iterations, include_pqc)

        existing_idemp = self.session.scalar(
            select(BenchmarkIdempotency).where(
                BenchmarkIdempotency.actor_id == actor_id,
                BenchmarkIdempotency.key_hash == key_hash,
            )
        )
        if existing_idemp is not None:
            if existing_idemp.request_hash == req_hash:
                # Same key & same parameters -> return existing job
                existing_job = self.session.scalar(
                    select(BenchmarkJob).where(BenchmarkJob.id == existing_idemp.job_id)
                )
                if existing_job is not None:
                    return JobResponse(
                        id=existing_job.id,
                        status=existing_job.status,  # type: ignore[arg-type]
                        created_at=existing_job.created_at,
                    )
            # Same key with different parameters -> 409 Conflict
            raise BenchmarkServiceError(
                "幂等键冲突：已存在相同 Idempotency-Key 但参数不同的任务",
                status_code=409,
                code="CONFLICT",
            )

        # 4. Create and persist Job + Idempotency + AuditLog
        job_id = str(uuid.uuid4())
        job = BenchmarkJob(
            id=job_id,
            actor_id=actor_id,
            iterations=iterations,
            include_pqc=include_pqc,
            status="queued",
            engine_version=status.version,
            provider_snapshot_json=json.dumps(dict(status.capabilities), sort_keys=True),
            created_at=now,
        )
        self.session.add(job)
        self.session.flush()

        idemp = BenchmarkIdempotency(
            id=str(uuid.uuid4()),
            actor_id=actor_id,
            key_hash=key_hash,
            request_hash=req_hash,
            job_id=job_id,
            created_at=now,
        )
        audit_detail = f"create:{job_id}:{iterations}:{include_pqc}".encode("utf-8")
        audit = AuditLog(
            actor=actor_id,
            action="benchmark.create",
            target=f"benchmark:{job_id}",
            detail_hash=self.crypto_engine.sm3_digest(audit_detail),
            ts=now,
        )
        self.session.add_all([idemp, audit])
        self.session.commit()

        # 5. Enqueue into executor
        try:
            self.executor.enqueue(job_id)
        except QueueFullError:
            fail_time = datetime.now(timezone.utc)
            job.status = "failed"
            job.error_code = "QUEUE_FULL"
            job.finished_at = fail_time
            self.session.commit()
            raise BenchmarkServiceError(
                "基准测试执行队列已满，请稍后重试",
                status_code=429,
                code="RATE_LIMITED",
            )

        return JobResponse(
            id=job.id,
            status=job.status,  # type: ignore[arg-type]
            created_at=job.created_at,
        )

    def get_job(self, benchmark_id: str) -> BenchmarkResultResponse:
        job = self.session.scalar(select(BenchmarkJob).where(BenchmarkJob.id == benchmark_id))
        if job is None:
            raise BenchmarkServiceError("基准测试任务不存在", status_code=404, code="NOT_FOUND")

        metrics_resp: list[BenchmarkMetricResponse] = []
        if job.status == "completed":
            metrics_entities = self.session.scalars(
                select(BenchmarkMetricEntity)
                .where(BenchmarkMetricEntity.job_id == benchmark_id)
                .order_by(BenchmarkMetricEntity.id)
            ).all()

            for m in metrics_entities:
                metrics_resp.append(
                    BenchmarkMetricResponse(
                        operation=m.operation,
                        mean_ms=ns_to_ms(m.mean_ns),
                        p99_ms=ns_to_ms(m.p99_ns),
                        pqc_overhead_percent=basis_points_to_percent(m.pqc_overhead_basis_points),
                    )
                )

        return BenchmarkResultResponse(
            id=job.id,
            status=job.status,  # type: ignore[arg-type]
            metrics=metrics_resp,
            created_at=job.created_at,
        )

    def export_job(self, benchmark_id: str, format: str, actor_id: str | None = None) -> tuple[str, str, bytes]:
        if format not in ("csv", "json"):
            raise BenchmarkServiceError("不支持的导出格式，仅支持 csv 或 json", status_code=422, code="VALIDATION_ERROR")

        job = self.session.scalar(select(BenchmarkJob).where(BenchmarkJob.id == benchmark_id))
        if job is None:
            raise BenchmarkServiceError("基准测试任务不存在", status_code=404, code="NOT_FOUND")
        if job.status != "completed":
            raise BenchmarkServiceError("只有已完成的基准测试结果才支持导出", status_code=409, code="CONFLICT")

        job_result = self.get_job(benchmark_id)
        effective_actor = actor_id or job.actor_id
        now = datetime.now(timezone.utc)
        audit = AuditLog(
            actor=effective_actor,
            action="benchmark.export",
            target=f"benchmark:{benchmark_id}",
            detail_hash=self.crypto_engine.sm3_digest(f"export:{benchmark_id}:{format}".encode("utf-8")),
            ts=now,
        )
        self.session.add(audit)
        self.session.commit()

        if format == "json":
            content_bytes = job_result.model_dump_json(indent=2).encode("utf-8")
            return "application/json", f"benchmark-{benchmark_id}.json", content_bytes

        # format == "csv"
        # UTF-8 without BOM, \r\n line terminators
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(["operation", "mean_ms", "p99_ms", "pqc_overhead_percent"])
        for m in job_result.metrics:
            overhead_str = f"{m.pqc_overhead_percent:.6f}" if m.pqc_overhead_percent is not None else ""
            writer.writerow([
                m.operation,
                f"{m.mean_ms:.6f}",
                f"{m.p99_ms:.6f}",
                overhead_str,
            ])
        csv_bytes = output.getvalue().encode("utf-8")
        return "text/csv; charset=utf-8", f"benchmark-{benchmark_id}.csv", csv_bytes
