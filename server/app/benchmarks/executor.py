from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import json
import logging
import queue
import threading
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from app.benchmarks.runner import BenchmarkMetricResult, BenchmarkRunner
from app.benchmarks.statistics import BenchmarkError, percent_to_basis_points
from app.crypto.dependencies import get_crypto_engine
from app.crypto.locks import ProviderLockError, ProviderOperationLock, provider_operation_lock
from app.models.audit import AuditLog
from app.models.benchmark import BenchmarkJob, BenchmarkMetricEntity

logger = logging.getLogger("app.benchmarks.executor")


class QueueFullError(Exception):
    """Raised when the benchmark task queue has reached capacity."""
    pass


def recover_interrupted_jobs(session: Session) -> int:
    """
    Recover any jobs left in 'running' state after an application crash or restart.
    Marks them as failed with error_code='INTERRUPTED'.
    """
    now = datetime.now(timezone.utc)
    result = session.execute(
        update(BenchmarkJob)
        .where(BenchmarkJob.status == "running")
        .values(status="failed", error_code="INTERRUPTED", finished_at=now)
    )
    session.commit()
    return result.rowcount


class BenchmarkExecutor:
    """
    Bounded, single-worker in-process executor for benchmark jobs.
    Ensures serial execution with at most 1 benchmark running at any time.
    """
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        runner_factory: Callable[[], Any] | None = None,
        crypto_engine: Any | None = None,
        lock: ProviderOperationLock | None = None,
        max_queue_size: int = 4,
    ) -> None:
        self.session_factory = session_factory
        self.crypto_engine = crypto_engine
        self.runner_factory = runner_factory or (lambda: BenchmarkRunner(self.get_engine()))
        self.provider_lock = lock or provider_operation_lock
        self.max_queue_size = max_queue_size
        self._queue: queue.Queue[str | None] = queue.Queue(maxsize=max_queue_size)
        self._worker_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def get_engine(self) -> Any:
        return self.crypto_engine if self.crypto_engine is not None else get_crypto_engine()

    def start(self) -> None:
        if self._worker_thread is not None and self._worker_thread.is_alive():
            return
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._run_worker, name="benchmark-worker", daemon=True)
        self._worker_thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        if self._worker_thread is not None and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

    def enqueue(self, job_id: str) -> bool:
        """Enqueue a job_id. Raises QueueFullError if queue capacity is exceeded."""
        try:
            self._queue.put_nowait(job_id)
            return True
        except queue.Full:
            raise QueueFullError("queue_full")

    def _run_worker(self) -> None:
        while not self._stop_event.is_set():
            try:
                job_id = self._queue.get(timeout=0.5)
                if job_id is None:
                    break
                try:
                    self.process_job_sync(job_id)
                finally:
                    self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.exception("Unexpected error in benchmark worker loop: %s", e)

    def process_job_sync(self, job_id: str) -> None:
        now = datetime.now(timezone.utc)
        with self.session_factory() as session:
            # 1. Atomic claim: queued -> running
            result = session.execute(
                update(BenchmarkJob)
                .where(BenchmarkJob.id == job_id, BenchmarkJob.status == "queued")
                .values(status="running", started_at=now)
            )
            session.commit()
            if result.rowcount == 0:
                return

            job = session.scalar(select(BenchmarkJob).where(BenchmarkJob.id == job_id))
            if job is None:
                return

            try:
                # 2. Acquire shared provider read lock with timeout
                with self.provider_lock.reader_lock(timeout=10.0):
                    runner = self.runner_factory()
                    metric_results = runner.run(
                        iterations=job.iterations,
                        include_pqc=job.include_pqc,
                    )

                finish_time = datetime.now(timezone.utc)
                # 3. Persist metrics and update job status to completed
                for m in metric_results:
                    entity = BenchmarkMetricEntity(
                        job_id=job.id,
                        operation=m.operation,
                        sample_count=m.sample_count,
                        mean_ns=int(m.mean_ns),
                        p99_ns=m.p99_ns,
                        pqc_overhead_basis_points=percent_to_basis_points(m.pqc_overhead_percent),
                    )
                    session.add(entity)

                job.status = "completed"
                job.finished_at = finish_time
                job.error_code = None

                # Record audit log
                crypto = self.get_engine()
                detail_hash = crypto.sm3_digest(f"completed:{job.id}:{len(metric_results)}".encode("utf-8"))
                audit = AuditLog(
                    actor=job.actor_id,
                    action="benchmark.complete",
                    target=f"benchmark:{job.id}",
                    detail_hash=detail_hash,
                    ts=finish_time,
                )
                session.add(audit)
                session.commit()

            except Exception as exc:
                session.rollback()
                finish_time = datetime.now(timezone.utc)
                error_code = self._map_error_code(exc)

                job.status = "failed"
                job.finished_at = finish_time
                job.error_code = error_code

                try:
                    crypto = self.get_engine()
                    detail_hash = crypto.sm3_digest(f"failed:{job.id}:{error_code}".encode("utf-8"))
                    audit = AuditLog(
                        actor=job.actor_id,
                        action="benchmark.fail",
                        target=f"benchmark:{job.id}",
                        detail_hash=detail_hash,
                        ts=finish_time,
                    )
                    session.add(audit)
                except Exception:
                    pass

                session.commit()

    @staticmethod
    def _map_error_code(exc: Exception) -> str:
        if isinstance(exc, ProviderLockError):
            return "PROVIDER_BUSY"
        if isinstance(exc, BenchmarkError):
            msg = str(exc)
            if "engine_unavailable" in msg:
                return "ENGINE_UNAVAILABLE"
            if "pqc_unavailable" in msg:
                return "PQC_UNAVAILABLE"
            if "verification_failed" in msg:
                return "SELF_CHECK_FAILED"
            if "invalid_iterations" in msg:
                return "INVALID_ITERATIONS"
        return "INTERNAL"


_default_executor: BenchmarkExecutor | None = None


def get_default_executor() -> BenchmarkExecutor:
    global _default_executor
    if _default_executor is None:
        from app.db.session import SessionLocal
        _default_executor = BenchmarkExecutor(session_factory=SessionLocal)
    return _default_executor

