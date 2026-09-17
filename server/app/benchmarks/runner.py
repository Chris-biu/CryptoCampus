from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import time

from app.benchmarks.registry import ALL_OPERATIONS, BenchmarkOperation, get_benchmark_operations
from app.benchmarks.statistics import (
    BenchmarkError,
    SampleSummary,
    compute_pqc_overhead,
    ns_to_ms,
    summarize,
)
from app.crypto.engine import CryptoEngine


@dataclass(frozen=True)
class BenchmarkMetricResult:
    operation: str
    sample_count: int
    mean_ns: float
    p99_ns: int
    mean_ms: float
    p99_ms: float
    pqc_overhead_percent: float | None


class BenchmarkRunner:
    def __init__(self, crypto_engine: CryptoEngine):
        self.crypto_engine = crypto_engine

    def run(
        self,
        *,
        iterations: int,
        include_pqc: bool,
        clock_ns: Callable[[], int] = time.perf_counter_ns,
    ) -> list[BenchmarkMetricResult]:
        if iterations < 10 or iterations > 10000:
            raise BenchmarkError("invalid_iterations")

        status = self.crypto_engine.provider_status()
        if status.state != "online":
            raise BenchmarkError("engine_unavailable")

        operations = get_benchmark_operations(include_pqc)
        capabilities = dict(status.capabilities)

        if include_pqc:
            pqc_supported = any(capabilities.get(op.required_capability, False) for op in operations if op.is_pqc)
            if not pqc_supported:
                raise BenchmarkError("pqc_unavailable")

        # Filter operations by supported capabilities
        executable_ops: list[BenchmarkOperation] = []
        for op in operations:
            if op.required_capability == "sm2":
                if capabilities.get("sm2", False):
                    executable_ops.append(op)
            elif op.required_capability == "envelope":
                if capabilities.get("sm2", False) and capabilities.get("sm4_gcm", False):
                    executable_ops.append(op)
            elif op.required_capability == "hybrid_envelope":
                if capabilities.get("hybrid_envelope", False):
                    executable_ops.append(op)

        if not executable_ops:
            raise BenchmarkError("no_executable_operations")

        summaries: dict[str, SampleSummary] = {}
        warmup_count = min(5, iterations)

        for op in executable_ops:
            ctx = op.setup(self.crypto_engine)
            try:
                # 1. Warmup (not counted in samples)
                for _ in range(warmup_count):
                    op.run_once(self.crypto_engine, ctx)

                # 2. Timed measurement loop
                samples: list[int] = []
                for _ in range(iterations):
                    t0 = clock_ns()
                    op.run_once(self.crypto_engine, ctx)
                    t1 = clock_ns()
                    samples.append(t1 - t0)

                # 3. Correctness check
                if not op.verify(self.crypto_engine, ctx):
                    raise BenchmarkError(f"verification_failed:{op.name}")

                summaries[op.name] = summarize(samples)
            finally:
                op.teardown(self.crypto_engine, ctx)

        # 4. Build results and calculate PQC overhead
        results: list[BenchmarkMetricResult] = []
        for op in executable_ops:
            s = summaries[op.name]
            overhead: float | None = None
            if op.paired_with and op.paired_with in summaries:
                classic_mean = summaries[op.paired_with].mean_ns
                overhead = compute_pqc_overhead(classic_mean, s.mean_ns)

            results.append(
                BenchmarkMetricResult(
                    operation=op.name,
                    sample_count=s.sample_count,
                    mean_ns=s.mean_ns,
                    p99_ns=s.p99_ns,
                    mean_ms=s.mean_ms,
                    p99_ms=s.p99_ms,
                    pqc_overhead_percent=overhead,
                )
            )

        return results
