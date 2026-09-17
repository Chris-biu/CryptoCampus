from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import math


class BenchmarkError(Exception):
    """Base exception for benchmark failures."""
    pass


@dataclass(frozen=True)
class SampleSummary:
    sample_count: int
    mean_ns: float
    p99_ns: int

    @property
    def mean_ms(self) -> float:
        return ns_to_ms(self.mean_ns)

    @property
    def p99_ms(self) -> float:
        return ns_to_ms(self.p99_ns)


def ns_to_ms(ns: float | int) -> float:
    """Convert nanoseconds to milliseconds, rounded to 6 decimal places."""
    return round(float(ns) / 1_000_000.0, 6)


def summarize(samples_ns: Sequence[int]) -> SampleSummary:
    """
    Summarize a collection of nanosecond samples into mean and nearest-rank P99.
    
    Nearest-rank method:
        rank = ceil(0.99 * n)
        p99 = sorted_samples[rank - 1]
    """
    if not samples_ns or any(value <= 0 for value in samples_ns):
        raise BenchmarkError("invalid_samples")

    ordered = sorted(samples_ns)
    n = len(ordered)
    rank = math.ceil(0.99 * n)
    mean_ns = sum(ordered) / n
    p99_ns = ordered[rank - 1]

    return SampleSummary(
        sample_count=n,
        mean_ns=mean_ns,
        p99_ns=p99_ns,
    )


def compute_pqc_overhead(classic_mean_ns: float, pqc_mean_ns: float) -> float | None:
    """
    Compute PQC overhead percentage relative to classic implementation:
        ((pqc_mean / classic_mean) - 1) * 100
    Returns None if classic_mean <= 0.
    """
    if classic_mean_ns <= 0:
        return None
    return round(((pqc_mean_ns / classic_mean_ns) - 1.0) * 100.0, 6)


def percent_to_basis_points(percent: float | None) -> int | None:
    """
    Convert a percentage (e.g. 150.123456%) to integer basis points (15012).
    1% = 100 basis points.
    """
    if percent is None:
        return None
    return int(round(percent * 100.0))


def basis_points_to_percent(basis_points: int | None) -> float | None:
    """
    Convert integer basis points (15012) back to percentage (150.12%).
    """
    if basis_points is None:
        return None
    return round(float(basis_points) / 100.0, 6)
