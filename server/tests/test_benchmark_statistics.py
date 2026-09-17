from __future__ import annotations

import math
import random
import pytest

from app.benchmarks.statistics import (
    BenchmarkError,
    SampleSummary,
    compute_pqc_overhead,
    summarize,
    ns_to_ms,
    percent_to_basis_points,
    basis_points_to_percent,
)


def test_summarize_rejects_empty_samples() -> None:
    with pytest.raises(BenchmarkError, match="invalid_samples"):
        summarize([])


def test_summarize_rejects_non_positive_samples() -> None:
    with pytest.raises(BenchmarkError, match="invalid_samples"):
        summarize([100, 0, 200])

    with pytest.raises(BenchmarkError, match="invalid_samples"):
        summarize([100, -50, 200])


def test_summarize_golden_10_samples() -> None:
    # 10 samples: 1..10. rank = ceil(0.99 * 10) = 10 -> index 9 -> 10th element (100)
    samples = [i * 10 for i in range(1, 11)]  # 10, 20, ..., 100
    summary = summarize(samples)

    assert summary.sample_count == 10
    assert summary.mean_ns == 55.0
    assert summary.p99_ns == 100
    assert summary.mean_ms == 0.000055
    assert summary.p99_ms == 0.000100


def test_summarize_golden_100_samples() -> None:
    # 100 samples: 1..100. rank = ceil(0.99 * 100) = 99 -> index 98 -> 99th element (99)
    samples = list(range(1, 101))
    summary = summarize(samples)

    assert summary.sample_count == 100
    assert summary.mean_ns == 50.5
    assert summary.p99_ns == 99


def test_summarize_golden_101_samples() -> None:
    # 101 samples: 1..101. rank = ceil(0.99 * 101) = ceil(99.99) = 100 -> index 99 -> 100th element (100)
    samples = list(range(1, 102))
    summary = summarize(samples)

    assert summary.sample_count == 101
    assert summary.p99_ns == 100


def test_summarize_order_independence() -> None:
    samples = list(range(1, 101))
    shuffled = samples.copy()
    random.seed(42)
    random.shuffle(shuffled)

    s1 = summarize(samples)
    s2 = summarize(shuffled)

    assert s1.sample_count == s2.sample_count
    assert s1.mean_ns == s2.mean_ns
    assert s1.p99_ns == s2.p99_ns
    assert s1.mean_ms == s2.mean_ms
    assert s1.p99_ms == s2.p99_ms


def test_summarize_large_integers_no_overflow() -> None:
    # 100 large numbers (each 10 seconds in ns = 10_000_000_000)
    base = 10_000_000_000
    samples = [base + i for i in range(100)]
    summary = summarize(samples)

    assert summary.sample_count == 100
    assert summary.mean_ns == base + 49.5
    assert summary.p99_ns == base + 98


def test_ns_to_ms_rounding() -> None:
    # 1_234_567 ns = 1.234567 ms
    assert ns_to_ms(1_234_567) == 1.234567
    # rounding to 6 decimals
    assert ns_to_ms(1_234_567_890) == 1234.56789


def test_compute_pqc_overhead_positive() -> None:
    # classic = 1000 ns, pqc = 2500 ns -> overhead = ((2500/1000) - 1) * 100 = 150.0%
    overhead = compute_pqc_overhead(1000.0, 2500.0)
    assert overhead == 150.0


def test_compute_pqc_overhead_negative() -> None:
    # pqc faster than classic: classic = 2000, pqc = 1500 -> ((1500/2000) - 1) * 100 = -25.0%
    overhead = compute_pqc_overhead(2000.0, 1500.0)
    assert overhead == -25.0


def test_compute_pqc_overhead_zero_and_missing() -> None:
    # classic mean <= 0 -> None
    assert compute_pqc_overhead(0.0, 1500.0) is None
    assert compute_pqc_overhead(-100.0, 1500.0) is None
    # identical -> 0.0%
    assert compute_pqc_overhead(1000.0, 1000.0) == 0.0


def test_basis_points_conversion() -> None:
    # 150.123456% -> 15012 basis points (integer representation)
    bp = percent_to_basis_points(150.123456)
    assert bp == 15012
    assert basis_points_to_percent(bp) == 150.12

    assert percent_to_basis_points(None) is None
    assert basis_points_to_percent(None) is None
