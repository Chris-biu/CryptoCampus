from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Sequence

from app.benchmarks.runner import BenchmarkMetricResult, BenchmarkRunner
from app.benchmarks.statistics import BenchmarkError
from app.crypto.dependencies import get_crypto_engine


def run_smoke_benchmark(
    iterations: int = 10,
    include_pqc: bool = True,
    output_path: str | None = None,
    output_format: str | None = None,
) -> list[BenchmarkMetricResult]:
    """
    Run controlled smoke benchmark with real crypto engine.
    """
    engine = get_crypto_engine()
    status = engine.provider_status()

    if status.state != "online":
        print(f"Error: Crypto engine is {status.state} (provider: {status.provider}). Benchmarking requires an online engine.", file=sys.stderr)
        raise SystemExit(1)

    print("=" * 70)
    print("CryptoCampus Benchmark Smoke Test (Real CryptoEngine Timing)")
    print("=" * 70)
    print(f"Iterations   : {iterations}")
    print(f"Include PQC  : {include_pqc}")
    print(f"Provider     : {status.provider}")
    print(f"Engine State : {status.state}")
    print(f"Capabilities : {status.capabilities}")
    print("-" * 70)

    runner = BenchmarkRunner(engine)
    try:
        results = runner.run(iterations=iterations, include_pqc=include_pqc)
    except BenchmarkError as exc:
        print(f"Benchmark failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    # Print table header
    header = f"{'Operation':<26} | {'Samples':<8} | {'Mean (ms)':<11} | {'P99 (ms)':<11} | {'PQC Overhead':<12}"
    print(header)
    print("-" * len(header))

    for r in results:
        overhead_str = f"{r.pqc_overhead_percent:+.2f}%" if r.pqc_overhead_percent is not None else "N/A"
        print(
            f"{r.operation:<26} | {r.sample_count:<8} | {r.mean_ms:<11.6f} | {r.p99_ms:<11.6f} | {overhead_str:<12}"
        )
    print("=" * 70)

    if output_path:
        path = Path(output_path)
        fmt = (output_format or (path.suffix.lstrip(".").lower() if path.suffix else "json")).lower()
        if fmt not in ("json", "csv"):
            fmt = "json"

        if fmt == "json":
            data = [
                {
                    "operation": r.operation,
                    "sample_count": r.sample_count,
                    "mean_ms": r.mean_ms,
                    "p99_ms": r.p99_ms,
                    "pqc_overhead_percent": r.pqc_overhead_percent,
                }
                for r in results
            ]
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        else:
            with path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["operation", "sample_count", "mean_ms", "p99_ms", "pqc_overhead_percent"])
                for r in results:
                    overhead_val = f"{r.pqc_overhead_percent:.6f}" if r.pqc_overhead_percent is not None else ""
                    writer.writerow([
                        r.operation,
                        r.sample_count,
                        f"{r.mean_ms:.6f}",
                        f"{r.p99_ms:.6f}",
                        overhead_val,
                    ])
        print(f"Exported benchmark results to {path.resolve()} ({fmt.upper()})")

    return results


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="CryptoCampus Performance Benchmark Smoke CLI")
    parser.add_argument(
        "--iterations",
        type=int,
        default=10,
        help="Number of iterations for each operation (10..10000, default 10)",
    )
    parser.add_argument(
        "--include-pqc",
        action="store_true",
        default=True,
        help="Include post-quantum cryptography benchmark operations (default: True)",
    )
    parser.add_argument(
        "--no-pqc",
        action="store_false",
        dest="include_pqc",
        help="Disable post-quantum cryptography operations",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional path to save exported results (e.g. results.json or results.csv)",
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["json", "csv"],
        default=None,
        help="Export format (defaults to file extension or json)",
    )

    args = parser.parse_args(argv)
    run_smoke_benchmark(
        iterations=args.iterations,
        include_pqc=args.include_pqc,
        output_path=args.output,
        output_format=args.format,
    )


if __name__ == "__main__":
    main()
