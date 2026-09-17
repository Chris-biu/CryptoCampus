from __future__ import annotations

import json
from pathlib import Path
import pytest
from unittest.mock import patch

from app.benchmarks.smoke import run_smoke_benchmark, main
from app.crypto.unavailable import UnavailableCryptoEngine
from tests.test_benchmark_runner import ControllableMockCryptoEngine


def test_smoke_cli_offline_engine_exits() -> None:
    offline_engine = UnavailableCryptoEngine()
    with patch("app.benchmarks.smoke.get_crypto_engine", return_value=offline_engine):
        with pytest.raises(SystemExit) as exc:
            run_smoke_benchmark(iterations=10, include_pqc=False)
        assert exc.value.code == 1


def test_smoke_cli_execution_and_json_export(tmp_path: Path) -> None:
    online_engine = ControllableMockCryptoEngine(state="online", pqc=False)
    output_json = tmp_path / "smoke_out.json"

    with patch("app.benchmarks.smoke.get_crypto_engine", return_value=online_engine):
        results = run_smoke_benchmark(
            iterations=10,
            include_pqc=False,
            output_path=str(output_json),
            output_format="json",
        )

    assert len(results) == 5
    assert output_json.exists()
    data = json.loads(output_json.read_text(encoding="utf-8"))
    assert len(data) == 5
    assert data[0]["operation"] == "envelope.sm2.seal"
    assert data[0]["sample_count"] == 10
    assert data[0]["mean_ms"] > 0
    assert data[0]["p99_ms"] > 0


def test_smoke_cli_csv_export(tmp_path: Path) -> None:
    online_engine = ControllableMockCryptoEngine(state="online", pqc=False)
    output_csv = tmp_path / "smoke_out.csv"

    with patch("app.benchmarks.smoke.get_crypto_engine", return_value=online_engine):
        main(["--iterations", "10", "--no-pqc", "--output", str(output_csv), "--format", "csv"])

    assert output_csv.exists()
    lines = output_csv.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "operation,sample_count,mean_ms,p99_ms,pqc_overhead_percent"
    assert len(lines) == 6
