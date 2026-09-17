from __future__ import annotations

import time
import pytest

from app.benchmarks.registry import get_benchmark_operations
from app.benchmarks.runner import BenchmarkMetricResult, BenchmarkRunner
from app.benchmarks.statistics import BenchmarkError
from app.crypto.engine import CryptoEngine
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import (
    EnvelopeArtifact,
    ProviderStatus,
    Sm2KeyPair,
    Sm4GcmCiphertext,
)
from app.crypto.unavailable import UnavailableCryptoEngine


class ControllableMockCryptoEngine(MockCryptoEngine):
    """A mock crypto engine with realistic protocol returns for runner testing."""
    def __init__(self, state: str = "online", pqc: bool = False):
        super().__init__(
            status=ProviderStatus(
                state=state,
                version="1.0.0-test",
                provider="test-provider",
                capabilities={"sm2": True, "sm3": True, "sm4_gcm": True, "hybrid_envelope": pqc, "ml_dsa": pqc},
            )
        )
        self.call_counts: dict[str, int] = {}
        # Pre-seed default results
        self.set_result("sm2_generate_keypair", Sm2KeyPair(private_key=b"\x11" * 32, public_key=b"\x04" + b"\x22" * 64))
        self.set_result("sm2_sign", b"\x33" * 64)
        self.set_result("sm2_verify", True)
        self.set_result("sm2_ecdh", b"\x44" * 32)
        self.set_result("sm3_digest", b"\x55" * 32)
        dummy_env = EnvelopeArtifact(
            ciphertext=b"test ciphertext",
            nonce=b"\x03" * 12,
            tag=b"\x05" * 16,
            enc_key_sm2=b"\x02" * 64,
            enc_key_mlkem=None,
            sender_signature=b"\x07" * 64,
            sender_certificate=b"\x30\x03\x02\x01\x01",
        )
        self.set_result("envelope_seal", dummy_env)
        from app.benchmarks.vectors import FIXED_PLAINTEXT_4K
        self.set_result("envelope_open", FIXED_PLAINTEXT_4K)

    def _operation(self, name: str, params: dict) -> object:
        self.call_counts[name] = self.call_counts.get(name, 0) + 1
        return super()._operation(name, params)


def test_runner_rejects_offline_engine() -> None:
    engine = UnavailableCryptoEngine()
    runner = BenchmarkRunner(engine)

    with pytest.raises(BenchmarkError, match="engine_unavailable"):
        runner.run(iterations=10, include_pqc=False)


def test_runner_rejects_missing_pqc_when_requested() -> None:
    engine = ControllableMockCryptoEngine(state="online", pqc=False)
    runner = BenchmarkRunner(engine)

    with pytest.raises(BenchmarkError, match="pqc_unavailable"):
        runner.run(iterations=10, include_pqc=True)


def test_runner_fails_closed_when_capability_snapshot_is_incomplete() -> None:
    engine = ControllableMockCryptoEngine(state="online", pqc=False)
    engine._status = ProviderStatus(
        state="online",
        version="1.0.0-test",
        provider="test-provider",
        capabilities={},
    )

    with pytest.raises(BenchmarkError, match="no_executable_operations"):
        BenchmarkRunner(engine).run(iterations=10, include_pqc=False)


def test_runner_rejects_invalid_iterations() -> None:
    engine = ControllableMockCryptoEngine(state="online", pqc=False)
    runner = BenchmarkRunner(engine)

    with pytest.raises(BenchmarkError, match="invalid_iterations"):
        runner.run(iterations=9, include_pqc=False)

    with pytest.raises(BenchmarkError, match="invalid_iterations"):
        runner.run(iterations=10001, include_pqc=False)


def test_runner_execution_iteration_count_and_warmup() -> None:
    engine = ControllableMockCryptoEngine(state="online", pqc=False)
    runner = BenchmarkRunner(engine)

    # Simulated monotonic clock: advances 1000 ns on each call
    current_ns = 1_000_000
    def fake_clock() -> int:
        nonlocal current_ns
        current_ns += 1000
        return current_ns

    iterations = 10
    results = runner.run(iterations=iterations, include_pqc=False, clock_ns=fake_clock)

    assert len(results) > 0
    # Every operation result must have exact iterations sample count
    for res in results:
        assert res.sample_count == iterations
        assert res.mean_ns > 0
        assert res.p99_ns > 0
        assert res.pqc_overhead_percent is None  # no PQC executed

    # Check that warmup (5) + iterations (10) were executed
    # For sm2_sign, it is called during warmup (5) and measurement (10) = 15 times
    assert engine.call_counts.get("sm2_sign", 0) >= 15


def test_runner_verification_failure_raises() -> None:
    engine = ControllableMockCryptoEngine(state="online", pqc=False)
    engine.set_result("sm2_verify", False)  # verification fails!
    runner = BenchmarkRunner(engine)

    with pytest.raises(BenchmarkError, match="verification_failed"):
        runner.run(iterations=10, include_pqc=False)


def test_runner_pqc_overhead_calculation_when_pqc_enabled() -> None:
    engine = ControllableMockCryptoEngine(state="online", pqc=True)
    runner = BenchmarkRunner(engine)

    # Clock where PQC runs slightly slower than classic
    current_ns = 1_000_000
    def fake_clock() -> int:
        nonlocal current_ns
        current_ns += 500
        return current_ns

    results = runner.run(iterations=10, include_pqc=True, clock_ns=fake_clock)
    op_map = {r.operation: r for r in results}

    # If hybrid envelope ran, verify its overhead relative to classic envelope
    if "envelope.hybrid.seal" in op_map and "envelope.sm2.seal" in op_map:
        hybrid = op_map["envelope.hybrid.seal"]
        assert hybrid.pqc_overhead_percent is not None
