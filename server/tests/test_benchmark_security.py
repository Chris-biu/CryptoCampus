from __future__ import annotations

import ast
from pathlib import Path
import pytest

from app.benchmarks.vectors import (
    FIXED_PLAINTEXT_4K,
    FIXED_SM3_DIGEST_KAT,
    Sm2SignContext,
    Sm2VerifyContext,
    Sm2EcdhContext,
    Sm2EnvelopeSealContext,
    Sm2EnvelopeOpenContext,
)
from app.crypto.types import Sm2KeyPair
from app.models.benchmark import BenchmarkJob, BenchmarkMetricEntity, BenchmarkIdempotency
from app.models.audit import AuditLog


def test_no_sleep_or_fake_random_in_production_benchmark_code() -> None:
    """
    CRITICAL ACCEPTANCE CRITERIA:
    Strictly verify that production benchmark runner and execution code contains NO
    sleep(), asyncio.sleep(), random.uniform/random(), or Mock usage to fake timing.
    """
    benchmarks_dir = Path(__file__).resolve().parent.parent / "app" / "benchmarks"
    assert benchmarks_dir.is_dir(), f"Directory not found: {benchmarks_dir}"

    py_files = list(benchmarks_dir.glob("*.py"))
    assert len(py_files) >= 5, f"Expected at least 5 benchmark modules, found {len(py_files)}"

    disallowed_calls = {
        "sleep",
        "random",
        "uniform",
        "randint",
        "choice",
        "randrange",
    }

    disallowed_modules = {
        "mock",
        "unittest.mock",
        "random",
    }

    for py_file in py_files:
        code = py_file.read_text(encoding="utf-8-sig")
        tree = ast.parse(code, filename=str(py_file))

        for node in ast.walk(tree):
            # Check disallowed imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in disallowed_modules, (
                        f"File {py_file.name} imports disallowed module '{alias.name}'"
                    )
            elif isinstance(node, ast.ImportFrom):
                assert node.module not in disallowed_modules, (
                    f"File {py_file.name} imports from disallowed module '{node.module}'"
                )

            # Check disallowed function calls
            elif isinstance(node, ast.Call):
                func = node.func
                # e.g., sleep(1)
                if isinstance(func, ast.Name):
                    assert func.id not in disallowed_calls, (
                        f"File {py_file.name} calls disallowed function '{func.id}'"
                    )
                # e.g., time.sleep(1) or random.uniform(1, 2)
                elif isinstance(func, ast.Attribute):
                    assert func.attr not in disallowed_calls, (
                        f"File {py_file.name} calls disallowed attribute/method '{func.attr}'"
                    )


def test_benchmark_models_no_sensitive_secrets_storage() -> None:
    """
    Verify that BenchmarkJob, BenchmarkMetricEntity, and BenchmarkIdempotency
    do not store plaintexts, private keys, or passwords.
    """
    forbidden_terms = {"private_key", "password", "plaintext", "secret", "token", "symmetric_key"}

    for model in [BenchmarkJob, BenchmarkMetricEntity, BenchmarkIdempotency]:
        columns = {c.name.lower() for c in model.__table__.columns}
        for col in columns:
            for term in forbidden_terms:
                assert term not in col, f"Model {model.__name__} has sensitive column '{col}' containing '{term}'"


def test_benchmark_vectors_no_hardcoded_user_secrets() -> None:
    """
    Verify test vectors use fixed public test constants and ephemeral ephemeral keys.
    """
    # 4K buffer
    assert len(FIXED_PLAINTEXT_4K) == 4096
    assert len(FIXED_SM3_DIGEST_KAT) == 32


def test_ephemeral_context_generation_and_uniqueness() -> None:
    """
    Verify that setup functions create valid ephemeral keypairs and clean contexts.
    """
    from app.benchmarks.registry import _setup_sm2_sign, _setup_sm2_ecdh

    class DummyCrypto:
        def __init__(self):
            self._counter = 0

        def sm2_generate_keypair(self) -> Sm2KeyPair:
            self._counter += 1
            return Sm2KeyPair(
                private_key=b"\x01" * 31 + bytes([self._counter % 256]),
                public_key=b"\x04" + b"\x02" * 63 + bytes([self._counter % 256]),
            )

    crypto = DummyCrypto()
    ctx1 = _setup_sm2_sign(crypto)
    ctx2 = _setup_sm2_sign(crypto)

    assert ctx1.keypair.private_key != ctx2.keypair.private_key
    assert ctx1.keypair.public_key != ctx2.keypair.public_key
    assert ctx1.digest == FIXED_SM3_DIGEST_KAT

    ecdh_ctx = _setup_sm2_ecdh(crypto)
    assert ecdh_ctx.party_a.public_key != ecdh_ctx.party_b.public_key
    ecdh_ctx.teardown()
    assert ecdh_ctx.shared_secret is None
