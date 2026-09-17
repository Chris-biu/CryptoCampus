import pytest
from app.core.errors import ApiError
from app.crypto.mock import MockCryptoEngine
from app.crypto.unavailable import UnavailableCryptoEngine
from app.schemas.inspect import ExperimentRequest
from app.services.experiments import ExperimentService


def test_sm4_mode_compare_has_warning_and_no_leak():
    engine = MockCryptoEngine()
    # Mock sm4_gcm_encrypt
    from app.crypto.types import Sm4GcmCiphertext
    engine.set_result("sm4_gcm_encrypt", Sm4GcmCiphertext(b"\x00" * 32, b"\x01" * 12, b"\x02" * 16))
    engine.set_result("sm3_digest", b"\xaa" * 32)

    service = ExperimentService()
    req = ExperimentRequest(
        experiment="sm4_mode_compare",
        input="A" * 64,  # Repeated blocks
    )

    result = service.run_experiment(req, engine)
    assert result.passed is True
    assert "禁止生产使用" in str(result.redacted_values)
    assert "key" not in result.redacted_values
    assert result.redacted_values.get("duplicate_blocks", 0) > 0


def test_sm3_avalanche_calculates_bit_difference():
    engine = MockCryptoEngine()
    # Mock two distinct digests with known bit diff
    engine.set_result("sm3_digest", b"\x00" * 32)
    # Configure DynamicMockCryptoEngine to return real sm3 or distinct digests
    service = ExperimentService()
    req = ExperimentRequest(
        experiment="sm3_avalanche",
        input="hello world\nhello worle",
    )

    result = service.run_experiment(req, engine)
    assert result.passed is True
    assert "bit_difference" in result.redacted_values
    assert "avalanche_percentage" in result.redacted_values


def test_sm2_curve_experiment():
    engine = MockCryptoEngine()
    service = ExperimentService()
    req = ExperimentRequest(
        experiment="sm2_curve",
        input="sm2p256v1",
    )
    result = service.run_experiment(req, engine)
    assert result.passed is True
    assert "curve_name" in result.redacted_values
    assert "p" in result.redacted_values


def test_ecdh_experiment_does_not_leak_shared_secret():
    engine = MockCryptoEngine()
    engine.set_result("sm2_ecdh", b"\x99" * 32)
    service = ExperimentService()
    req = ExperimentRequest(
        experiment="ecdh",
        input="vector-standard-01",
    )
    result = service.run_experiment(req, engine)
    assert result.passed is True
    assert result.redacted_values["keys_match"] is True
    # Shared secret itself MUST NOT be in redacted_values
    assert "shared_secret" not in result.redacted_values


def test_ml_kem_and_ml_dsa_fail_safely_when_unavailable():
    engine = UnavailableCryptoEngine()
    service = ExperimentService()

    with pytest.raises(ApiError) as exc_kem:
        service.run_experiment(ExperimentRequest(experiment="ml_kem", input="default"), engine)
    assert exc_kem.value.status_code == 503

    with pytest.raises(ApiError) as exc_dsa:
        service.run_experiment(ExperimentRequest(experiment="ml_dsa", input="default"), engine)
    assert exc_dsa.value.status_code == 503


def test_kat_fails_safely_when_unified_runner_unavailable():
    engine = MockCryptoEngine()
    service = ExperimentService()

    with pytest.raises(ApiError) as exc_kat:
        service.run_experiment(ExperimentRequest(experiment="kat", input="full_suite"), engine)
    assert exc_kat.value.status_code in (400, 503)


def test_experiment_service_edge_cases():
    service = ExperimentService()
    engine = MockCryptoEngine()

    # Empty input
    with pytest.raises(ApiError) as exc:
        service.run_experiment(ExperimentRequest(experiment="sm2_curve", input="   "), engine)
    assert exc.value.status_code == 400

    # sm3_avalanche invalid input (single line)
    with pytest.raises(ApiError) as exc:
        service.run_experiment(ExperimentRequest(experiment="sm3_avalanche", input="only_one_line"), engine)
    assert exc.value.status_code == 400

    # sm2_curve unsupported curve
    with pytest.raises(ApiError) as exc:
        service.run_experiment(ExperimentRequest(experiment="sm2_curve", input="secp256k1"), engine)
    assert exc.value.status_code == 400


def test_ml_kem_and_dsa_when_available():
    from app.crypto.types import ProviderStatus

    engine = MockCryptoEngine(
        status=ProviderStatus(
            state="online",
            version="1.0.0",
            provider="test_pqc",
            capabilities={"ml_kem": True, "ml_dsa": True},
        )
    )
    service = ExperimentService()

    kem_res = service.run_experiment(ExperimentRequest(experiment="ml_kem", input="default"), engine)
    assert kem_res.passed is True
    assert kem_res.redacted_values["algorithm"] == "ML-KEM-768"

    dsa_res = service.run_experiment(ExperimentRequest(experiment="ml_dsa", input="default"), engine)
    assert dsa_res.passed is True
    assert dsa_res.redacted_values["algorithm"] == "ML-DSA-65"

