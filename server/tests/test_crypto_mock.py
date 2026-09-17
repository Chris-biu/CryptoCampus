import pytest

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import CrlArtifact, ProviderStatus, SignedCertificate


def test_mock_returns_explicitly_configured_value_and_status() -> None:
    status = ProviderStatus(
        state="degraded",
        version="test",
        provider="mock",
        capabilities={"sm3": False},
    )
    engine = MockCryptoEngine(status=status)
    engine.set_result("sm3_digest", b"")

    assert isinstance(engine, CryptoEngine)
    assert engine.provider_status() is status
    assert engine.sm3_digest(b"\x00\x01") == b""
    assert engine.calls == (("sm3_digest", {"message": 2}),)


def test_mock_raises_explicitly_configured_error() -> None:
    engine = MockCryptoEngine()
    configured_error = CryptoBridgeError(BridgeErrorCode.CERT_INVALID)
    engine.set_error("sm2_verify", configured_error)

    with pytest.raises(CryptoBridgeError) as raised:
        engine.sm2_verify(bytes(65), bytes(32), bytes(64))

    assert raised.value is configured_error


def test_mock_rejects_unconfigured_operation() -> None:
    engine = MockCryptoEngine()

    with pytest.raises(CryptoBridgeError) as raised:
        engine.sm2_generate_keypair()

    assert raised.value.code is BridgeErrorCode.UNSUPPORTED


def test_mock_call_history_contains_lengths_without_byte_values() -> None:
    engine = MockCryptoEngine()
    engine.set_result("sm4_gcm_decrypt", b"")
    engine.sm4_gcm_decrypt(
        bytes(16), bytes(12), b"\x03\x04\x05", b"", bytes(16)
    )

    calls = engine.calls

    assert calls == (
        (
            "sm4_gcm_decrypt",
            {"key": 16, "nonce": 12, "ciphertext": 3, "aad": 0, "tag": 16},
        ),
    )
    assert all(isinstance(length, int) for _, values in calls for length in values.values())


def test_mock_rejects_invalid_fixed_input_lengths() -> None:
    engine = MockCryptoEngine()
    engine.set_result("sm2_sign", b"")

    with pytest.raises(CryptoBridgeError) as raised:
        engine.sm2_sign(b"", bytes(32))

    assert raised.value.code is BridgeErrorCode.INVALID_ARGUMENT


def test_mock_records_only_lengths_for_certificate_operations() -> None:
    engine = MockCryptoEngine()
    engine.set_result("csr_create", b"csr")
    engine.set_result(
        "cert_sign",
        SignedCertificate(der=b"certificate", serial="01", not_before=1, not_after=2),
    )
    engine.set_result("cert_chain_verify", True)
    engine.set_result("crl_create", CrlArtifact(der=b"crl", this_update=1, next_update=2))
    engine.set_result("crl_verify", False)

    assert engine.csr_create(
        b"k" * 32,
        b"\x04" + b"p" * 64,
        "00000000-0000-0000-0000-000000000001",
        "student",
    ) == b"csr"
    assert engine.cert_sign(b"csr", b"ca", b"k" * 32, 1, 2, ("digitalSignature",)).serial == "01"
    assert engine.cert_chain_verify(b"leaf", (b"intermediate",), b"root", 1, ("digitalSignature",))
    assert engine.crl_create(("01",), b"ca", b"k" * 32, 1, 2).der == b"crl"
    assert not engine.crl_verify(b"certificate", b"crl", 1)

    assert engine.calls[-5:] == (
        ("csr_create", {"private_key": 32, "public_key": 65, "common_name": 36, "role": 7}),
        ("cert_sign", {"csr_der": 3, "ca_certificate_der": 2, "ca_private_key": 32, "key_usage": 1}),
        ("cert_chain_verify", {"leaf_certificate_der": 4, "certificate_chain_der": 1, "trust_root_der": 4, "required_key_usage": 1}),
        ("crl_create", {"revoked_serials": 1, "ca_certificate_der": 2, "ca_private_key": 32}),
        ("crl_verify", {"certificate_der": 11, "crl_der": 3}),
    )


def test_mock_rejects_invalid_certificate_operation_inputs() -> None:
    engine = MockCryptoEngine()
    engine.set_result("csr_create", b"csr")

    with pytest.raises(CryptoBridgeError) as raised:
        engine.csr_create(b"short", b"\x04" + b"p" * 64, "user", "student")

    assert raised.value.code is BridgeErrorCode.INVALID_ARGUMENT


def test_mock_reload_pqc_provider_records_call_and_returns_status() -> None:
    engine = MockCryptoEngine()
    assert isinstance(engine, CryptoEngine)
    assert hasattr(engine, "reload_pqc_provider")

    status = engine.reload_pqc_provider()
    assert status.state == "online"
    assert engine.calls == (("reload_pqc_provider", {}),)

    new_status = ProviderStatus(
        state="online",
        version="pqc-v2",
        provider="mock-pqc",
        capabilities={"ml_kem_768": True, "ml_dsa_65": True},
    )
    engine.set_result("reload_pqc_provider", new_status)
    assert engine.reload_pqc_provider() == new_status

    engine.set_error("reload_pqc_provider", CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))
    with pytest.raises(CryptoBridgeError) as exc_info:
        engine.reload_pqc_provider()
    assert exc_info.value.code == BridgeErrorCode.PROVIDER_UNAVAILABLE
