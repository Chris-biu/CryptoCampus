import pytest

from app.crypto.dependencies import get_crypto_engine
from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.unavailable import UnavailableCryptoEngine


def test_default_crypto_engine_is_unavailable_and_offline() -> None:
    engine = get_crypto_engine()

    assert isinstance(engine, CryptoEngine)
    assert isinstance(engine, UnavailableCryptoEngine)
    assert not isinstance(engine, MockCryptoEngine)
    assert engine.provider_status().state == "offline"
    assert engine.provider_status().version == "unknown"
    assert engine.provider_status().provider == "unavailable"
    assert engine.provider_status().capabilities == {}


@pytest.mark.parametrize(
    "operation",
    [
        lambda engine: engine.sm3_digest(b""),
        lambda engine: engine.sm3_hash_password(b"", b""),
        lambda engine: engine.constant_time_equal(b"", b""),
        lambda engine: engine.hkdf_sm3(b"", b"", b"", 0),
        lambda engine: engine.sm4_gcm_encrypt(b"", b""),
        lambda engine: engine.sm4_gcm_decrypt(b"", b"", b"", b"", b""),
        lambda engine: engine.sm2_generate_keypair(),
        lambda engine: engine.sm2_sign(b"", b""),
        lambda engine: engine.sm2_verify(b"", b"", b""),
        lambda engine: engine.sm2_ecdh(b"", b""),
        lambda engine: engine.csr_create(b"", b"", "user", "student"),
        lambda engine: engine.cert_sign(b"", b"", b"", 1, 2, ("digitalSignature",)),
        lambda engine: engine.cert_chain_verify(b"", (), b"", 1, ("digitalSignature",)),
        lambda engine: engine.crl_create((), b"", b"", 1, 2),
        lambda engine: engine.crl_verify(b"", b"", 1),
        lambda engine: engine.reload_pqc_provider(),
    ],
)
def test_unavailable_crypto_engine_rejects_all_crypto_operations(operation) -> None:
    with pytest.raises(CryptoBridgeError) as raised:
        operation(UnavailableCryptoEngine())

    assert raised.value.code is BridgeErrorCode.PROVIDER_UNAVAILABLE
