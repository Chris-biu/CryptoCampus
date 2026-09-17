from dataclasses import FrozenInstanceError

import pytest

from app.crypto.types import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    SM2_PRIVATE_KEY_SIZE,
    SM2_PUBLIC_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
    SM3_DIGEST_SIZE,
    SM4_KEY_SIZE,
    ProviderStatus,
    Sm2KeyPair,
    Sm4GcmCiphertext,
)
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError


def test_crypto_contract_lengths_are_exposed() -> None:
    assert SM3_DIGEST_SIZE == 32
    assert SM4_KEY_SIZE == 16
    assert GCM_NONCE_SIZE == 12
    assert GCM_TAG_SIZE == 16
    assert SM2_PRIVATE_KEY_SIZE == 32
    assert SM2_PUBLIC_KEY_SIZE == 65
    assert SM2_SIGNATURE_SIZE == 64


def test_crypto_result_types_are_immutable() -> None:
    status = ProviderStatus(
        state="offline",
        version="unknown",
        provider="unavailable",
        capabilities={},
    )
    ciphertext = Sm4GcmCiphertext(
        ciphertext=b"", nonce=bytes(GCM_NONCE_SIZE), tag=bytes(GCM_TAG_SIZE)
    )
    key_pair = Sm2KeyPair(
        private_key=bytes(SM2_PRIVATE_KEY_SIZE),
        public_key=bytes(SM2_PUBLIC_KEY_SIZE),
    )

    with pytest.raises(FrozenInstanceError):
        status.state = "online"  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        ciphertext.tag = b""  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        key_pair.public_key = b""  # type: ignore[misc]


@pytest.mark.parametrize(
    "result",
    [
        lambda: Sm4GcmCiphertext(
            ciphertext=b"", nonce=b"", tag=bytes(GCM_TAG_SIZE)
        ),
        lambda: Sm4GcmCiphertext(
            ciphertext=b"", nonce=bytes(GCM_NONCE_SIZE), tag=b""
        ),
        lambda: Sm2KeyPair(
            private_key=b"", public_key=bytes(SM2_PUBLIC_KEY_SIZE)
        ),
        lambda: Sm2KeyPair(
            private_key=bytes(SM2_PRIVATE_KEY_SIZE), public_key=b""
        ),
    ],
)
def test_crypto_result_types_reject_invalid_fixed_lengths(result) -> None:
    with pytest.raises(CryptoBridgeError) as raised:
        result()

    assert raised.value.code is BridgeErrorCode.INVALID_ARGUMENT
