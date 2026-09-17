import pytest

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    MAX_DER_CERTIFICATE_SIZE,
    SM2_PRIVATE_KEY_SIZE,
    SM2_PUBLIC_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
    EnvelopeArtifact,
)
from app.crypto.unavailable import UnavailableCryptoEngine

VALID_NONCE = b"\x01" * GCM_NONCE_SIZE
VALID_TAG = b"\x02" * GCM_TAG_SIZE
VALID_SM2_ENC = b"\x03" * 96
VALID_MLKEM_ENC = b"\x04" * 1088
VALID_SIG = b"\x05" * SM2_SIGNATURE_SIZE
VALID_CERT = b"\x30\x82\x01\x00" + b"\x06" * 100
VALID_SM2_PUB = b"\x04" + b"\x07" * (SM2_PUBLIC_KEY_SIZE - 1)
VALID_MLKEM_PUB = b"\x08" * 1184
VALID_SM2_PRIV = b"\x09" * SM2_PRIVATE_KEY_SIZE


def test_envelope_artifact_validates_field_lengths() -> None:
    artifact = EnvelopeArtifact(
        ciphertext=b"encrypted payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=None,
        sender_signature=VALID_SIG,
        sender_certificate=VALID_CERT,
    )
    assert artifact.ciphertext == b"encrypted payload"
    assert artifact.nonce == VALID_NONCE
    assert artifact.tag == VALID_TAG
    assert artifact.enc_key_sm2 == VALID_SM2_ENC
    assert artifact.enc_key_mlkem is None
    assert artifact.sender_signature == VALID_SIG
    assert artifact.sender_certificate == VALID_CERT


def test_envelope_artifact_rejects_invalid_lengths() -> None:
    # invalid nonce length
    with pytest.raises(CryptoBridgeError) as exc:
        EnvelopeArtifact(
            ciphertext=b"data",
            nonce=b"\x01" * 11,
            tag=VALID_TAG,
            enc_key_sm2=VALID_SM2_ENC,
            enc_key_mlkem=None,
            sender_signature=VALID_SIG,
            sender_certificate=VALID_CERT,
        )
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # invalid tag length
    with pytest.raises(CryptoBridgeError) as exc:
        EnvelopeArtifact(
            ciphertext=b"data",
            nonce=VALID_NONCE,
            tag=b"\x02" * 15,
            enc_key_sm2=VALID_SM2_ENC,
            enc_key_mlkem=None,
            sender_signature=VALID_SIG,
            sender_certificate=VALID_CERT,
        )
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # invalid mlkem length
    with pytest.raises(CryptoBridgeError) as exc:
        EnvelopeArtifact(
            ciphertext=b"data",
            nonce=VALID_NONCE,
            tag=VALID_TAG,
            enc_key_sm2=VALID_SM2_ENC,
            enc_key_mlkem=b"\x04" * 1087,
            sender_signature=VALID_SIG,
            sender_certificate=VALID_CERT,
        )
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # invalid signature length
    with pytest.raises(CryptoBridgeError) as exc:
        EnvelopeArtifact(
            ciphertext=b"data",
            nonce=VALID_NONCE,
            tag=VALID_TAG,
            enc_key_sm2=VALID_SM2_ENC,
            enc_key_mlkem=None,
            sender_signature=b"\x05" * 63,
            sender_certificate=VALID_CERT,
        )
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # oversized certificate
    with pytest.raises(CryptoBridgeError) as exc:
        EnvelopeArtifact(
            ciphertext=b"data",
            nonce=VALID_NONCE,
            tag=VALID_TAG,
            enc_key_sm2=VALID_SM2_ENC,
            enc_key_mlkem=None,
            sender_signature=VALID_SIG,
            sender_certificate=b"\x06" * (MAX_DER_CERTIFICATE_SIZE + 1),
        )
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT


def test_unavailable_crypto_engine_envelope_seal_raises_unavailable() -> None:
    engine = UnavailableCryptoEngine()
    assert isinstance(engine, CryptoEngine)
    with pytest.raises(CryptoBridgeError) as exc:
        engine.envelope_seal(
            plaintext=b"hello",
            recipient_sm2_public_key=VALID_SM2_PUB,
            pqc_mode=False,
            recipient_mlkem_public_key=None,
            sender_private_key=VALID_SM2_PRIV,
            sender_certificate_der=VALID_CERT,
            access_factor=None,
        )
    assert exc.value.code == BridgeErrorCode.PROVIDER_UNAVAILABLE


def test_mock_crypto_engine_envelope_seal_records_and_returns_artifact() -> None:
    engine = MockCryptoEngine()
    assert isinstance(engine, CryptoEngine)
    expected_artifact = EnvelopeArtifact(
        ciphertext=b"ciphertext_bytes",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=VALID_MLKEM_ENC,
        sender_signature=VALID_SIG,
        sender_certificate=VALID_CERT,
    )
    engine.set_result("envelope_seal", expected_artifact)

    result = engine.envelope_seal(
        plaintext=b"secret payload",
        recipient_sm2_public_key=VALID_SM2_PUB,
        pqc_mode=True,
        recipient_mlkem_public_key=VALID_MLKEM_PUB,
        sender_private_key=VALID_SM2_PRIV,
        sender_certificate_der=VALID_CERT,
        access_factor=b"\xaa" * 32,
    )
    assert result == expected_artifact
    assert len(engine.calls) == 1
    op, lengths = engine.calls[0]
    assert op == "envelope_seal"
    assert lengths["plaintext"] == len(b"secret payload")
    assert lengths["recipient_sm2_public_key"] == SM2_PUBLIC_KEY_SIZE
    assert lengths["recipient_mlkem_public_key"] == 1184
    assert lengths["sender_private_key"] == SM2_PRIVATE_KEY_SIZE
    assert lengths["access_factor"] == 32
