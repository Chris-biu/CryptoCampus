from __future__ import annotations

from dataclasses import replace

import pytest

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.hitls import HitlsCryptoEngine


@pytest.fixture(scope="module")
def engine() -> HitlsCryptoEngine:
    return HitlsCryptoEngine()


def test_real_adapter_satisfies_engine_contract(engine: HitlsCryptoEngine) -> None:
    assert isinstance(engine, CryptoEngine)
    status = engine.provider_status()
    assert status.state == "online"
    assert status.provider == "openHiTLS"
    assert status.capabilities["sm3"] is True
    assert status.capabilities["sm4_gcm"] is True
    assert status.capabilities["sm2"] is True
    assert status.capabilities["pqc"] is False


def test_real_adapter_uses_official_sm3_answer(engine: HitlsCryptoEngine) -> None:
    assert engine.sm3_digest(b"abc").hex() == (
        "66c7f0f462eeedd9d1f2d46bdc10e4e2"
        "4167c4875cf2f7a2297da02b8f4ba8e0"
    )


def test_real_sm4_gcm_roundtrip_and_tamper_rejection(engine: HitlsCryptoEngine) -> None:
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    plaintext = b"CryptoCampus real openHiTLS adapter"
    aad = b"kat:sm4-gcm"
    encrypted = engine.sm4_gcm_encrypt(key, plaintext, aad)

    assert engine.sm4_gcm_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, aad, encrypted.tag
    ) == plaintext

    tampered_tag = encrypted.tag[:-1] + bytes([encrypted.tag[-1] ^ 1])
    with pytest.raises(CryptoBridgeError):
        engine.sm4_gcm_decrypt(
            key, encrypted.nonce, encrypted.ciphertext, aad, tampered_tag
        )


def test_real_sm2_sign_verify_and_ecdh(engine: HitlsCryptoEngine) -> None:
    alice = engine.sm2_generate_keypair()
    bob = engine.sm2_generate_keypair()
    digest = engine.sm3_digest(b"CryptoCampus SM2 adapter")
    signature = engine.sm2_sign(alice.private_key, digest)

    assert engine.sm2_verify(alice.public_key, digest, signature) is True
    tampered_signature = signature[:-1] + bytes([signature[-1] ^ 1])
    assert engine.sm2_verify(alice.public_key, digest, tampered_signature) is False
    assert engine.sm2_ecdh(alice.private_key, bob.public_key) == engine.sm2_ecdh(
        bob.private_key, alice.public_key
    )


def test_real_classic_envelope_roundtrip_and_tamper_rejection(
    engine: HitlsCryptoEngine,
) -> None:
    recipient = engine.sm2_generate_keypair()
    sender = engine.sm2_generate_keypair()
    plaintext = b"CryptoCampus real classic envelope"
    artifact = engine.envelope_seal(
        plaintext=plaintext,
        recipient_sm2_public_key=recipient.public_key,
        pqc_mode=False,
        recipient_mlkem_public_key=None,
        sender_private_key=sender.private_key,
        sender_certificate_der=b"\x30\x03\x02\x01\x01",
        access_factor=None,
    )

    assert artifact.ciphertext
    assert artifact.enc_key_sm2
    assert artifact.sender_certificate == b"\x30\x03\x02\x01\x01"
    assert engine.envelope_open(
        envelope=artifact,
        recipient_sm2_private_key=recipient.private_key,
        pqc_mode=False,
        recipient_mlkem_private_key=None,
        access_factor=None,
    ) == plaintext

    tampered = replace(
        artifact,
        tag=artifact.tag[:-1] + bytes([artifact.tag[-1] ^ 1]),
    )
    with pytest.raises(CryptoBridgeError):
        engine.envelope_open(
            envelope=tampered,
            recipient_sm2_private_key=recipient.private_key,
            pqc_mode=False,
            recipient_mlkem_private_key=None,
            access_factor=None,
        )

    wrong_recipient = engine.sm2_generate_keypair()
    with pytest.raises(CryptoBridgeError):
        engine.envelope_open(
            envelope=artifact,
            recipient_sm2_private_key=wrong_recipient.private_key,
            pqc_mode=False,
            recipient_mlkem_private_key=None,
            access_factor=None,
        )


def test_unimplemented_pqc_reload_fails_closed(engine: HitlsCryptoEngine) -> None:
    with pytest.raises(CryptoBridgeError) as caught:
        engine.reload_pqc_provider()
    assert caught.value.code == BridgeErrorCode.UNSUPPORTED
