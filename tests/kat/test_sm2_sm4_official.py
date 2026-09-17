from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.hitls import HitlsCryptoEngine


VECTOR_ROOT = Path(__file__).with_name("vectors")


def _load(name: str) -> dict[str, object]:
    return json.loads((VECTOR_ROOT / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def engine() -> HitlsCryptoEngine:
    return HitlsCryptoEngine()


def test_openhitls_sm2_gbt32918_known_signature_and_tamper_rejection(
    engine: HitlsCryptoEngine,
) -> None:
    payload = _load("openhitls-sm2-verify.json")
    assert payload["algorithm"] == "SM2-VERIFY"
    vector = payload["cases"][0]  # type: ignore[index]
    public_key = bytes.fromhex(vector["public_key_hex"])  # type: ignore[index]
    digest = bytes.fromhex(vector["digest_hex"])  # type: ignore[index]
    signature = bytes.fromhex(vector["signature_raw_hex"])  # type: ignore[index]

    assert engine.sm2_verify(public_key, digest, signature) is True

    tampered_digest = digest[:-1] + bytes([digest[-1] ^ 1])
    tampered_signature = signature[:-1] + bytes([signature[-1] ^ 1])
    assert engine.sm2_verify(public_key, tampered_digest, signature) is False
    assert engine.sm2_verify(public_key, digest, tampered_signature) is False

    other_public_key = engine.sm2_generate_keypair().public_key
    assert engine.sm2_verify(other_public_key, digest, signature) is False


def test_rfc8998_sm4_gcm_known_answer_and_tamper_rejection(
    engine: HitlsCryptoEngine,
) -> None:
    payload = _load("rfc8998-sm4-gcm.json")
    assert payload["algorithm"] == "SM4-GCM"
    vector = payload["cases"][0]  # type: ignore[index]
    key = bytes.fromhex(vector["key_hex"])  # type: ignore[index]
    nonce = bytes.fromhex(vector["nonce_hex"])  # type: ignore[index]
    aad = bytes.fromhex(vector["aad_hex"])  # type: ignore[index]
    plaintext = bytes.fromhex(vector["plaintext_hex"])  # type: ignore[index]
    ciphertext = bytes.fromhex(vector["ciphertext_hex"])  # type: ignore[index]
    tag = bytes.fromhex(vector["tag_hex"])  # type: ignore[index]

    assert engine.sm4_gcm_decrypt(key, nonce, ciphertext, aad, tag) == plaintext

    for changed_ciphertext, changed_aad, changed_tag in (
        (ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), aad, tag),
        (ciphertext, aad[:-1] + bytes([aad[-1] ^ 1]), tag),
        (ciphertext, aad, tag[:-1] + bytes([tag[-1] ^ 1])),
    ):
        with pytest.raises(CryptoBridgeError) as caught:
            engine.sm4_gcm_decrypt(
                key,
                nonce,
                changed_ciphertext,
                changed_aad,
                changed_tag,
            )
        assert caught.value.code == BridgeErrorCode.INTEGRITY_FAILED
