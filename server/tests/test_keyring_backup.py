import pytest

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import Sm4GcmCiphertext
from app.services.keyring_backup import BackupMaterial, KeyringBackupCodec, KeyringBackupError


def test_tampered_backup_is_rejected_without_exposing_payload() -> None:
    engine = MockCryptoEngine()
    engine.set_result("hkdf_sm3", b"b" * 16)
    engine.set_result(
        "sm4_gcm_encrypt",
        Sm4GcmCiphertext(ciphertext=b"encrypted-backup", nonce=b"n" * 12, tag=b"t" * 16),
    )
    codec = KeyringBackupCodec(engine, random_bytes=lambda _: b"s" * 32)
    material = BackupMaterial(
        user_id="a6e8a84c-2278-47fe-9f26-e5d9c5d740eb",
        role="student",
        certificate_serial="identity-cert",
        public_key=b"\x04" + b"p" * 64,
        salt_k=b"k" * 32,
        encrypted_private_key=b"v1" + b"n" * 12 + b"ciphertext" + b"t" * 16,
    )

    pem = codec.export(material, b"CorrectPassword1")
    engine.set_error("sm4_gcm_decrypt", CryptoBridgeError(BridgeErrorCode.INTEGRITY_FAILED))

    with pytest.raises(KeyringBackupError) as raised:
        codec.import_backup(
            pem[:-8] + b"AAAAAAAA", b"CorrectPassword1", material.user_id
        )

    assert raised.value.code == "backup_invalid"
    assert b"CorrectPassword1" not in str(raised.value).encode()


def test_backup_decryption_binds_the_container_to_the_current_user() -> None:
    engine = MockCryptoEngine()
    engine.set_result("hkdf_sm3", b"b" * 16)
    engine.set_result(
        "sm4_gcm_encrypt",
        Sm4GcmCiphertext(ciphertext=b"encrypted-backup", nonce=b"n" * 12, tag=b"t" * 16),
    )
    user_id = "a6e8a84c-2278-47fe-9f26-e5d9c5d740eb"
    material = BackupMaterial(
        user_id=user_id,
        role="student",
        certificate_serial="identity-cert",
        public_key=b"\x04" + b"p" * 64,
        salt_k=b"k" * 32,
        encrypted_private_key=b"v1" + b"n" * 12 + b"ciphertext" + b"t" * 16,
    )
    codec = KeyringBackupCodec(engine, random_bytes=lambda _: b"s" * 32)
    pem = codec.export(material, b"CorrectPassword1")
    engine.set_error("sm4_gcm_decrypt", CryptoBridgeError(BridgeErrorCode.INTEGRITY_FAILED))

    with pytest.raises(KeyringBackupError):
        codec.import_backup(pem, b"CorrectPassword1", user_id)

    decrypt_call = [call for call in engine.calls if call[0] == "sm4_gcm_decrypt"][0]
    assert decrypt_call[1]["aad"] == len(b"keyring-backup-v1|" + user_id.encode("ascii"))
