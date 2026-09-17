import base64
import hashlib
import hmac

import pytest

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import Sm4GcmCiphertext
from app.services.keyring_backup import BackupMaterial, KeyringBackupCodec, KeyringBackupError


class AuthenticatedTestEngine:
    """Deterministic test double for container integrity; not a crypto KAT."""

    def hkdf_sm3(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        return hmac.new(salt, ikm + info, hashlib.sha256).digest()[:length]

    def sm4_gcm_encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> Sm4GcmCiphertext:
        nonce = b"N" * 12
        stream = hashlib.sha256(key + nonce).digest()
        ciphertext = bytes(value ^ stream[index % len(stream)] for index, value in enumerate(plaintext))
        tag = hmac.new(key, nonce + aad + ciphertext, hashlib.sha256).digest()[:16]
        return Sm4GcmCiphertext(ciphertext=ciphertext, nonce=nonce, tag=tag)

    def sm4_gcm_decrypt(
        self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes
    ) -> bytes:
        expected = hmac.new(key, nonce + aad + ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(expected, tag):
            raise CryptoBridgeError(BridgeErrorCode.INTEGRITY_FAILED)
        stream = hashlib.sha256(key + nonce).digest()
        return bytes(value ^ stream[index % len(stream)] for index, value in enumerate(ciphertext))


def material() -> BackupMaterial:
    return BackupMaterial(
        user_id="a6e8a84c-2278-47fe-9f26-e5d9c5d740eb",
        role="student",
        certificate_serial="identity-cert",
        public_key=b"\x04" + b"p" * 64,
        salt_k=b"k" * 32,
        encrypted_private_key=b"encrypted-private-key",
    )


def mutate_container(pem: bytes, offset: int) -> bytes:
    lines = pem.splitlines()
    container = bytearray(base64.b64decode(b"".join(lines[1:-1]), validate=True))
    container[offset] ^= 0x01
    encoded = base64.b64encode(container)
    body = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return b"\n".join((lines[0], *body, lines[-1], b""))


@pytest.mark.parametrize(
    ("field", "offset"),
    [
        ("backup_salt", 6),
        ("gcm_nonce", 6 + 32),
        ("gcm_tag", 6 + 32 + 12),
        ("ciphertext", 6 + 32 + 12 + 16),
    ],
)
def test_single_byte_container_tamper_fails_closed_without_payload(field, offset) -> None:
    engine = AuthenticatedTestEngine()
    codec = KeyringBackupCodec(engine, random_bytes=lambda _: b"S" * 32)
    password = b"CorrectPassword1"
    original = codec.export(material(), password)

    with pytest.raises(KeyringBackupError) as raised:
        codec.import_backup(mutate_container(original, offset), password, material().user_id)

    assert raised.value.code == "backup_invalid", field
    assert password.decode() not in str(raised.value)
    assert material().encrypted_private_key.decode() not in str(raised.value)


def test_backup_cannot_be_replayed_for_another_user_context() -> None:
    engine = AuthenticatedTestEngine()
    codec = KeyringBackupCodec(engine, random_bytes=lambda _: b"S" * 32)
    original = codec.export(material(), b"CorrectPassword1")

    with pytest.raises(KeyringBackupError):
        codec.import_backup(
            original,
            b"CorrectPassword1",
            "00000000-0000-4000-8000-000000000002",
        )
