import base64
import binascii
import secrets
import struct
from dataclasses import dataclass
from typing import Callable

from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.crypto.types import GCM_NONCE_SIZE, GCM_TAG_SIZE, SM2_PUBLIC_KEY_SIZE, SM4_KEY_SIZE


MAX_BACKUP_SIZE = 256 * 1024
BACKUP_SALT_SIZE = 32
BACKUP_KDF_INFO = b"keyring-backup-kek-v1"
_PEM_BEGIN = b"-----BEGIN CRYPTOCAMPUS KEYRING BACKUP-----"
_PEM_END = b"-----END CRYPTOCAMPUS KEYRING BACKUP-----"
_OUTER_MAGIC = b"CCKB"
_PAYLOAD_MAGIC = b"KRB1"
_VERSION = 1
_ROLES = frozenset({"student", "admin", "teacher"})


class KeyringBackupError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class BackupMaterial:
    user_id: str
    role: str
    certificate_serial: str
    public_key: bytes
    salt_k: bytes
    encrypted_private_key: bytes


class KeyringBackupCodec:
    def __init__(
        self,
        crypto_engine: CryptoEngine,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self.crypto_engine = crypto_engine
        self.random_bytes = random_bytes

    def export(self, material: BackupMaterial, password: bytes) -> bytes:
        self._validate_material(material)
        self._validate_password(password)
        backup_salt = self._random_salt()
        key_encryption_key: bytes | None = None
        payload: bytes | None = None
        try:
            key_encryption_key = self.crypto_engine.hkdf_sm3(
                password, backup_salt, BACKUP_KDF_INFO, SM4_KEY_SIZE
            )
            payload = self._pack_material(material)
            encrypted = self.crypto_engine.sm4_gcm_encrypt(
                key_encryption_key, payload, self._aad(material.user_id)
            )
            container = (
                _OUTER_MAGIC
                + bytes((_VERSION, BACKUP_SALT_SIZE))
                + backup_salt
                + encrypted.nonce
                + encrypted.tag
                + encrypted.ciphertext
            )
            return self._to_pem(container)
        except CryptoBridgeError:
            raise
        except Exception:
            raise KeyringBackupError("backup_invalid") from None
        finally:
            key_encryption_key = None
            payload = None

    def import_backup(
        self, backup: bytes, password: bytes, expected_user_id: str
    ) -> BackupMaterial:
        self._validate_password(password)
        if not isinstance(expected_user_id, str) or not expected_user_id:
            raise KeyringBackupError("backup_invalid")
        backup_salt: bytes | None = None
        key_encryption_key: bytes | None = None
        payload: bytes | None = None
        try:
            backup_salt, nonce, tag, ciphertext = self._from_pem(backup)
            key_encryption_key = self.crypto_engine.hkdf_sm3(
                password, backup_salt, BACKUP_KDF_INFO, SM4_KEY_SIZE
            )
            payload = self.crypto_engine.sm4_gcm_decrypt(
                key_encryption_key, nonce, ciphertext, self._aad(expected_user_id), tag
            )
            material = self._unpack_material(payload)
            self._validate_material(material)
            if material.user_id != expected_user_id:
                raise KeyringBackupError("backup_invalid")
            return material
        except CryptoBridgeError:
            raise KeyringBackupError("backup_invalid") from None
        except KeyringBackupError:
            raise
        except Exception:
            raise KeyringBackupError("backup_invalid") from None
        finally:
            backup_salt = None
            key_encryption_key = None
            payload = None

    @staticmethod
    def _aad(user_id: str) -> bytes:
        return b"keyring-backup-v1|" + user_id.encode("ascii")

    def _random_salt(self) -> bytes:
        salt = self.random_bytes(BACKUP_SALT_SIZE)
        if not isinstance(salt, bytes) or len(salt) != BACKUP_SALT_SIZE:
            raise KeyringBackupError("backup_invalid")
        return salt

    @staticmethod
    def _validate_password(password: bytes) -> None:
        if not isinstance(password, bytes) or not 1 <= len(password) <= 512:
            raise KeyringBackupError("backup_invalid")

    @staticmethod
    def _validate_material(material: BackupMaterial) -> None:
        if (
            not isinstance(material.user_id, str)
            or not material.user_id
            or not isinstance(material.role, str)
            or material.role not in _ROLES
            or not isinstance(material.certificate_serial, str)
            or not 1 <= len(material.certificate_serial) <= 128
            or not isinstance(material.public_key, bytes)
            or len(material.public_key) != SM2_PUBLIC_KEY_SIZE
            or not isinstance(material.salt_k, bytes)
            or not 16 <= len(material.salt_k) <= 64
            or not isinstance(material.encrypted_private_key, bytes)
            or not material.encrypted_private_key
        ):
            raise KeyringBackupError("backup_invalid")

    @staticmethod
    def _pack_material(material: BackupMaterial) -> bytes:
        values = (
            material.user_id.encode("ascii"),
            material.role.encode("ascii"),
            material.certificate_serial.encode("ascii"),
            material.public_key,
            material.salt_k,
            material.encrypted_private_key,
        )
        if any(len(value) > 65535 for value in values):
            raise KeyringBackupError("backup_invalid")
        return _PAYLOAD_MAGIC + b"".join(
            struct.pack(">H", len(value)) + value for value in values
        )

    @classmethod
    def _unpack_material(cls, payload: bytes) -> BackupMaterial:
        if not isinstance(payload, bytes) or not payload.startswith(_PAYLOAD_MAGIC):
            raise KeyringBackupError("backup_invalid")
        offset = len(_PAYLOAD_MAGIC)
        values: list[bytes] = []
        for _ in range(6):
            if offset + 2 > len(payload):
                raise KeyringBackupError("backup_invalid")
            length = struct.unpack(">H", payload[offset : offset + 2])[0]
            offset += 2
            if length == 0 or offset + length > len(payload):
                raise KeyringBackupError("backup_invalid")
            values.append(payload[offset : offset + length])
            offset += length
        if offset != len(payload):
            raise KeyringBackupError("backup_invalid")
        try:
            return BackupMaterial(
                user_id=values[0].decode("ascii"),
                role=values[1].decode("ascii"),
                certificate_serial=values[2].decode("ascii"),
                public_key=values[3],
                salt_k=values[4],
                encrypted_private_key=values[5],
            )
        except UnicodeDecodeError:
            raise KeyringBackupError("backup_invalid") from None

    @staticmethod
    def _to_pem(container: bytes) -> bytes:
        encoded = base64.b64encode(container)
        lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
        pem = b"\n".join((_PEM_BEGIN, *lines, _PEM_END, b""))
        if len(pem) > MAX_BACKUP_SIZE:
            raise KeyringBackupError("backup_invalid")
        return pem

    @staticmethod
    def _from_pem(backup: bytes) -> tuple[bytes, bytes, bytes, bytes]:
        if not isinstance(backup, bytes) or not backup or len(backup) > MAX_BACKUP_SIZE:
            raise KeyringBackupError("backup_invalid")
        lines = backup.splitlines()
        if len(lines) < 3 or lines[0] != _PEM_BEGIN or lines[-1] != _PEM_END:
            raise KeyringBackupError("backup_invalid")
        try:
            container = base64.b64decode(b"".join(lines[1:-1]), validate=True)
        except (ValueError, binascii.Error):
            raise KeyringBackupError("backup_invalid") from None
        minimum_size = 4 + 2 + BACKUP_SALT_SIZE + GCM_NONCE_SIZE + GCM_TAG_SIZE + 1
        if len(container) < minimum_size or container[:4] != _OUTER_MAGIC:
            raise KeyringBackupError("backup_invalid")
        if container[4] != _VERSION or container[5] != BACKUP_SALT_SIZE:
            raise KeyringBackupError("backup_invalid")
        offset = 6
        backup_salt = container[offset : offset + BACKUP_SALT_SIZE]
        offset += BACKUP_SALT_SIZE
        nonce = container[offset : offset + GCM_NONCE_SIZE]
        offset += GCM_NONCE_SIZE
        tag = container[offset : offset + GCM_TAG_SIZE]
        offset += GCM_TAG_SIZE
        ciphertext = container[offset:]
        if not ciphertext:
            raise KeyringBackupError("backup_invalid")
        return backup_salt, nonce, tag, ciphertext
