from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import secrets
from threading import Lock
from typing import Iterator

from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import GCM_NONCE_SIZE, GCM_TAG_SIZE, SM2_PRIVATE_KEY_SIZE, SM4_KEY_SIZE
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.pki.errors import PkiError
from app.pki.service import PlatformCAService
from app.schemas.keyring import KeyringItem, KeyringSummary
from app.security.key_cache import PrivateKeyUnlockCacheProtocol
from app.services.keyring_backup import BackupMaterial, KeyringBackupCodec, KeyringBackupError


class KeyringError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RotationIdempotencyStore:
    def __init__(self, maximum_entries: int = 2048) -> None:
        self._maximum_entries = maximum_entries
        self._completed: set[tuple[str, str]] = set()
        self._lock = Lock()

    @contextmanager
    def reserve(self, user_id: str, idempotency_key: str) -> Iterator[None]:
        pair = (user_id, idempotency_key)
        with self._lock:
            if pair in self._completed:
                raise KeyringError("conflict")
            yield
            if len(self._completed) >= self._maximum_entries:
                self._completed.pop()
            self._completed.add(pair)


class KeyringService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        key_cache: PrivateKeyUnlockCacheProtocol,
        platform_ca: PlatformCAService | None = None,
        idempotency_store: RotationIdempotencyStore | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.key_cache = key_cache
        self.platform_ca = platform_ca
        self.idempotency_store = idempotency_store or RotationIdempotencyStore()

    def summary(self, user_id: str, now: datetime) -> KeyringSummary:
        user = self.session.get(User, user_id)
        if user is None:
            raise KeyringError("not_found")
        if not user.cert_serial:
            raise KeyringError("certificate_missing")
        certificate = self.session.get(CertificateRecord, user.cert_serial)
        if certificate is None or certificate.subject_user_id != user.id:
            raise KeyringError("certificate_missing")
        normalized_now = self._utc(now)
        certificate_status = certificate.status
        if certificate_status == "active" and self._utc(certificate.not_after) <= normalized_now:
            certificate_status = "expired"
        fingerprint = self.crypto_engine.sm3_digest(user.pubkey).hex()
        certificate_fingerprint = self.crypto_engine.sm3_digest(
            certificate.serial.encode("utf-8")
        ).hex()
        expires_at = self.key_cache.expires_at(user.id, normalized_now)
        return KeyringSummary(
            items=[
                KeyringItem(
                    kind="sm2_identity",
                    algorithm="SM2",
                    fingerprint=fingerprint,
                    status="active",
                    expires_at=None,
                ),
                KeyringItem(
                    kind="certificate",
                    algorithm="SM2-X.509",
                    fingerprint=certificate_fingerprint,
                    status=certificate_status,
                    expires_at=self._utc(certificate.not_after),
                ),
            ],
            unlocked_until=expires_at,
        )

    def rotate(
        self, user_id: str, password: str, idempotency_key: str, now: datetime
    ) -> KeyringSummary:
        if self.platform_ca is None:
            raise KeyringError("internal")
        if not isinstance(idempotency_key, str) or not 16 <= len(idempotency_key) <= 128:
            raise KeyringError("conflict")
        password_bytes = self._password_bytes(password)
        normalized_now = self._utc(now)
        key_encryption_key: bytes | None = None
        old_private_key: bytes | None = None
        new_private_key: bytes | None = None
        try:
            with self.idempotency_store.reserve(user_id, idempotency_key):
                with self._transaction():
                    user = self.session.get(User, user_id)
                    if user is None:
                        raise KeyringError("not_found")
                    old_certificate = self.session.get(CertificateRecord, user.cert_serial)
                    if (
                        old_certificate is None
                        or old_certificate.subject_user_id != user.id
                        or old_certificate.kind != "user_identity"
                        or old_certificate.status != "active"
                    ):
                        raise KeyringError("conflict")
                    self._authenticate(user, password_bytes)
                    key_encryption_key = self.crypto_engine.hkdf_sm3(
                        password_bytes, user.salt_k, b"user-kek", SM4_KEY_SIZE
                    )
                    nonce, ciphertext, tag = self._parse_encrypted_private_key(user.enc_sk)
                    old_private_key = self.crypto_engine.sm4_gcm_decrypt(
                        key_encryption_key, nonce, ciphertext, b"", tag
                    )
                    if len(old_private_key) != SM2_PRIVATE_KEY_SIZE:
                        raise KeyringError("internal")
                    self.crypto_engine.csr_create(
                        old_private_key, user.pubkey, user.id, user.role
                    )

                    key_pair = self.crypto_engine.sm2_generate_keypair()
                    new_private_key = key_pair.private_key
                    new_salt_a = secrets.token_bytes(32)
                    new_salt_k = secrets.token_bytes(32)
                    new_auth_hash = self.crypto_engine.sm3_hash_password(
                        password_bytes, new_salt_a
                    )
                    key_encryption_key = self.crypto_engine.hkdf_sm3(
                        password_bytes, new_salt_k, b"user-kek", SM4_KEY_SIZE
                    )
                    encrypted = self.crypto_engine.sm4_gcm_encrypt(
                        key_encryption_key, new_private_key
                    )
                    issued = self.platform_ca.issue_user_certificate(
                        user.id,
                        user.role,
                        new_private_key,
                        key_pair.public_key,
                        normalized_now,
                        normalized_now + timedelta(days=365),
                    )
                    old_serial = user.cert_serial
                    user.salt_a = new_salt_a
                    user.auth_hash = new_auth_hash
                    user.salt_k = new_salt_k
                    user.enc_sk = b"v1" + encrypted.nonce + encrypted.ciphertext + encrypted.tag
                    user.pubkey = key_pair.public_key
                    self.session.flush()
                    self.platform_ca.record_issued_certificate(user, issued)
                    self.platform_ca.revoke_certificate(
                        old_serial,
                        "key_rotation",
                        user.id,
                        normalized_now,
                        normalized_now + timedelta(days=7),
                    )
                    self.key_cache.delete(user.id)
                    self.session.flush()
            return self.summary(user_id, normalized_now)
        except KeyringError:
            raise
        except CryptoBridgeError as error:
            if error.code in (BridgeErrorCode.PROVIDER_UNAVAILABLE, BridgeErrorCode.UNSUPPORTED):
                raise KeyringError("unavailable") from None
            raise KeyringError("internal") from None
        except PkiError:
            raise KeyringError("internal") from None
        except Exception:
            raise KeyringError("internal") from None
        finally:
            password_bytes = None
            key_encryption_key = None
            old_private_key = None
            new_private_key = None

    def export(self, user_id: str, password: str) -> bytes:
        password_bytes = self._password_bytes(password)
        try:
            user = self.session.get(User, user_id)
            if user is None:
                raise KeyringError("not_found")
            certificate = self.session.get(CertificateRecord, user.cert_serial)
            if (
                certificate is None
                or certificate.subject_user_id != user.id
                or certificate.status != "active"
            ):
                raise KeyringError("conflict")
            self._authenticate(user, password_bytes)
            return KeyringBackupCodec(self.crypto_engine).export(
                BackupMaterial(
                    user_id=user.id,
                    role=user.role,
                    certificate_serial=user.cert_serial,
                    public_key=user.pubkey,
                    salt_k=user.salt_k,
                    encrypted_private_key=user.enc_sk,
                ),
                password_bytes,
            )
        except KeyringError:
            raise
        except KeyringBackupError:
            raise KeyringError("backup_invalid") from None
        except CryptoBridgeError as error:
            if error.code in (BridgeErrorCode.PROVIDER_UNAVAILABLE, BridgeErrorCode.UNSUPPORTED):
                raise KeyringError("unavailable") from None
            raise KeyringError("internal") from None
        finally:
            password_bytes = None

    def import_backup(self, user_id: str, backup: bytes, password: str) -> KeyringSummary:
        password_bytes = self._password_bytes(password)
        key_encryption_key: bytes | None = None
        private_key: bytes | None = None
        try:
            with self._transaction():
                user = self.session.get(User, user_id)
                if user is None:
                    raise KeyringError("not_found")
                certificate = self.session.get(CertificateRecord, user.cert_serial)
                if (
                    certificate is None
                    or certificate.subject_user_id != user.id
                    or certificate.status != "active"
                ):
                    raise KeyringError("conflict")
                self._authenticate(user, password_bytes)
                restored = KeyringBackupCodec(self.crypto_engine).import_backup(
                    backup, password_bytes, user.id
                )
                if (
                    restored.role != user.role
                    or restored.certificate_serial != user.cert_serial
                    or restored.public_key != user.pubkey
                    or restored.salt_k != user.salt_k
                ):
                    raise KeyringError("backup_invalid")
                nonce, ciphertext, tag = self._parse_encrypted_private_key(
                    restored.encrypted_private_key
                )
                key_encryption_key = self.crypto_engine.hkdf_sm3(
                    password_bytes, user.salt_k, b"user-kek", SM4_KEY_SIZE
                )
                private_key = self.crypto_engine.sm4_gcm_decrypt(
                    key_encryption_key, nonce, ciphertext, b"", tag
                )
                if len(private_key) != SM2_PRIVATE_KEY_SIZE:
                    raise KeyringError("backup_invalid")
                self.crypto_engine.csr_create(private_key, user.pubkey, user.id, user.role)
                user.enc_sk = restored.encrypted_private_key
                self.key_cache.delete(user.id)
                self.session.flush()
            return self.summary(user_id, datetime.now(timezone.utc))
        except KeyringError:
            raise
        except KeyringBackupError:
            raise KeyringError("backup_invalid") from None
        except CryptoBridgeError as error:
            if error.code in (BridgeErrorCode.PROVIDER_UNAVAILABLE, BridgeErrorCode.UNSUPPORTED):
                raise KeyringError("unavailable") from None
            raise KeyringError("backup_invalid") from None
        except Exception:
            raise KeyringError("internal") from None
        finally:
            password_bytes = None
            key_encryption_key = None
            private_key = None

    def _authenticate(self, user: User, password: bytes) -> None:
        candidate = self.crypto_engine.sm3_hash_password(password, user.salt_a)
        if not self.crypto_engine.constant_time_equal(candidate, user.auth_hash):
            raise KeyringError("credentials_invalid")

    @staticmethod
    def _password_bytes(password: str) -> bytes:
        if not isinstance(password, str) or not 1 <= len(password) <= 128:
            raise KeyringError("credentials_invalid")
        value = password.encode("utf-8")
        if not 1 <= len(value) <= 512:
            raise KeyringError("credentials_invalid")
        return value

    @staticmethod
    def _parse_encrypted_private_key(enc_sk: bytes) -> tuple[bytes, bytes, bytes]:
        if not isinstance(enc_sk, bytes) or len(enc_sk) < 2 + GCM_NONCE_SIZE + GCM_TAG_SIZE + 1:
            raise KeyringError("internal")
        if enc_sk[:2] != b"v1":
            raise KeyringError("internal")
        nonce = enc_sk[2 : 2 + GCM_NONCE_SIZE]
        tag = enc_sk[-GCM_TAG_SIZE:]
        ciphertext = enc_sk[2 + GCM_NONCE_SIZE : -GCM_TAG_SIZE]
        if not ciphertext:
            raise KeyringError("internal")
        return nonce, ciphertext, tag

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        manager = self.session.begin_nested() if self.session.in_transaction() else self.session.begin()
        with manager:
            yield

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
