from contextlib import contextmanager
import secrets
from collections.abc import Iterator

from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import GCM_NONCE_SIZE, GCM_TAG_SIZE, SM4_KEY_SIZE, Sm4GcmCiphertext
from app.models.user import User
from app.security.key_cache import PrivateKeyUnlockCacheProtocol
from app.security.password_policy import PasswordPolicyError, validate_password


class PasswordChangeError(Exception):
    _STATUS_CODES = {
        "INVALID_CREDENTIALS": 401,
        "VALIDATION_ERROR": 422,
        "PROVIDER_UNAVAILABLE": 503,
        "CRYPTO_ERROR": 500,
        "INTERNAL_ERROR": 500,
    }

    def __init__(self, code: str) -> None:
        self.code = code
        self.status_code = self._STATUS_CODES.get(code, 500)
        super().__init__(code)


class PasswordChangeService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        key_cache: PrivateKeyUnlockCacheProtocol,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.key_cache = key_cache

    def change(self, user_id: str, current_password: str, new_password: str) -> None:
        password_bytes: bytes | None = None
        new_password_bytes: bytes | None = None
        old_kek: bytes | None = None
        new_kek: bytes | None = None
        private_key: bytes | None = None
        try:
            self._validate_inputs(current_password, new_password)
            if current_password == new_password:
                raise PasswordChangeError("VALIDATION_ERROR")
            try:
                password_bytes = current_password.encode("utf-8")
                new_password_bytes = new_password.encode("utf-8")
            except UnicodeError:
                raise PasswordChangeError("VALIDATION_ERROR") from None

            with self._transaction():
                user = self.session.get(User, user_id)
                if user is None or user.status != "active":
                    raise PasswordChangeError("INVALID_CREDENTIALS")

                derived_hash = self.crypto_engine.sm3_hash_password(
                    password_bytes, user.salt_a
                )
                if not self.crypto_engine.constant_time_equal(
                    derived_hash, user.auth_hash
                ):
                    raise PasswordChangeError("INVALID_CREDENTIALS")

                old_kek = self.crypto_engine.hkdf_sm3(
                    password_bytes, user.salt_k, b"user-kek", SM4_KEY_SIZE
                )
                nonce, ciphertext, tag = self._parse_encrypted_private_key(user.enc_sk)
                private_key = self.crypto_engine.sm4_gcm_decrypt(
                    old_kek, nonce, ciphertext, b"", tag
                )
                if not isinstance(private_key, bytes) or not private_key:
                    raise PasswordChangeError("CRYPTO_ERROR")

                salt_a = secrets.token_bytes(32)
                salt_k = secrets.token_bytes(32)
                if salt_a in (user.salt_a, user.salt_k) or salt_k in (
                    user.salt_a,
                    user.salt_k,
                    salt_a,
                ):
                    raise PasswordChangeError("CRYPTO_ERROR")
                auth_hash = self.crypto_engine.sm3_hash_password(
                    new_password_bytes, salt_a
                )
                new_kek = self.crypto_engine.hkdf_sm3(
                    new_password_bytes, salt_k, b"user-kek", SM4_KEY_SIZE
                )
                encrypted = self.crypto_engine.sm4_gcm_encrypt(new_kek, private_key)
                if (
                    not isinstance(encrypted, Sm4GcmCiphertext)
                    or not isinstance(encrypted.ciphertext, bytes)
                    or not encrypted.ciphertext
                ):
                    raise PasswordChangeError("CRYPTO_ERROR")
                user.salt_a = salt_a
                user.auth_hash = auth_hash
                user.salt_k = salt_k
                user.enc_sk = self._pack_encrypted_private_key(encrypted)
                self.session.flush()
                self.key_cache.delete(user.id)
        except PasswordChangeError:
            raise
        except CryptoBridgeError as error:
            if error.code in (BridgeErrorCode.PROVIDER_UNAVAILABLE, BridgeErrorCode.UNSUPPORTED):
                raise PasswordChangeError("PROVIDER_UNAVAILABLE") from None
            raise PasswordChangeError("CRYPTO_ERROR") from None
        except Exception:
            raise PasswordChangeError("INTERNAL_ERROR") from None
        finally:
            password_bytes = None
            new_password_bytes = None
            old_kek = None
            new_kek = None
            private_key = None

    @staticmethod
    def _validate_inputs(current_password: str, new_password: str) -> None:
        if (
            not isinstance(current_password, str)
            or not 1 <= len(current_password) <= 128
            or len(current_password.encode("utf-8")) > 512
        ):
            raise PasswordChangeError("VALIDATION_ERROR")
        try:
            validate_password(new_password)
        except (PasswordPolicyError, UnicodeError):
            raise PasswordChangeError("VALIDATION_ERROR") from None
        if len(new_password.encode("utf-8")) > 512:
            raise PasswordChangeError("VALIDATION_ERROR")

    @staticmethod
    def _parse_encrypted_private_key(enc_sk: bytes) -> tuple[bytes, bytes, bytes]:
        if not isinstance(enc_sk, bytes) or len(enc_sk) < 2 + GCM_NONCE_SIZE + GCM_TAG_SIZE + 1:
            raise PasswordChangeError("CRYPTO_ERROR")
        if enc_sk[:2] != b"v1":
            raise PasswordChangeError("CRYPTO_ERROR")
        nonce = enc_sk[2 : 2 + GCM_NONCE_SIZE]
        tag = enc_sk[-GCM_TAG_SIZE:]
        ciphertext = enc_sk[2 + GCM_NONCE_SIZE : -GCM_TAG_SIZE]
        if not ciphertext:
            raise PasswordChangeError("CRYPTO_ERROR")
        return nonce, ciphertext, tag

    @staticmethod
    def _pack_encrypted_private_key(encrypted: Sm4GcmCiphertext) -> bytes:
        return b"v1" + encrypted.nonce + encrypted.ciphertext + encrypted.tag

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        manager = self.session.begin_nested() if self.session.in_transaction() else self.session.begin()
        with manager:
            yield
