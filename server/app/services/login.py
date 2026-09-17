from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator

from sqlalchemy import case, update
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import GCM_NONCE_SIZE, GCM_TAG_SIZE, SM4_KEY_SIZE
from app.models.user import User
from app.schemas.auth import AuthSession, UserSummary
from app.security.key_cache import PrivateKeyUnlockCacheProtocol
from app.security.password_policy import PasswordPolicyError, normalize_campus_email
from app.security.tokens import AccessTokenIssuer, TokenIssuerError
from app.services.sessions import SessionService


class LoginError(Exception):
    def __init__(self, code: str, status_code: int | None = None) -> None:
        self.code = code
        self.status_code = status_code or {
            "INVALID_CREDENTIALS": 401,
            "RATE_LIMITED": 429,
            "PROVIDER_UNAVAILABLE": 503,
            "INTERNAL_ERROR": 500,
        }.get(code, 500)
        super().__init__(code)


_DUMMY_SALT_A = b"login-dummy-salt-a"
_DUMMY_AUTH_HASH = b"login-dummy-auth-hash-32-bytes!!"


class LoginService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        token_issuer: AccessTokenIssuer,
        key_cache: PrivateKeyUnlockCacheProtocol,
        session_service: SessionService | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.token_issuer = token_issuer
        self.key_cache = key_cache
        self.session_service = session_service
        self._pending_refresh_token: str | None = None

    def login(
        self,
        email: str,
        password: str,
        now: datetime,
        device: str = "unknown",
        ip: str = "0.0.0.0",
    ) -> AuthSession:
        self._pending_refresh_token = None
        password_bytes: bytes | None = None
        key_encryption_key: bytes | None = None
        private_key: bytes | None = None
        cached_user_id: str | None = None
        failure_code: str | None = None
        normalized_now = self._utc(now)
        try:
            try:
                normalized_email = normalize_campus_email(email)
            except PasswordPolicyError as error:
                raise LoginError("INVALID_CREDENTIALS") from error

            if not isinstance(password, str) or not 1 <= len(password) <= 128:
                raise LoginError("INVALID_CREDENTIALS")
            password_bytes = password.encode("utf-8")
            if not 1 <= len(password_bytes) <= 512:
                raise LoginError("INVALID_CREDENTIALS")

            with self._transaction():
                user = (
                    self.session.query(User)
                    .filter(User.email == normalized_email)
                    .one_or_none()
                )
                if user is None:
                    self._authenticate_dummy(password_bytes)
                    raise LoginError("INVALID_CREDENTIALS")
                if user.status != "active":
                    raise LoginError("INVALID_CREDENTIALS")
                if user.locked_until is not None and self._utc(user.locked_until) > normalized_now:
                    raise LoginError("RATE_LIMITED")

                if not self._authenticate_user(user, password_bytes):
                    self._record_failure(user, normalized_now)
                    failure_code = (
                        "RATE_LIMITED"
                        if user.failed_login_count >= 5
                        else "INVALID_CREDENTIALS"
                    )
                else:
                    key_encryption_key = self.crypto_engine.hkdf_sm3(
                        password_bytes, user.salt_k, b"user-kek", SM4_KEY_SIZE
                    )
                    nonce, ciphertext, tag = self._parse_encrypted_private_key(user.enc_sk)
                    private_key = self.crypto_engine.sm4_gcm_decrypt(
                        key_encryption_key, nonce, ciphertext, b"", tag
                    )
                    if not isinstance(private_key, bytes) or not private_key:
                        raise LoginError("INTERNAL_ERROR")

                    user.failed_login_count = 0
                    user.locked_until = None
                    self.session.flush()
                    cached_user_id = user.id
                    self.key_cache.put(
                        user.id, private_key, normalized_now + timedelta(minutes=15)
                    )
                    refresh_token: str | None = None
                    refresh_record = None
                    if self.session_service is not None:
                        try:
                            refresh_token, refresh_record = self.session_service.create(
                                user.id, device, ip, normalized_now
                            )
                        except Exception as error:
                            raise LoginError("INTERNAL_ERROR") from error
                    try:
                        try:
                            access_token = self.token_issuer.issue_access_token(
                                user.id, user.role, normalized_now,
                                sid=refresh_record.id if refresh_record is not None else None,
                            )
                        except TypeError:
                            access_token = self.token_issuer.issue_access_token(
                                user.id, user.role, normalized_now
                            )
                    except TokenIssuerError as error:
                        raise LoginError("INTERNAL_ERROR") from error
                    except Exception as error:
                        raise LoginError("INTERNAL_ERROR") from error
                    self.session.flush()
                    self._pending_refresh_token = refresh_token
                    result = AuthSession(
                        access_token=access_token,
                        token_type="bearer",
                        expires_in=7200,
                        user=UserSummary.model_validate(
                            {
                                "id": user.id,
                                "email": user.email,
                                "role": user.role,
                                "status": user.status,
                                "pqc_mode": user.pqc_pubkey is not None,
                                "created_at": user.created_at,
                            }
                        ),
                    )
            if failure_code is not None:
                raise LoginError(failure_code)
            return result
        except LoginError:
            if cached_user_id is not None:
                try:
                    self.key_cache.delete(cached_user_id)
                except Exception:
                    pass
            raise
        except CryptoBridgeError as error:
            if cached_user_id is not None:
                try:
                    self.key_cache.delete(cached_user_id)
                except Exception:
                    pass
            if error.code in (
                BridgeErrorCode.PROVIDER_UNAVAILABLE,
                BridgeErrorCode.UNSUPPORTED,
            ):
                raise LoginError("PROVIDER_UNAVAILABLE") from None
            raise LoginError("INTERNAL_ERROR") from None
        except Exception:
            if cached_user_id is not None:
                try:
                    self.key_cache.delete(cached_user_id)
                except Exception:
                    pass
            raise LoginError("INTERNAL_ERROR") from None
        finally:
            password_bytes = None
            key_encryption_key = None
            private_key = None

    def take_refresh_token(self) -> str | None:
        token = self._pending_refresh_token
        self._pending_refresh_token = None
        return token

    def _authenticate_user(self, user: User, password_bytes: bytes) -> bool:
        derived_hash = self.crypto_engine.sm3_hash_password(password_bytes, user.salt_a)
        return self.crypto_engine.constant_time_equal(derived_hash, user.auth_hash)

    def _authenticate_dummy(self, password_bytes: bytes) -> bool:
        derived_hash = self.crypto_engine.sm3_hash_password(password_bytes, _DUMMY_SALT_A)
        return self.crypto_engine.constant_time_equal(derived_hash, _DUMMY_AUTH_HASH)

    def _record_failure(self, user: User, now: datetime) -> None:
        next_count = User.failed_login_count + 1
        lock_deadline = now + timedelta(minutes=10)
        result = self.session.execute(
            update(User)
            .where(User.id == user.id)
            .values(
                failed_login_count=next_count,
                locked_until=case(
                    (next_count >= 5, lock_deadline), else_=User.locked_until
                ),
            )
        )
        if result.rowcount != 1:
            raise LoginError("INTERNAL_ERROR")
        self.session.flush()
        self.session.refresh(user)

    @staticmethod
    def _parse_encrypted_private_key(enc_sk: bytes) -> tuple[bytes, bytes, bytes]:
        if not isinstance(enc_sk, bytes) or len(enc_sk) < 2 + GCM_NONCE_SIZE + GCM_TAG_SIZE:
            raise LoginError("INTERNAL_ERROR")
        if enc_sk[:2] != b"v1":
            raise LoginError("INTERNAL_ERROR")
        nonce = enc_sk[2 : 2 + GCM_NONCE_SIZE]
        tag = enc_sk[-GCM_TAG_SIZE:]
        ciphertext = enc_sk[2 + GCM_NONCE_SIZE : -GCM_TAG_SIZE]
        if not ciphertext:
            raise LoginError("INTERNAL_ERROR")
        return nonce, ciphertext, tag

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        manager = self.session.begin_nested() if self.session.in_transaction() else self.session.begin()
        with manager:
            yield
