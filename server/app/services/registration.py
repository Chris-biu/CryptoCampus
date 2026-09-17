from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import secrets
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import SM4_KEY_SIZE
from app.models.audit import AuditLog
from app.models.user import User
from app.pki.errors import PkiError
from app.pki.service import PlatformCAService
from app.security.password_policy import PasswordPolicyError, normalize_campus_email, validate_password


class AuthSession(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 7200
    user: dict[str, Any]


class TokenIssuer(Protocol):
    def issue(self, user: User) -> AuthSession: ...


class RegistrationError(Exception):
    def __init__(self, code: str, status_code: int = 422) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(code)


class VerificationConsumer(Protocol):
    def consume(self, email: str, code: str, now: datetime | None = None) -> bool: ...


class RegistrationService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        platform_ca: PlatformCAService,
        verification_codes: VerificationConsumer,
        token_issuer: TokenIssuer,
        *,
        pqc_mode: bool = False,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.platform_ca = platform_ca
        self.verification_codes = verification_codes
        self.token_issuer = token_issuer
        self.pqc_mode = pqc_mode

    def register(self, email: str, password: str, verification_code: str) -> AuthSession:
        try:
            normalized_email = normalize_campus_email(email)
            validate_password(password)
        except PasswordPolicyError as error:
            raise RegistrationError("VALIDATION_ERROR", 422) from error
        if not isinstance(verification_code, str) or len(verification_code) != 6 or not verification_code.isdigit():
            raise RegistrationError("VALIDATION_ERROR", 422)
        now = datetime.now(timezone.utc)
        if not self.verification_codes.consume(normalized_email, verification_code, now):
            raise RegistrationError("CREDENTIALS_INVALID", 422)
        if self.pqc_mode:
            raise RegistrationError("UNSUPPORTED", 503)

        password_bytes: bytes | None = password.encode("utf-8")
        key_encryption_key: bytes | None = None
        private_key: bytes | None = None
        csr_der: bytes | None = None
        try:
            with self._transaction():
                if self.session.query(User).filter(User.email == normalized_email).one_or_none() is not None:
                    raise RegistrationError("EMAIL_EXISTS", 409)
                user_id = str(uuid4())
                salt_a = secrets.token_bytes(32)
                salt_k = secrets.token_bytes(32)
                auth_hash = self.crypto_engine.sm3_hash_password(password_bytes, salt_a)
                key_encryption_key = self.crypto_engine.hkdf_sm3(password_bytes, salt_k, b"user-kek", SM4_KEY_SIZE)
                key_pair = self.crypto_engine.sm2_generate_keypair()
                private_key = key_pair.private_key
                encrypted = self.crypto_engine.sm4_gcm_encrypt(key_encryption_key, private_key)
                enc_sk = b"v1" + encrypted.nonce + encrypted.ciphertext + encrypted.tag
                issued = self.platform_ca.issue_user_certificate(
                    user_id, "student", private_key, key_pair.public_key,
                    now, now + timedelta(days=365),
                )
                user = User(
                    id=user_id, email=normalized_email, role="student", status="active",
                    salt_a=salt_a, auth_hash=auth_hash, salt_k=salt_k,
                    enc_sk=enc_sk, pubkey=key_pair.public_key,
                    cert_serial=issued.certificate.serial,
                )
                self.session.add(user)
                self.session.flush()
                self.platform_ca.record_issued_certificate(user, issued)
                self.session.add(
                    AuditLog(
                        actor=user.id,
                        action="auth.register",
                        target=f"user:{user.id}",
                        detail_hash=self.crypto_engine.sm3_digest(
                            f"auth.register|{user.id}".encode("utf-8")
                        ),
                    )
                )
                self.session.flush()
                return self.token_issuer.issue(user)
        except RegistrationError:
            raise
        except CryptoBridgeError as error:
            status = 503 if error.code in (BridgeErrorCode.UNSUPPORTED, BridgeErrorCode.PROVIDER_UNAVAILABLE) else 500
            raise RegistrationError("UNSUPPORTED" if status == 503 else "INTERNAL_ERROR", status) from None
        except PkiError:
            raise RegistrationError("INTERNAL_ERROR", 500) from None
        except IntegrityError:
            raise RegistrationError("EMAIL_EXISTS", 409) from None
        except Exception:
            raise RegistrationError("INTERNAL_ERROR", 500) from None
        finally:
            password_bytes = None
            key_encryption_key = None
            private_key = None
            csr_der = None

    register_user = register

    @contextmanager
    def _transaction(self):
        manager = self.session.begin_nested() if self.session.in_transaction() else self.session.begin()
        with manager:
            yield
