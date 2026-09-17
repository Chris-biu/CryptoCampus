from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator, Protocol

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.models.audit import AuditLog
from app.models.credential import CredentialLedger
from app.models.notification import Notification
from app.models.session import UserSession
from app.models.user import User
from app.security.key_cache import PrivateKeyUnlockCacheProtocol


class CertificateRevoker(Protocol):
    def revoke_certificate(
        self, serial: str, reason: str, operator_user_id: str, this_update: datetime, next_update: datetime
    ) -> object: ...


class AccountGovernanceError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AccountGovernanceService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine | Callable[[bytes], bytes],
        key_cache: PrivateKeyUnlockCacheProtocol,
        platform_ca: CertificateRevoker | None = None,
        audit_chain_service: Any = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.key_cache = key_cache
        self.platform_ca = platform_ca
        self.audit_chain_service = audit_chain_service

    def update_status(self, actor_id: str, target_id: str, status: str, reason: str, now: datetime) -> User:
        if status not in {"active", "frozen"}:
            raise AccountGovernanceError("status_invalid")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
            raise AccountGovernanceError("reason_invalid")
        clear_cache_for: str | None = None
        try:
            with self._transaction():
                target = self.session.get(User, target_id)
                if target is None:
                    raise AccountGovernanceError("not_found")
                if target.role == "system":
                    raise AccountGovernanceError("system_user")
                if target.status == "pending_deletion":
                    raise AccountGovernanceError("pending_deletion")
                if target.status == status:
                    return target
                old_status = target.status
                target.status = status
                if status == "frozen":
                    self.session.execute(
                        update(UserSession)
                        .where(UserSession.user_id == target.id, UserSession.revoked.is_(False))
                        .values(revoked=True)
                    )
                action = "user.freeze" if status == "frozen" else "user.unfreeze"
                reason_hash = self._digest(reason.strip().encode("utf-8"))
                detail_hash = self._digest(
                    f"user.status.update|{target.id}|{old_status}|{status}|{reason_hash.hex()}".encode("utf-8")
                )
                self.session.add(
                    AuditLog(
                        actor=actor_id,
                        action=action,
                        target=f"user:{target.id}",
                        detail_hash=detail_hash,
                    )
                )
                if self.audit_chain_service is not None:
                    self.audit_chain_service.append(
                        session=self.session,
                        actor_id=actor_id,
                        action="user.status.update",
                        target=f"user:{target.id}",
                        detail_hash=detail_hash,
                        timestamp=now,
                    )
                self.session.flush()
                if status == "frozen":
                    clear_cache_for = target.id
        except AccountGovernanceError:
            raise
        except Exception as error:
            raise AccountGovernanceError("internal") from error
        if clear_cache_for is not None:
            self.key_cache.delete(clear_cache_for)
        return target

    def update_role(
        self,
        *,
        actor_id: str,
        target_id: str,
        new_role: str,
        reason: str,
        now: datetime,
    ) -> User:
        if new_role not in {"student", "admin", "teacher"}:
            raise AccountGovernanceError("role_invalid")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
            raise AccountGovernanceError("reason_invalid")
        clear_cache_for: str | None = None
        try:
            with self._transaction():
                target = self.session.get(User, target_id)
                if target is None:
                    raise AccountGovernanceError("not_found")
                if target.role == "system":
                    raise AccountGovernanceError("system_user")
                if target.status == "pending_deletion":
                    raise AccountGovernanceError("pending_deletion")
                if target.role == new_role:
                    return target
                if target.role == "teacher" and target.status == "active" and new_role != "teacher":
                    active_teachers = (
                        self.session.query(func.count(User.id))
                        .filter(User.role == "teacher", User.status == "active", User.id != target.id)
                        .scalar()
                        or 0
                    )
                    if active_teachers == 0:
                        raise AccountGovernanceError("last_teacher_protected")

                old_role = target.role
                target.role = new_role
                self.session.execute(
                    update(UserSession)
                    .where(UserSession.user_id == target.id, UserSession.revoked.is_(False))
                    .values(revoked=True)
                )
                clear_cache_for = target.id

                reason_hash = self._digest(reason.strip().encode("utf-8"))
                detail_hash = self._digest(
                    f"user.role.update|{target.id}|{old_role}|{new_role}|{reason_hash.hex()}".encode("utf-8")
                )
                self.session.add(
                    AuditLog(
                        actor=actor_id,
                        action="user.role.update",
                        target=f"user:{target.id}",
                        detail_hash=detail_hash,
                    )
                )
                if self.audit_chain_service is not None:
                    self.audit_chain_service.append(
                        session=self.session,
                        actor_id=actor_id,
                        action="user.role.update",
                        target=f"user:{target.id}",
                        detail_hash=detail_hash,
                        timestamp=now,
                    )
                self.session.flush()
        except AccountGovernanceError:
            raise
        except Exception as error:
            raise AccountGovernanceError("internal") from error
        if clear_cache_for is not None:
            self.key_cache.delete(clear_cache_for)
        return target

    def delete_account(self, user_id: str, password: str, confirm: str, now: datetime) -> None:
        if confirm != "DELETE_MY_ACCOUNT":
            raise AccountGovernanceError("credentials_invalid")
        if not isinstance(password, str) or not 1 <= len(password) <= 128:
            raise AccountGovernanceError("credentials_invalid")
        password_bytes = password.encode("utf-8")
        try:
            with self._transaction():
                user = self.session.get(User, user_id)
                if user is None:
                    raise AccountGovernanceError("not_found")
                if user.status == "pending_deletion":
                    return
                if user.status != "active" or not self._authenticate(user, password_bytes):
                    raise AccountGovernanceError("credentials_invalid")
                if self.platform_ca is None or not user.cert_serial:
                    raise AccountGovernanceError("unavailable")
                normalized_now = self._utc(now)
                self.session.add(
                    AuditLog(
                        actor=user.id,
                        action="user.delete.requested",
                        target=f"user:{user.id}",
                        detail_hash=self._digest(f"user.delete.requested|{user.id}".encode("utf-8")),
                    )
                )
                self.session.execute(
                    update(UserSession)
                    .where(UserSession.user_id == user.id, UserSession.revoked.is_(False))
                    .values(revoked=True)
                )
                self.session.execute(
                    delete(Notification).where(Notification.user_id == user.id)
                )
                self.platform_ca.revoke_certificate(
                    user.cert_serial,
                    "account_deletion",
                    user.id,
                    normalized_now,
                    normalized_now + timedelta(days=7),
                )
                user.status = "pending_deletion"
                user.email = None
                user.salt_a = None
                user.auth_hash = None
                user.salt_k = None
                user.enc_sk = None
                user.pubkey = None
                user.cert_serial = None
                user.pqc_pubkey = None
                user.enc_pqc_sk = None
                user.failed_login_count = 0
                user.locked_until = None
                self.session.add(
                    AuditLog(
                        actor=user.id,
                        action="user.delete.completed",
                        target=f"user:{user.id}",
                        detail_hash=self._digest(f"user.delete.completed|{user.id}".encode("utf-8")),
                    )
                )
                self.session.flush()
            self.key_cache.delete(user_id)
        except AccountGovernanceError:
            raise
        except CryptoBridgeError as error:
            if error.code in {BridgeErrorCode.PROVIDER_UNAVAILABLE, BridgeErrorCode.UNSUPPORTED}:
                raise AccountGovernanceError("unavailable") from None
            raise AccountGovernanceError("internal") from error
        except Exception as error:
            raise AccountGovernanceError("internal") from error
        finally:
            password_bytes = None

    def purge_expired_credential_ledgers(self, now: datetime) -> int:
        cutoff = self._utc(now) - timedelta(days=30)
        deleted_users = (
            select(User.id)
            .join(AuditLog, AuditLog.actor == User.id)
            .where(
                User.status == "pending_deletion",
                AuditLog.action == "user.delete.completed",
                AuditLog.ts <= cutoff,
            )
        )
        try:
            with self._transaction():
                result = self.session.execute(
                    delete(CredentialLedger).where(CredentialLedger.user_id.in_(deleted_users))
                )
                return int(result.rowcount or 0)
        except Exception as error:
            raise AccountGovernanceError("internal") from error

    def _authenticate(self, user: User, password: bytes) -> bool:
        if user.salt_a is None or user.auth_hash is None:
            return False
        engine = self.crypto_engine
        if not hasattr(engine, "sm3_hash_password") or not hasattr(engine, "constant_time_equal"):
            return False
        candidate = engine.sm3_hash_password(password, user.salt_a)
        return bool(engine.constant_time_equal(candidate, user.auth_hash))

    def _digest(self, value: bytes) -> bytes:
        engine = self.crypto_engine
        if callable(engine) and not hasattr(engine, "sm3_digest"):
            result = engine(value)
        else:
            result = engine.sm3_digest(value)
        if not isinstance(result, bytes) or len(result) != 32:
            raise AccountGovernanceError("internal")
        return result

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        if self.session.in_transaction():
            self.session.connection()
            yield
            return
        with self.session.begin():
            yield

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
