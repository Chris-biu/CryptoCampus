import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterator

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.models.session import UserSession
from app.models.user import User
from app.schemas.session import DeviceSession
from app.security.tokens import AccessTokenIssuer, TokenIssuerError


REFRESH_TOKEN_TTL = timedelta(days=7)


class SessionError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SessionService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.token_factory = token_factory or (lambda: secrets.token_urlsafe(48))

    def create(
        self, user_id: str, device: str, ip: str, now: datetime
    ) -> tuple[str, UserSession]:
        normalized_now = self._utc(now)
        token: str | None = None
        try:
            token = self.token_factory()
            token_hash = self._digest(token)
            record = UserSession(
                user_id=user_id,
                device=self._device(device),
                ip=self._ip(ip),
                refresh_token_hash=token_hash,
                expires_at=normalized_now + REFRESH_TOKEN_TTL,
                last_active_at=normalized_now,
                revoked=False,
            )
            with self._transaction():
                self.session.add(record)
                self.session.flush()
            return token, record
        except SessionError:
            raise
        except Exception as error:
            raise SessionError("internal") from error
        finally:
            token = None

    def rotate(
        self, token: str, now: datetime, device: str, ip: str
    ) -> tuple[str, UserSession, User]:
        normalized_now = self._utc(now)
        try:
            token_hash = self._digest(token)
            with self._transaction():
                record = (
                    self.session.query(UserSession)
                    .filter(UserSession.refresh_token_hash == token_hash)
                    .one_or_none()
                )
                if record is None:
                    raise SessionError("invalid")
                user = self.session.get(User, record.user_id)
                if (
                    user is None
                    or user.status != "active"
                    or record.revoked
                    or self._utc(record.expires_at) <= normalized_now
                ):
                    raise SessionError("invalid")
                result = self.session.execute(
                    update(UserSession)
                    .where(
                        UserSession.id == record.id,
                        UserSession.revoked.is_(False),
                    )
                    .values(revoked=True)
                )
                if result.rowcount != 1:
                    raise SessionError("invalid")
                new_token = self.token_factory()
                new_record = UserSession(
                    user_id=user.id,
                    device=self._device(device),
                    ip=self._ip(ip),
                    refresh_token_hash=self._digest(new_token),
                    expires_at=normalized_now + REFRESH_TOKEN_TTL,
                    last_active_at=normalized_now,
                    revoked=False,
                )
                self.session.add(new_record)
                self.session.flush()
            return new_token, new_record, user
        except SessionError:
            raise
        except Exception as error:
            raise SessionError("internal") from error
        finally:
            token = None

    def refresh(
        self,
        token: str,
        now: datetime,
        device: str,
        ip: str,
        token_issuer: AccessTokenIssuer,
    ) -> tuple[str, UserSession, User, str]:
        normalized_now = self._utc(now)
        try:
            token_hash = self._digest(token)
            with self._transaction():
                record = (
                    self.session.query(UserSession)
                    .filter(UserSession.refresh_token_hash == token_hash)
                    .one_or_none()
                )
                if record is None:
                    raise SessionError("invalid")
                user = self.session.get(User, record.user_id)
                if (
                    user is None
                    or user.status != "active"
                    or record.revoked
                    or self._utc(record.expires_at) <= normalized_now
                ):
                    raise SessionError("invalid")
                result = self.session.execute(
                    update(UserSession)
                    .where(UserSession.id == record.id, UserSession.revoked.is_(False))
                    .values(revoked=True)
                )
                if result.rowcount != 1:
                    raise SessionError("invalid")
                new_token = self.token_factory()
                new_record = UserSession(
                    user_id=user.id,
                    device=self._device(device),
                    ip=self._ip(ip),
                    refresh_token_hash=self._digest(new_token),
                    expires_at=normalized_now + REFRESH_TOKEN_TTL,
                    last_active_at=normalized_now,
                    revoked=False,
                )
                self.session.add(new_record)
                self.session.flush()
                try:
                    access_token = token_issuer.issue_access_token(
                        user.id, user.role, normalized_now, sid=new_record.id
                    )
                except TypeError:
                    access_token = token_issuer.issue_access_token(
                        user.id, user.role, normalized_now
                    )
                except Exception as error:
                    raise SessionError("internal") from error
                if not isinstance(access_token, str) or not access_token:
                    raise SessionError("internal")
            return new_token, new_record, user, access_token
        except SessionError:
            raise
        except Exception as error:
            raise SessionError("internal") from error
        finally:
            token = None

    def revoke(self, token: str, now: datetime) -> None:
        normalized_now = self._utc(now)
        try:
            token_hash = self._digest(token)
            with self._transaction():
                record = (
                    self.session.query(UserSession)
                    .filter(UserSession.refresh_token_hash == token_hash)
                    .one_or_none()
                )
                if record is None or record.revoked or self._utc(record.expires_at) <= normalized_now:
                    raise SessionError("invalid")
                record.revoked = True
                self.session.flush()
        except SessionError:
            raise
        except Exception as error:
            raise SessionError("internal") from error
        finally:
            token = None

    def list_for_user(
        self, user_id: str, current_session_id: str | None = None
    ) -> list[DeviceSession]:
        records = (
            self.session.query(UserSession)
            .filter(UserSession.user_id == user_id)
            .order_by(UserSession.last_active_at.desc())
            .all()
        )
        return [
            DeviceSession(
                id=record.id,
                device=record.device,
                ip_masked=mask_ip(record.ip),
                last_active_at=self._utc(record.last_active_at),
                current=record.id == current_session_id,
            )
            for record in records
        ]

    def revoke_for_user(self, user_id: str, session_id: str) -> None:
        with self._transaction():
            record = (
                self.session.query(UserSession)
                .filter(UserSession.id == session_id, UserSession.user_id == user_id)
                .one_or_none()
            )
            if record is None:
                raise SessionError("not_found")
            record.revoked = True
            self.session.flush()

    def _digest(self, token: str) -> bytes:
        if not isinstance(token, str) or not token:
            raise SessionError("invalid")
        digest = self.crypto_engine.sm3_digest(token.encode("utf-8"))
        if not isinstance(digest, bytes) or not digest:
            raise SessionError("internal")
        return digest

    @staticmethod
    def _device(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            return "unknown"
        normalized = value.strip()
        lowered = normalized.lower()
        for marker, label in (("edg/", "Edge"), ("chrome/", "Chrome"), ("firefox/", "Firefox"), ("safari/", "Safari")):
            if marker in lowered:
                return label
        return normalized[:100] if len(normalized) <= 100 else "unknown"

    @staticmethod
    def _ip(value: str) -> str:
        if not isinstance(value, str) or not value:
            return "0.0.0.0"
        return value[:45]

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


def mask_ip(value: str) -> str:
    if "." in value:
        parts = value.split(".")
        return ".".join(parts[:3] + ["xxx"]) if len(parts) == 4 else "xxx"
    if ":" in value:
        parts = value.split(":")
        visible = parts[:4]
        return ":".join(visible + ["xxxx"])
    return "xxx"
