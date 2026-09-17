import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Protocol
from typing import Callable
from uuid import uuid4

from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError


class VerificationCodeError(Exception):
    pass


class VerificationCodeSender(Protocol):
    def send(self, email: str, code: str) -> None: ...


class VerificationCodeDigest(Protocol):
    def sm3_digest(self, message: bytes) -> bytes: ...


class VerificationCodeStore(Protocol):
    def issue(self, email: str, code: str, expires_at: datetime) -> str: ...

    def consume(self, email: str, code: str, now: datetime) -> bool: ...

    def revoke(self, email: str, issue_id: str) -> None: ...


@dataclass
class _Entry:
    issue_id: str
    digest: bytes
    expires_at: datetime
    consumed: bool = False


class InMemoryVerificationCodeStore:
    def __init__(self, crypto_engine: VerificationCodeDigest | None = None) -> None:
        self._crypto_engine = crypto_engine
        self._entries: dict[str, _Entry] = {}
        self._lock = Lock()

    def issue(self, email: str, code: str, expires_at: datetime) -> str:
        issue_id = str(uuid4())
        with self._lock:
            self._entries[email] = _Entry(issue_id, self._digest(code), expires_at)
        return issue_id

    def consume(self, email: str, code: str, now: datetime) -> bool:
        with self._lock:
            entry = self._entries.get(email)
            if entry is None or entry.consumed or now >= entry.expires_at:
                return False
            if not secrets.compare_digest(entry.digest, self._digest(code)):
                return False
            entry.consumed = True
            return True

    def revoke(self, email: str, issue_id: str) -> None:
        with self._lock:
            entry = self._entries.get(email)
            if entry is not None and entry.issue_id == issue_id and not entry.consumed:
                self._entries.pop(email, None)

    def _digest(self, code: str) -> bytes:
        if self._crypto_engine is None:
            raise VerificationCodeError("crypto_engine_required")
        return self._crypto_engine.sm3_digest(code.encode("ascii"))

    def __repr__(self) -> str:
        return f"{type(self).__name__}(entries={len(self._entries)})"


class VerificationCodeService:
    def __init__(
        self,
        sender: VerificationCodeSender,
        store: VerificationCodeStore,
        crypto_engine: CryptoEngine | None = None,
        ttl: timedelta = timedelta(minutes=10),
        code_factory: Callable[[], str] | None = None,
    ) -> None:
        self.sender = sender
        self.store = store
        if crypto_engine is not None:
            self.store._crypto_engine = crypto_engine
        self.ttl = ttl
        self.code_factory = code_factory or (lambda: f"{secrets.randbelow(1_000_000):06d}")

    def issue(self, email: str, *, now: datetime | None = None) -> None:
        issued_at = now or datetime.now(timezone.utc)
        code = self.code_factory()
        if not isinstance(code, str) or len(code) != 6 or not code.isdigit():
            raise VerificationCodeError("verification_code_invalid")
        expires_at = issued_at + self.ttl
        issue_id: str | None = None
        try:
            issue_id = self.store.issue(email, code, expires_at)
            self.sender.send(email, code)
        except (CryptoBridgeError, Exception) as error:
            if issue_id is not None:
                try:
                    self.store.revoke(email, issue_id)
                except Exception:
                    pass
            if isinstance(error, VerificationCodeError):
                raise
            raise VerificationCodeError("verification_code_unavailable") from None

    def consume(self, email: str, code: str, now: datetime | None = None) -> bool:
        if not isinstance(code, str) or len(code) != 6 or not code.isdigit():
            return False
        return self.store.consume(email, code, now or datetime.now(timezone.utc))

    request_code = issue
    verify = consume
