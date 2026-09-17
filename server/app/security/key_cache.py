from datetime import datetime
from typing import Protocol


class PrivateKeyUnlockCacheProtocol(Protocol):
    def put(self, user_id: str, private_key: bytes, expires_at: datetime) -> None: ...

    def get(self, user_id: str, now: datetime) -> bytes | None: ...

    def expires_at(self, user_id: str, now: datetime) -> datetime | None: ...

    def delete(self, user_id: str) -> None: ...


class PrivateKeyUnlockCache:
    def __init__(self) -> None:
        self._entries: dict[str, tuple[bytes, datetime]] = {}

    def put(self, user_id: str, private_key: bytes, expires_at: datetime) -> None:
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("invalid_cache_key")
        if not isinstance(private_key, bytes) or not private_key:
            raise ValueError("invalid_cache_value")
        self._entries[user_id] = (private_key, expires_at)

    def get(self, user_id: str, now: datetime) -> bytes | None:
        entry = self._entries.get(user_id)
        if entry is None:
            return None
        private_key, expires_at = entry
        if now >= expires_at:
            self._entries.pop(user_id, None)
            return None
        return private_key

    def expires_at(self, user_id: str, now: datetime) -> datetime | None:
        entry = self._entries.get(user_id)
        if entry is None:
            return None
        _, expires_at = entry
        if now >= expires_at:
            self._entries.pop(user_id, None)
            return None
        return expires_at

    def delete(self, user_id: str) -> None:
        self._entries.pop(user_id, None)

    def __repr__(self) -> str:
        return f"PrivateKeyUnlockCache(entries={len(self._entries)})"
