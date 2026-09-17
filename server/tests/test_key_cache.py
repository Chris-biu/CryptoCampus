from datetime import datetime, timedelta, timezone

from app.security.key_cache import PrivateKeyUnlockCache


def test_private_key_cache_expires_and_removes_key() -> None:
    cache = PrivateKeyUnlockCache()
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    private_key = b"private-key"
    cache.put("user-1", private_key, now + timedelta(minutes=15))

    assert cache.get("user-1", now + timedelta(minutes=14, seconds=59)) == private_key
    assert cache.get("user-1", now + timedelta(minutes=15)) is None
    assert cache.get("user-1", now + timedelta(minutes=16)) is None


def test_private_key_cache_repr_does_not_include_private_key() -> None:
    cache = PrivateKeyUnlockCache()
    now = datetime.now(timezone.utc)
    private_key = b"do-not-log-this-key"
    cache.put("user-1", private_key, now + timedelta(minutes=15))

    assert private_key.decode() not in repr(cache)


def test_private_key_cache_delete_supports_rollback() -> None:
    cache = PrivateKeyUnlockCache()
    now = datetime.now(timezone.utc)
    cache.put("user-1", b"private-key", now + timedelta(minutes=15))

    cache.delete("user-1")

    assert cache.get("user-1", now) is None
