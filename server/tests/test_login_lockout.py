from datetime import datetime, timedelta, timezone

import pytest

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.models.user import User
from app.services.login import LoginError, LoginService


class Token:
    def __init__(self, value: str = "access-token", error: Exception | None = None) -> None:
        self.value = value
        self.error = error
        self.calls: list[tuple[str, str, datetime]] = []

    def issue_access_token(self, user_id: str, role: str, now: datetime) -> str:
        self.calls.append((user_id, role, now))
        if self.error:
            raise self.error
        return self.value


class Cache:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.values: dict[str, bytes] = {}
        self.deleted: list[str] = []

    def put(self, user_id: str, private_key: bytes, expires_at: datetime) -> None:
        if self.error:
            raise self.error
        self.values[user_id] = private_key

    def get(self, user_id: str, now: datetime) -> bytes | None:
        return self.values.get(user_id)

    def delete(self, user_id: str) -> None:
        self.deleted.append(user_id)
        self.values.pop(user_id, None)


def add_user(db_session, **changes) -> User:
    values = {
        "email": "student@campus.edu",
        "role": "student",
        "status": "active",
        "cert_serial": "cert-login",
        "salt_a": b"a" * 16,
        "auth_hash": b"h" * 32,
        "salt_k": b"k" * 16,
        "enc_sk": b"v1" + b"n" * 12 + b"cipher" + b"t" * 16,
        "pubkey": b"p" * 65,
    }
    values.update(changes)
    user = User(**values)
    db_session.add(user)
    db_session.commit()
    return user


def configured_engine() -> MockCryptoEngine:
    engine = MockCryptoEngine()
    engine.set_result("sm3_hash_password", b"d" * 32)
    engine.set_result("constant_time_equal", True)
    engine.set_result("hkdf_sm3", b"k" * 16)
    engine.set_result("sm4_gcm_decrypt", b"s" * 32)
    return engine


def test_login_success_uses_crypto_engine_and_unlocks_private_key(db_session) -> None:
    user = add_user(db_session)
    engine = configured_engine()
    token = Token()
    cache = Cache()
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)

    result = LoginService(db_session, engine, token, cache).login(
        " Student@Campus.edu ", "Password123", now
    )

    assert result.access_token == "access-token"
    assert result.expires_in == 7200
    assert token.calls == [(user.id, "student", now)]
    assert cache.values[user.id] == b"s" * 32
    assert [operation for operation, _ in engine.calls] == [
        "sm3_hash_password",
        "constant_time_equal",
        "hkdf_sm3",
        "sm4_gcm_decrypt",
    ]
    assert user.failed_login_count == 0
    assert user.locked_until is None


def test_wrong_password_increments_count_without_token_or_cache(db_session) -> None:
    user = add_user(db_session)
    engine = configured_engine()
    engine.set_result("constant_time_equal", False)
    token = Token()
    cache = Cache()

    with pytest.raises(LoginError) as raised:
        LoginService(db_session, engine, token, cache).login(
            user.email, "wrong", datetime(2030, 1, 1, tzinfo=timezone.utc)
        )

    assert raised.value.code == "INVALID_CREDENTIALS"
    assert token.calls == []
    assert cache.values == {}
    assert db_session.query(User).filter_by(id=user.id).one().failed_login_count == 1


def test_fifth_wrong_password_locks_user_for_ten_minutes(db_session) -> None:
    user = add_user(db_session)
    engine = configured_engine()
    engine.set_result("constant_time_equal", False)
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    service = LoginService(db_session, engine, Token(), Cache())

    for _ in range(5):
        with pytest.raises(LoginError):
            service.login(user.email, "wrong", now)

    locked = db_session.query(User).filter_by(id=user.id).one()
    assert locked.failed_login_count == 5
    assert locked.locked_until.replace(tzinfo=timezone.utc) == now + timedelta(minutes=10)
    engine.set_result("constant_time_equal", True)
    with pytest.raises(LoginError) as raised:
        service.login(user.email, "Password123", now)
    assert raised.value.code == "RATE_LIMITED"


def test_frozen_user_is_rejected_without_success_response(db_session) -> None:
    user = add_user(db_session, status="frozen")
    engine = configured_engine()

    with pytest.raises(LoginError) as raised:
        LoginService(db_session, engine, Token(), Cache()).login(
            user.email, "Password123", datetime.now(timezone.utc)
        )

    assert raised.value.code == "INVALID_CREDENTIALS"


def test_success_clears_previous_failures_and_expired_lock(db_session) -> None:
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    user = add_user(
        db_session,
        failed_login_count=4,
        locked_until=now - timedelta(seconds=1),
    )
    engine = configured_engine()

    LoginService(db_session, engine, Token(), Cache()).login(
        user.email, "Password123", now
    )

    updated = db_session.query(User).filter_by(id=user.id).one()
    assert updated.failed_login_count == 0
    assert updated.locked_until is None


def test_missing_email_has_same_error_and_crypto_path_as_wrong_password(db_session) -> None:
    engine = configured_engine()
    engine.set_result("constant_time_equal", False)
    service = LoginService(db_session, engine, Token(), Cache())

    with pytest.raises(LoginError) as missing:
        service.login("missing@campus.edu", "wrong", datetime.now(timezone.utc))

    assert missing.value.code == "INVALID_CREDENTIALS"
    assert [operation for operation, _ in engine.calls] == [
        "sm3_hash_password",
        "constant_time_equal",
    ]


def test_decrypt_failure_rolls_back_auth_state_and_exposes_no_secret(db_session) -> None:
    user = add_user(db_session, failed_login_count=2)
    engine = configured_engine()
    engine.set_error(
        "sm4_gcm_decrypt", CryptoBridgeError(BridgeErrorCode.INTEGRITY_FAILED)
    )

    with pytest.raises(LoginError) as raised:
        LoginService(db_session, engine, Token(), Cache()).login(
            user.email, "Password123", datetime.now(timezone.utc)
        )

    assert raised.value.code == "INTERNAL_ERROR"
    assert "Password123" not in str(raised.value)
    assert db_session.query(User).filter_by(id=user.id).one().failed_login_count == 2


def test_token_failure_removes_cached_key_and_rolls_back_state(db_session) -> None:
    user = add_user(db_session, failed_login_count=2)
    engine = configured_engine()
    cache = Cache()
    token = Token(error=RuntimeError("token secret"))

    with pytest.raises(LoginError) as raised:
        LoginService(db_session, engine, token, cache).login(
            user.email, "Password123", datetime.now(timezone.utc)
        )

    assert raised.value.code == "INTERNAL_ERROR"
    assert "token secret" not in str(raised.value)
    assert cache.deleted == [user.id]
    assert cache.values == {}
    assert db_session.query(User).filter_by(id=user.id).one().failed_login_count == 2


def test_cache_failure_rolls_back_auth_state_and_cleans_partial_entry(db_session) -> None:
    user = add_user(db_session, failed_login_count=2)
    engine = configured_engine()
    cache = Cache(error=RuntimeError("private key cache failure"))

    with pytest.raises(LoginError) as raised:
        LoginService(db_session, engine, Token(), cache).login(
            user.email, "Password123", datetime.now(timezone.utc)
        )

    assert raised.value.code == "INTERNAL_ERROR"
    assert cache.deleted == [user.id]
    assert db_session.query(User).filter_by(id=user.id).one().failed_login_count == 2
