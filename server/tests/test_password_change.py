from datetime import datetime, timedelta, timezone

import pytest

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import Sm4GcmCiphertext
from app.models.user import User
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.password_change import PasswordChangeError, PasswordChangeService


def make_user() -> User:
    return User(
        id="user-password-change",
        email="student@campus.edu",
        role="student",
        status="active",
        salt_a=b"old-salt-a",
        auth_hash=b"old-auth-hash",
        salt_k=b"old-salt-k",
        enc_sk=b"v1" + b"n" * 12 + b"old-ciphertext" + b"t" * 16,
        pubkey=b"p" * 65,
        cert_serial="cert-password-change",
    )


def configure_success_engine(engine: MockCryptoEngine) -> None:
    engine.set_result("sm3_hash_password", b"derived-hash")
    engine.set_result("constant_time_equal", True)
    engine.set_result("hkdf_sm3", b"k" * 16)
    engine.set_result("sm4_gcm_decrypt", b"private-key")
    engine.set_result(
        "sm4_gcm_encrypt", Sm4GcmCiphertext(b"new-ciphertext", b"N" * 12, b"T" * 16)
    )


def test_change_password_reencrypts_private_key_and_invalidates_cache(
    db_session, monkeypatch
) -> None:
    user = make_user()
    db_session.add(user)
    db_session.commit()
    engine = MockCryptoEngine()
    configure_success_engine(engine)
    salts = iter((b"new-salt-a", b"new-salt-k"))
    monkeypatch.setattr("app.services.password_change.secrets.token_bytes", lambda _: next(salts))
    cache = PrivateKeyUnlockCache()
    cache.put(
        user.id,
        b"cached-private-key",
        datetime.now(timezone.utc) + timedelta(minutes=15),
    )

    service = PasswordChangeService(db_session, engine, cache)
    service.change(user.id, "Current123", "NewPassword123")

    db_session.expire_all()
    updated = db_session.get(User, user.id)
    assert updated is not None
    assert updated.salt_a == b"new-salt-a"
    assert updated.auth_hash == b"derived-hash"
    assert updated.salt_k == b"new-salt-k"
    assert updated.enc_sk == b"v1" + b"N" * 12 + b"new-ciphertext" + b"T" * 16
    assert updated.pubkey == b"p" * 65
    assert updated.cert_serial == "cert-password-change"
    assert cache.get(user.id, datetime.now(timezone.utc)) is None
    assert [name for name, _ in engine.calls] == [
        "sm3_hash_password",
        "constant_time_equal",
        "hkdf_sm3",
        "sm4_gcm_decrypt",
        "sm3_hash_password",
        "hkdf_sm3",
        "sm4_gcm_encrypt",
    ]


def test_wrong_current_password_does_not_decrypt_or_update(db_session) -> None:
    user = make_user()
    db_session.add(user)
    db_session.commit()
    engine = MockCryptoEngine()
    engine.set_result("sm3_hash_password", b"derived-hash")
    engine.set_result("constant_time_equal", False)

    with pytest.raises(PasswordChangeError) as raised:
        PasswordChangeService(db_session, engine, PrivateKeyUnlockCache()).change(
            user.id, "Wrong123", "NewPassword123"
        )

    assert raised.value.code == "INVALID_CREDENTIALS"
    assert [name for name, _ in engine.calls] == [
        "sm3_hash_password",
        "constant_time_equal",
    ]
    db_session.expire_all()
    unchanged = db_session.get(User, user.id)
    assert unchanged is not None and unchanged.salt_a == b"old-salt-a"


def test_crypto_failure_rolls_back_all_user_fields(db_session, monkeypatch) -> None:
    user = make_user()
    db_session.add(user)
    db_session.commit()
    engine = MockCryptoEngine()
    engine.set_result("sm3_hash_password", b"derived-hash")
    engine.set_result("constant_time_equal", True)
    engine.set_result("hkdf_sm3", b"k" * 16)
    engine.set_error("sm4_gcm_decrypt", CryptoBridgeError(BridgeErrorCode.INTEGRITY_FAILED))

    with pytest.raises(PasswordChangeError) as raised:
        PasswordChangeService(db_session, engine, PrivateKeyUnlockCache()).change(
            user.id, "Current123", "NewPassword123"
        )

    assert raised.value.code == "CRYPTO_ERROR"
    db_session.expire_all()
    unchanged = db_session.get(User, user.id)
    assert unchanged is not None
    assert unchanged.salt_a == b"old-salt-a"
    assert unchanged.salt_k == b"old-salt-k"
    assert unchanged.enc_sk.startswith(b"v1" + b"n")


@pytest.mark.parametrize("operation", ["hkdf_sm3", "sm4_gcm_encrypt"])
def test_new_key_material_failure_rolls_back_and_does_not_invalidate_cache(
    db_session, monkeypatch, operation: str
) -> None:
    user = make_user()
    db_session.add(user)
    db_session.commit()
    engine = MockCryptoEngine()
    configure_success_engine(engine)
    if operation == "hkdf_sm3":
        original_hkdf = engine.hkdf_sm3
        calls = 0

        def fail_on_new_hkdf(ikm, salt, info, length):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE)
            return original_hkdf(ikm, salt, info, length)

        engine.hkdf_sm3 = fail_on_new_hkdf
    else:
        engine.set_error(operation, CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))
    salt_values = iter((b"z" * 32, b"y" * 32))
    monkeypatch.setattr(
        "app.services.password_change.secrets.token_bytes", lambda _: next(salt_values)
    )
    cache = PrivateKeyUnlockCache()
    cache.put(
        user.id,
        b"cached-private-key",
        datetime.now(timezone.utc) + timedelta(minutes=15),
    )

    with pytest.raises(PasswordChangeError) as raised:
        PasswordChangeService(db_session, engine, cache).change(
            user.id, "Current123", "NewPassword123"
        )

    assert raised.value.code == "PROVIDER_UNAVAILABLE"
    db_session.expire_all()
    unchanged = db_session.get(User, user.id)
    assert unchanged is not None and unchanged.enc_sk.startswith(b"v1" + b"n")
    assert cache.get(user.id, datetime.now(timezone.utc)) == b"cached-private-key"


def test_cache_invalidation_failure_rolls_back_user_update(db_session, monkeypatch) -> None:
    class FailingCache:
        def delete(self, user_id: str) -> None:
            del user_id
            raise RuntimeError("cache failure")

    user = make_user()
    db_session.add(user)
    db_session.commit()
    engine = MockCryptoEngine()
    configure_success_engine(engine)
    salt_values = iter((b"new-salt-a", b"new-salt-k"))
    monkeypatch.setattr(
        "app.services.password_change.secrets.token_bytes",
        lambda _: next(salt_values),
    )

    with pytest.raises(PasswordChangeError) as raised:
        PasswordChangeService(db_session, engine, FailingCache()).change(
            user.id, "Current123", "NewPassword123"
        )

    assert raised.value.code == "INTERNAL_ERROR"
    db_session.expire_all()
    unchanged = db_session.get(User, user.id)
    assert unchanged is not None and unchanged.salt_a == b"old-salt-a"


def test_new_password_policy_is_checked_before_private_key_operations(db_session) -> None:
    user = make_user()
    db_session.add(user)
    db_session.commit()
    engine = MockCryptoEngine()

    with pytest.raises(PasswordChangeError) as raised:
        PasswordChangeService(db_session, engine, PrivateKeyUnlockCache()).change(
            user.id, "Current123", "weak"
        )

    assert raised.value.code == "VALIDATION_ERROR"
    assert engine.calls == ()


def test_password_change_errors_do_not_include_sensitive_inputs(db_session) -> None:
    with pytest.raises(PasswordChangeError) as raised:
        PasswordChangeService(
            db_session, MockCryptoEngine(), PrivateKeyUnlockCache()
        ).change("missing-user", "Current123", "NewPassword123")

    assert "Current123" not in str(raised.value)
    assert "NewPassword123" not in str(raised.value)
