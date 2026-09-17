from datetime import datetime, timedelta, timezone

import pytest

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SignedCertificate, Sm2KeyPair, Sm4GcmCiphertext
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.pki.types import IssuedUserCertificate, USER_IDENTITY_KEY_USAGE
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.keyring import KeyringError, KeyringService


class RecordingPlatformCA:
    def __init__(self, session, *, fail_revoke: bool = False) -> None:
        self.session = session
        self.fail_revoke = fail_revoke
        self.revoked_serials: list[str] = []

    def issue_user_certificate(self, user_id, role, private_key, public_key, not_before, not_after):
        del private_key, public_key, not_before, not_after
        return IssuedUserCertificate(
            user_id,
            role,
            "platform-ca",
            USER_IDENTITY_KEY_USAGE,
            SignedCertificate(b"new-certificate", "new-identity-cert", 1, 2_000_000_000),
        )

    def record_issued_certificate(self, user, issued):
        record = CertificateRecord(
            serial=issued.certificate.serial,
            subject_user_id=user.id,
            issuer_serial=issued.issuer_serial,
            kind="user_identity",
            certificate_der=issued.certificate.der,
            key_usage=",".join(issued.key_usage),
            not_before=datetime(2026, 9, 7, tzinfo=timezone.utc),
            not_after=datetime(2027, 9, 7, tzinfo=timezone.utc),
            status="active",
        )
        self.session.add(record)
        user.cert_serial = record.serial
        self.session.flush()
        return record

    def revoke_certificate(self, serial, reason, operator_user_id, this_update, next_update):
        del reason, operator_user_id, this_update, next_update
        self.revoked_serials.append(serial)
        if self.fail_revoke:
            raise RuntimeError("revoke failed")
        self.session.get(CertificateRecord, serial).status = "revoked"
        self.session.get(CertificateRecord, serial).revoked_at = datetime(2026, 9, 7, tzinfo=timezone.utc)
        self.session.get(CertificateRecord, serial).revocation_reason = "key_rotation"
        self.session.flush()


def _create_user_with_certificate(db_session):
    now = datetime(2026, 9, 7, tzinfo=timezone.utc)
    user = User(
        email="rotate@campus.edu",
        role="student",
        salt_a=b"a" * 32,
        auth_hash=b"h" * 32,
        salt_k=b"k" * 32,
        enc_sk=b"v1" + b"n" * 12 + b"old-ciphertext" + b"t" * 16,
        pubkey=b"\x04" + b"p" * 64,
        cert_serial="old-identity-cert",
    )
    db_session.add(user)
    db_session.flush()
    db_session.add(
        CertificateRecord(
            serial="old-identity-cert",
            subject_user_id=user.id,
            issuer_serial="platform-ca",
            kind="user_identity",
            certificate_der=b"old-certificate",
            key_usage="digitalSignature,keyEncipherment,keyAgreement",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=365),
            status="active",
        )
    )
    db_session.commit()
    return user, now


def _rotation_engine() -> MockCryptoEngine:
    engine = MockCryptoEngine()
    engine.set_result("sm3_hash_password", b"computed-auth")
    engine.set_result("constant_time_equal", True)
    engine.set_result("sm4_gcm_decrypt", b"o" * 32)
    engine.set_result("csr_create", b"validated-current-key")
    engine.set_result("sm2_generate_keypair", Sm2KeyPair(b"n" * 32, b"\x04" + b"q" * 64))
    engine.set_result("hkdf_sm3", b"b" * 16)
    engine.set_result(
        "sm4_gcm_encrypt",
        Sm4GcmCiphertext(ciphertext=b"new-ciphertext", nonce=b"x" * 12, tag=b"y" * 16),
    )
    engine.set_result("sm3_digest", b"f" * 32)
    return engine


def test_rotation_replaces_identity_revokes_old_certificate_and_clears_cache(db_session) -> None:
    user, now = _create_user_with_certificate(db_session)
    old_public_key = user.pubkey
    cache = PrivateKeyUnlockCache()
    cache.put(user.id, b"o" * 32, now + timedelta(minutes=15))
    platform_ca = RecordingPlatformCA(db_session)

    result = KeyringService(
        db_session, _rotation_engine(), cache, platform_ca=platform_ca
    ).rotate(user.id, "CorrectPassword1", "a" * 16, now)

    db_session.refresh(user)
    assert user.pubkey != old_public_key
    assert user.cert_serial == "new-identity-cert"
    assert db_session.get(CertificateRecord, "old-identity-cert").status == "revoked"
    assert db_session.get(CertificateRecord, "new-identity-cert").status == "active"
    assert platform_ca.revoked_serials == ["old-identity-cert"]
    assert cache.get(user.id, now) is None
    assert result.items[1].status == "active"


def test_rotation_failure_keeps_old_keyring_and_cache_usable(db_session) -> None:
    user, now = _create_user_with_certificate(db_session)
    original_public_key = user.pubkey
    original_certificate = user.cert_serial
    cache = PrivateKeyUnlockCache()
    cache.put(user.id, b"o" * 32, now + timedelta(minutes=15))

    with pytest.raises(KeyringError) as raised:
        KeyringService(
            db_session,
            _rotation_engine(),
            cache,
            platform_ca=RecordingPlatformCA(db_session, fail_revoke=True),
        ).rotate(user.id, "CorrectPassword1", "b" * 16, now)

    db_session.rollback()
    db_session.refresh(user)
    assert raised.value.code == "internal"
    assert user.pubkey == original_public_key
    assert user.cert_serial == original_certificate
    assert db_session.get(CertificateRecord, "old-identity-cert").status == "active"
    assert db_session.get(CertificateRecord, "new-identity-cert") is None
    assert cache.get(user.id, now) == b"o" * 32
