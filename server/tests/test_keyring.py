from datetime import datetime, timedelta, timezone

import pytest

from app.crypto.mock import MockCryptoEngine
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.keyring import KeyringService
from app.services.keyring import KeyringError


def test_summary_exposes_only_public_fingerprints_certificate_state_and_cache_expiry(db_session) -> None:
    now = datetime(2026, 9, 7, tzinfo=timezone.utc)
    user = User(
        email="keyring@campus.edu",
        role="student",
        salt_a=b"a" * 32,
        auth_hash=b"h" * 32,
        salt_k=b"k" * 32,
        enc_sk=b"v1" + b"n" * 12 + b"ciphertext" + b"t" * 16,
        pubkey=b"\x04" + b"p" * 64,
        cert_serial="keyring-cert",
    )
    certificate = CertificateRecord(
        serial="keyring-cert",
        subject_user_id=user.id,
        issuer_serial="platform-ca",
        kind="user_identity",
        certificate_der=b"certificate",
        key_usage="digitalSignature,keyEncipherment,keyAgreement",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        status="active",
    )
    db_session.add(user)
    db_session.flush()
    certificate.subject_user_id = user.id
    db_session.add(certificate)
    db_session.commit()

    engine = MockCryptoEngine()
    engine.set_result("sm3_digest", b"f" * 32)
    cache = PrivateKeyUnlockCache()
    cache.put(user.id, b"x" * 32, now + timedelta(minutes=15))

    summary = KeyringService(db_session, engine, cache).summary(user.id, now)

    assert [item.kind for item in summary.items] == ["sm2_identity", "certificate"]
    assert summary.items[0].algorithm == "SM2"
    assert summary.items[1].status == "active"
    assert summary.unlocked_until == now + timedelta(minutes=15)
    rendered = summary.model_dump_json().lower()
    assert "ciphertext" not in rendered
    assert "salt" not in rendered
    assert "private" not in rendered


def test_summary_reports_missing_certificate_without_querying_null_primary_key(db_session) -> None:
    now = datetime(2026, 9, 7, tzinfo=timezone.utc)
    user = User(
        email="no-certificate@campus.edu",
        role="student",
        salt_a=b"a" * 32,
        auth_hash=b"h" * 32,
        salt_k=b"k" * 32,
        enc_sk=b"v1" + b"n" * 12 + b"ciphertext" + b"t" * 16,
        pubkey=b"\x04" + b"p" * 64,
        cert_serial=None,
    )
    db_session.add(user)
    db_session.commit()

    with pytest.raises(KeyringError) as raised:
        KeyringService(
            db_session, MockCryptoEngine(), PrivateKeyUnlockCache()
        ).summary(user.id, now)

    assert raised.value.code == "certificate_missing"


def test_export_rejects_wrong_current_password_before_creating_backup(db_session) -> None:
    user = User(
        email="export@campus.edu",
        role="student",
        salt_a=b"a" * 32,
        auth_hash=b"h" * 32,
        salt_k=b"k" * 32,
        enc_sk=b"v1" + b"n" * 12 + b"ciphertext" + b"t" * 16,
        pubkey=b"\x04" + b"p" * 64,
        cert_serial="export-cert",
    )
    db_session.add(user)
    db_session.flush()
    db_session.add(
        CertificateRecord(
            serial="export-cert",
            subject_user_id=user.id,
            issuer_serial="platform-ca",
            kind="user_identity",
            certificate_der=b"certificate",
            key_usage="digitalSignature,keyEncipherment,keyAgreement",
            not_before=datetime(2026, 9, 6, tzinfo=timezone.utc),
            not_after=datetime(2027, 9, 7, tzinfo=timezone.utc),
            status="active",
        )
    )
    db_session.commit()
    engine = MockCryptoEngine()
    engine.set_result("sm3_hash_password", b"different-hash")
    engine.set_result("constant_time_equal", False)

    with pytest.raises(KeyringError) as raised:
        KeyringService(db_session, engine, PrivateKeyUnlockCache()).export(
            user.id, "WrongPassword1"
        )

    assert raised.value.code == "credentials_invalid"
    assert not [call for call in engine.calls if call[0] == "sm4_gcm_encrypt"]
