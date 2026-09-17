from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.db.session import init_database
from app.models.certificate import CertificateRecord, CrlSnapshot
from app.models.user import User


def make_user(email: str, cert_serial: str) -> User:
    return User(
        email=email,
        salt_a=b"authentication-salt",
        auth_hash=b"authentication-hash",
        salt_k=b"key-encryption-salt",
        enc_sk=b"encrypted-private-key",
        pubkey=b"public-key",
        cert_serial=cert_serial,
    )


def test_pki_tables_preserve_private_key_boundary(db_engine) -> None:
    init_database(db_engine)
    inspector = inspect(db_engine)
    certificate_columns = {column["name"] for column in inspector.get_columns("certificates")}
    crl_columns = {column["name"] for column in inspector.get_columns("crl_snapshots")}

    assert "private_key" not in certificate_columns
    assert "ca_private_key" not in certificate_columns
    assert "kek" not in certificate_columns
    assert "private_key" not in crl_columns


def test_certificate_rejects_invalid_revocation_state(db_session) -> None:
    user = make_user("pki@example.edu", "user-current")
    db_session.add(user)
    db_session.commit()
    db_session.add(
        CertificateRecord(
            serial="01",
            subject_user_id=user.id,
            issuer_serial="ca-1",
            kind="user_identity",
            certificate_der=b"certificate",
            key_usage="digitalSignature,keyEncipherment,keyAgreement",
            not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
            status="revoked",
        )
    )

    with pytest.raises(IntegrityError):
        db_session.commit()


def test_crl_snapshot_requires_increasing_times(db_session) -> None:
    db_session.add(
        CrlSnapshot(
            issuer_serial="ca-1",
            crl_der=b"crl",
            this_update=datetime(2026, 1, 1, tzinfo=timezone.utc),
            next_update=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    )

    with pytest.raises(IntegrityError):
        db_session.commit()


def test_certificate_rejects_missing_subject_user(db_session) -> None:
    db_session.add(
        CertificateRecord(
            serial="missing-user-cert",
            subject_user_id="missing-user",
            issuer_serial="ca-1",
            kind="user_identity",
            certificate_der=b"certificate",
            key_usage="digitalSignature",
            not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
            status="active",
        )
    )

    with pytest.raises(IntegrityError):
        db_session.commit()


def test_deleting_certificate_subject_user_is_restricted(db_session) -> None:
    user = make_user("certificate-owner@example.edu", "certificate-owner")
    db_session.add(user)
    db_session.commit()
    db_session.add(
        CertificateRecord(
            serial="owned-cert",
            subject_user_id=user.id,
            issuer_serial="ca-1",
            kind="user_identity",
            certificate_der=b"certificate",
            key_usage="digitalSignature",
            not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
            status="active",
        )
    )
    db_session.commit()

    db_session.delete(user)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
