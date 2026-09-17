from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.db.session import init_database
from app.models.audit import AuditLog, RevocationLog
from app.models.credential import ConsumedSN, CredentialLedger
from app.models.session import UserSession
from app.models.user import User


def make_user(email: str, cert_serial: str, **overrides) -> User:
    values = {
        "email": email,
        "salt_a": b"authentication-salt",
        "auth_hash": b"authentication-hash",
        "salt_k": b"key-encryption-salt",
        "enc_sk": b"encrypted-private-key",
        "pubkey": b"public-key",
        "cert_serial": cert_serial,
    }
    values.update(overrides)
    return User(**values)


def make_session(user_id: str, token_hash: bytes = b"refresh-token-hash") -> UserSession:
    return UserSession(
        user_id=user_id,
        device="test-device",
        ip="127.0.0.1",
        refresh_token_hash=token_hash,
        expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        last_active_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )


def test_user_and_session_columns_preserve_sensitive_data_boundaries(db_engine) -> None:
    init_database(db_engine)
    inspector = inspect(db_engine)
    user_columns = {column["name"] for column in inspector.get_columns("users")}
    session_columns = {column["name"] for column in inspector.get_columns("sessions")}

    assert user_columns == {
        "id",
        "email",
        "role",
        "status",
        "salt_a",
        "auth_hash",
        "salt_k",
        "enc_sk",
        "pubkey",
        "cert_serial",
        "pqc_pubkey",
        "enc_pqc_sk",
        "failed_login_count",
        "locked_until",
        "created_at",
    }
    assert session_columns == {
        "id",
        "user_id",
        "device",
        "ip",
        "refresh_token_hash",
        "expires_at",
        "last_active_at",
        "revoked",
    }
    assert "password" not in user_columns
    assert "kek" not in user_columns
    assert "private_key" not in user_columns
    assert "refresh_token" not in session_columns
    assert "refresh_token_hash" in session_columns


def test_users_reject_duplicate_email(db_session) -> None:
    db_session.add(make_user("student@example.edu", "cert-1"))
    db_session.commit()
    db_session.add(make_user("student@example.edu", "cert-2"))

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_users_reject_duplicate_certificate_serial(db_session) -> None:
    db_session.add(make_user("first@example.edu", "cert-1"))
    db_session.commit()
    db_session.add(make_user("second@example.edu", "cert-1"))

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_sessions_reject_missing_user(db_session) -> None:
    db_session.add(make_session("missing-user"))

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_sessions_reject_duplicate_refresh_token_hash(db_session) -> None:
    first_user = make_user("refresh-first@example.edu", "cert-refresh-first")
    second_user = make_user("refresh-second@example.edu", "cert-refresh-second")
    db_session.add_all([first_user, second_user])
    db_session.commit()
    db_session.add(make_session(first_user.id, b"same-refresh-token-hash"))
    db_session.commit()
    db_session.add(make_session(second_user.id, b"same-refresh-token-hash"))

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_deleting_user_cascades_sessions_and_ledger(db_session) -> None:
    user = make_user("cascade@example.edu", "cert-cascade")
    db_session.add(user)
    db_session.commit()
    db_session.add(make_session(user.id))
    db_session.add(
        CredentialLedger(
            user_id=user.id,
            service="hole_post",
            period="2026-09-02",
        )
    )
    db_session.commit()

    db_session.delete(user)
    db_session.commit()

    assert db_session.query(UserSession).count() == 0
    assert db_session.query(CredentialLedger).count() == 0


def test_users_require_pqc_keys_to_be_stored_together(db_session) -> None:
    db_session.add(
        make_user(
            "pqc@example.edu",
            "cert-pqc",
            pqc_pubkey=b"pqc-public-key",
        )
    )

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_users_reject_unknown_role(db_session) -> None:
    db_session.add(make_user("unknown-role@example.edu", "cert-role", role="guest"))

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_users_reject_unknown_status(db_session) -> None:
    db_session.add(make_user("unknown-status@example.edu", "cert-status", status="disabled"))

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_credential_tables_preserve_identity_and_anonymity_boundaries(db_engine) -> None:
    init_database(db_engine)
    inspector = inspect(db_engine)
    ledger_columns = {column["name"] for column in inspector.get_columns("credential_ledger")}
    consumed_columns = {column["name"] for column in inspector.get_columns("consumed_sn")}

    assert ledger_columns == {"id", "user_id", "service", "period", "issued_count"}
    assert consumed_columns == {"sn", "service", "consumed_at"}
    assert "sn" not in ledger_columns
    assert "signature" not in ledger_columns
    assert "blinding_factor" not in ledger_columns
    assert "user_id" not in consumed_columns


def test_credential_ledger_rejects_duplicate_user_service_period(db_session) -> None:
    user = make_user("ledger@example.edu", "cert-ledger")
    db_session.add(user)
    db_session.commit()
    db_session.add(CredentialLedger(user_id=user.id, service="hole_post", period="2026-09-02"))
    db_session.commit()
    db_session.add(CredentialLedger(user_id=user.id, service="hole_post", period="2026-09-02"))

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_credential_ledger_rejects_missing_user(db_session) -> None:
    db_session.add(
        CredentialLedger(
            user_id="missing-user",
            service="hole_post",
            period="2026-09-02",
        )
    )

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_credential_ledger_rejects_negative_issued_count(db_session) -> None:
    user = make_user("negative@example.edu", "cert-negative")
    db_session.add(user)
    db_session.commit()
    db_session.add(
        CredentialLedger(
            user_id=user.id,
            service="hole_post",
            period="2026-09-02",
            issued_count=-1,
        )
    )

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_consumed_sn_rejects_duplicate_serial_number_for_service(db_session) -> None:
    serial_number = b"credential-serial-number"
    db_session.add(ConsumedSN(sn=serial_number, service="hole_post"))
    db_session.commit()
    db_session.add(ConsumedSN(sn=serial_number, service="hole_post"))

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_audit_tables_store_only_hashes_and_metadata(db_engine) -> None:
    init_database(db_engine)
    inspector = inspect(db_engine)
    revocation_columns = {column["name"] for column in inspector.get_columns("revocation_log")}
    audit_columns = {column["name"] for column in inspector.get_columns("audit_log")}

    assert revocation_columns == {"hash_curr", "hash_prev", "sn", "reason", "operator", "ts"}
    assert audit_columns == {"id", "actor", "action", "target", "detail_hash", "ts"}
    assert AuditLog.__table__.c.detail_hash.type.__class__.__name__ == "LargeBinary"
    assert RevocationLog.__table__.c.hash_curr.type.__class__.__name__ == "LargeBinary"
    assert "detail_plaintext" not in audit_columns
    assert "content" not in audit_columns
    assert "private_key" not in audit_columns
    assert "kek" not in audit_columns


def test_revocation_log_rejects_missing_operator(db_session) -> None:
    db_session.add(
        RevocationLog(
            hash_curr=b"c" * 32,
            sn=b"revoked-credential-serial",
            reason="test revocation",
            operator="missing-operator",
        )
    )

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_audit_log_rejects_missing_actor(db_session) -> None:
    db_session.add(
        AuditLog(
            actor="missing-actor",
            action="account.freeze",
            target="user:missing",
            detail_hash=b"d" * 32,
        )
    )

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()
