from datetime import datetime, timedelta, timezone
import uuid

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.models.drop import Drop
from app.models.user import User


def _create_sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_drop_model_has_cooldown_fields_with_defaults() -> None:
    session = _create_sqlite_session()

    owner = User(id=str(uuid.uuid4()), email="owner@campus.edu", role="student", status="active")
    recipient = User(id=str(uuid.uuid4()), email="recv@campus.edu", role="student", status="active")
    session.add_all([owner, recipient])
    session.commit()

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=owner.id,
        recipient_user_id=recipient.id,
        link_code_hash=b"\x01" * 32,
        kind="text",
        envelope_version=1,
        ciphertext=b"enc",
        nonce=b"\x02" * 12,
        tag=b"\x03" * 16,
        enc_key_sm2=b"\x04" * 96,
        sender_signature=b"\x05" * 64,
        sender_certificate_der=b"\x30\x82\x01\x00" + b"\x06" * 50,
        sender_cert_serial="CERT-001",
        recipient_sm2_fingerprint=b"\x07" * 32,
        access_code_hash=b"\x08" * 32,
        ttl_policy="hours_24",
        burn_after_read=False,
        content_size=10,
        pqc_mode=False,
    )
    session.add(drop)
    session.commit()

    loaded = session.get(Drop, drop.id)
    assert loaded is not None
    assert loaded.failed_attempts == 0
    assert loaded.cooldown_until is None
    assert loaded.status == "available"


def test_drop_model_status_cooling_down_and_cooldown_until() -> None:
    session = _create_sqlite_session()

    owner = User(id=str(uuid.uuid4()), email="owner@campus.edu", role="student", status="active")
    recipient = User(id=str(uuid.uuid4()), email="recv@campus.edu", role="student", status="active")
    session.add_all([owner, recipient])
    session.commit()

    now_utc = datetime.now(timezone.utc)
    cooldown_time = now_utc + timedelta(minutes=10)

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=owner.id,
        recipient_user_id=recipient.id,
        link_code_hash=b"\x02" * 32,
        kind="text",
        envelope_version=1,
        ciphertext=b"enc",
        nonce=b"\x02" * 12,
        tag=b"\x03" * 16,
        enc_key_sm2=b"\x04" * 96,
        sender_signature=b"\x05" * 64,
        sender_certificate_der=b"\x30\x82\x01\x00" + b"\x06" * 50,
        sender_cert_serial="CERT-002",
        recipient_sm2_fingerprint=b"\x07" * 32,
        access_code_hash=b"\x08" * 32,
        ttl_policy="hours_24",
        burn_after_read=False,
        content_size=10,
        pqc_mode=False,
        status="cooling_down",
        failed_attempts=5,
        cooldown_until=cooldown_time,
    )
    session.add(drop)
    session.commit()

    loaded = session.get(Drop, drop.id)
    assert loaded is not None
    assert loaded.status == "cooling_down"
    assert loaded.failed_attempts == 5
    assert loaded.cooldown_until is not None


def test_drop_model_failed_attempts_check_constraint() -> None:
    session = _create_sqlite_session()

    owner = User(id=str(uuid.uuid4()), email="owner@campus.edu", role="student", status="active")
    recipient = User(id=str(uuid.uuid4()), email="recv@campus.edu", role="student", status="active")
    session.add_all([owner, recipient])
    session.commit()

    # Case 1: failed_attempts > 5 must fail
    drop_overflow = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=owner.id,
        recipient_user_id=recipient.id,
        link_code_hash=b"\x03" * 32,
        kind="text",
        envelope_version=1,
        ciphertext=b"enc",
        nonce=b"\x02" * 12,
        tag=b"\x03" * 16,
        enc_key_sm2=b"\x04" * 96,
        sender_signature=b"\x05" * 64,
        sender_certificate_der=b"\x30\x82\x01\x00" + b"\x06" * 50,
        sender_cert_serial="CERT-003",
        recipient_sm2_fingerprint=b"\x07" * 32,
        access_code_hash=b"\x08" * 32,
        ttl_policy="hours_24",
        burn_after_read=False,
        content_size=10,
        pqc_mode=False,
        failed_attempts=6,
    )
    session.add(drop_overflow)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

    # Case 2: failed_attempts < 0 must fail
    drop_underflow = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=owner.id,
        recipient_user_id=recipient.id,
        link_code_hash=b"\x04" * 32,
        kind="text",
        envelope_version=1,
        ciphertext=b"enc",
        nonce=b"\x02" * 12,
        tag=b"\x03" * 16,
        enc_key_sm2=b"\x04" * 96,
        sender_signature=b"\x05" * 64,
        sender_certificate_der=b"\x30\x82\x01\x00" + b"\x06" * 50,
        sender_cert_serial="CERT-004",
        recipient_sm2_fingerprint=b"\x07" * 32,
        access_code_hash=b"\x08" * 32,
        ttl_policy="hours_24",
        burn_after_read=False,
        content_size=10,
        pqc_mode=False,
        failed_attempts=-1,
    )
    session.add(drop_underflow)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_drop_model_has_no_sensitive_fields() -> None:
    drop_cols = {c.name for c in inspect(Drop).columns}
    prohibited = {"access_code", "access_password", "plaintext", "private_key", "session_key", "kek"}
    assert not (drop_cols & prohibited)
    assert "failed_attempts" in drop_cols
    assert "cooldown_until" in drop_cols


def test_init_database_upgrades_legacy_drops_columns(tmp_path) -> None:
    from sqlalchemy import text
    from app.db.session import create_db_engine, init_database

    db_path = tmp_path / "legacy_drops.db"
    engine = create_db_engine(f"sqlite+pysqlite:///{db_path.as_posix()}")

    # Create users and legacy drops table without failed_attempts and cooldown_until
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE users (
                id VARCHAR(36) PRIMARY KEY, email VARCHAR(254), role VARCHAR(16), status VARCHAR(32)
            )
        """))
        conn.execute(text("""
            CREATE TABLE drops (
                id VARCHAR(36) PRIMARY KEY,
                owner_user_id VARCHAR(36) NOT NULL,
                recipient_user_id VARCHAR(36) NOT NULL,
                link_code_hash BLOB NOT NULL,
                kind VARCHAR(8) NOT NULL,
                envelope_version INTEGER NOT NULL,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                tag BLOB NOT NULL,
                enc_key_sm2 BLOB NOT NULL,
                enc_key_mlkem BLOB,
                sender_signature BLOB NOT NULL,
                sender_certificate_der BLOB NOT NULL,
                sender_cert_serial VARCHAR(128) NOT NULL,
                recipient_sm2_fingerprint BLOB NOT NULL,
                recipient_mlkem_fingerprint BLOB,
                access_code_hash BLOB NOT NULL,
                access_factor_salt BLOB,
                ttl_policy VARCHAR(16) NOT NULL,
                burn_after_read BOOLEAN NOT NULL,
                expires_at DATETIME,
                filename VARCHAR(255),
                content_size INTEGER NOT NULL,
                pqc_mode BOOLEAN NOT NULL,
                status VARCHAR(16) NOT NULL,
                created_at DATETIME NOT NULL
            )
        """))
        conn.execute(text("""
            INSERT INTO drops VALUES (
                'legacy-drop-001', 'u1', 'u2', X'01', 'text', 1, X'02', X'03', X'04', X'05',
                NULL, X'06', X'07', 'CERT-1', X'08', NULL, X'09', NULL, 'hours_24',
                0, NULL, NULL, 100, 0, 'available', '2026-09-09 10:00:00'
            )
        """))

    init_database(engine)

    columns = {col["name"]: col for col in inspect(engine).get_columns("drops")}
    assert "failed_attempts" in columns
    assert "cooldown_until" in columns

    with engine.connect() as conn:
        row = conn.execute(text("SELECT id, failed_attempts, cooldown_until FROM drops WHERE id = 'legacy-drop-001'")).mappings().one()
        assert row["id"] == "legacy-drop-001"
        assert row["failed_attempts"] == 0
        assert row["cooldown_until"] is None

    engine.dispose()

