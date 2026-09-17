from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.db.revocation_upgrade import RevocationUpgradeError, upgrade_revocation_indexes
from app.db.session import create_db_engine, create_session_factory, init_database
from app.models.audit import RevocationLog
from app.models.user import User
from app.services.revocation_log import GENESIS_HASH


def make_operator_user(email: str = "operator@campus.edu", cert_serial: str = "operator-cert") -> User:
    return User(
        email=email,
        role="admin",
        status="active",
        salt_a=b"auth-salt",
        auth_hash=b"auth-hash",
        salt_k=b"key-salt",
        enc_sk=b"enc-sk",
        pubkey=b"pubkey",
        cert_serial=cert_serial,
    )


def test_revocation_log_columns_preserve_strict_schema(db_engine) -> None:
    init_database(db_engine)
    inspector = inspect(db_engine)
    columns = {col["name"]: col for col in inspector.get_columns("revocation_log")}

    assert set(columns.keys()) == {"hash_curr", "hash_prev", "sn", "reason", "operator", "ts"}
    assert columns["hash_prev"]["nullable"] is True
    assert columns["sn"]["nullable"] is False


def test_revocation_log_rejects_duplicate_sn(db_session) -> None:
    operator = make_operator_user("op1@campus.edu", "cert-op-1")
    db_session.add(operator)
    db_session.commit()

    log1 = RevocationLog(
        hash_curr=b"1" * 32,
        hash_prev=GENESIS_HASH,
        sn=b"duplicate-sn-test",
        reason="first revocation",
        operator=operator.id,
    )
    db_session.add(log1)
    db_session.commit()

    log2 = RevocationLog(
        hash_curr=b"2" * 32,
        hash_prev=b"1" * 32,
        sn=b"duplicate-sn-test",
        reason="second revocation with same sn",
        operator=operator.id,
    )
    db_session.add(log2)

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_revocation_log_rejects_duplicate_hash_prev(db_session) -> None:
    operator = make_operator_user("op2@campus.edu", "cert-op-2")
    db_session.add(operator)
    db_session.commit()

    log1 = RevocationLog(
        hash_curr=b"1" * 32,
        hash_prev=GENESIS_HASH,
        sn=b"sn-entry-001",
        reason="genesis branch 1",
        operator=operator.id,
    )
    db_session.add(log1)
    db_session.commit()

    # Attempt to fork from GENESIS_HASH
    log2 = RevocationLog(
        hash_curr=b"2" * 32,
        hash_prev=GENESIS_HASH,
        sn=b"sn-entry-002",
        reason="genesis branch 2 (fork attempt)",
        operator=operator.id,
    )
    db_session.add(log2)

    with pytest.raises(IntegrityError):
        db_session.commit()

    db_session.rollback()


def test_revocation_log_accepts_valid_distinct_records(db_session) -> None:
    operator = make_operator_user("op3@campus.edu", "cert-op-3")
    db_session.add(operator)
    db_session.commit()

    log1 = RevocationLog(
        hash_curr=b"1" * 32,
        hash_prev=GENESIS_HASH,
        sn=b"sn-entry-101",
        reason="genesis entry",
        operator=operator.id,
    )
    log2 = RevocationLog(
        hash_curr=b"2" * 32,
        hash_prev=b"1" * 32,
        sn=b"sn-entry-102",
        reason="second entry",
        operator=operator.id,
    )
    db_session.add_all([log1, log2])
    db_session.commit()

    assert db_session.query(RevocationLog).count() == 2


def test_upgrade_legacy_database_creates_unique_indexes_and_is_idempotent(tmp_path) -> None:
    db_file = tmp_path / "legacy.db"
    db_url = f"sqlite+pysqlite:///{db_file.as_posix()}"
    engine = create_db_engine(db_url)

    # Create table manually without unique constraints/indexes
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE revocation_log (
                hash_curr BLOB PRIMARY KEY,
                hash_prev BLOB,
                sn BLOB NOT NULL,
                reason VARCHAR(500) NOT NULL,
                operator VARCHAR(36) NOT NULL,
                ts DATETIME NOT NULL
            )
        """))
        conn.execute(text("""
            INSERT INTO revocation_log (hash_curr, hash_prev, sn, reason, operator, ts)
            VALUES (X'0101', X'0000', X'AAAA', 'valid 1', 'user1', '2026-09-09 12:00:00')
        """))

    # Upgrade
    upgrade_revocation_indexes(engine)

    # Verify unique indexes were created
    inspector = inspect(engine)
    index_names = {idx["name"] for idx in inspector.get_indexes("revocation_log")}
    assert "uq_revocation_log_sn" in index_names
    assert "uq_revocation_log_hash_prev" in index_names

    # Duplicate sn is rejected after upgrade
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO revocation_log (hash_curr, hash_prev, sn, reason, operator, ts)
                VALUES (X'0202', X'1111', X'AAAA', 'dup sn', 'user1', '2026-09-09 12:01:00')
            """))

    # Duplicate hash_prev is rejected after upgrade
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO revocation_log (hash_curr, hash_prev, sn, reason, operator, ts)
                VALUES (X'0303', X'0000', X'BBBB', 'dup prev', 'user1', '2026-09-09 12:02:00')
            """))

    # Idempotent call raises no errors
    upgrade_revocation_indexes(engine)
    engine.dispose()


def test_upgrade_blocked_by_duplicate_sn(tmp_path) -> None:
    db_file = tmp_path / "dup_sn.db"
    db_url = f"sqlite+pysqlite:///{db_file.as_posix()}"
    engine = create_db_engine(db_url)

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE revocation_log (
                hash_curr BLOB PRIMARY KEY,
                hash_prev BLOB,
                sn BLOB NOT NULL,
                reason VARCHAR(500) NOT NULL,
                operator VARCHAR(36) NOT NULL,
                ts DATETIME NOT NULL
            )
        """))
        conn.execute(text("""
            INSERT INTO revocation_log (hash_curr, hash_prev, sn, reason, operator, ts)
            VALUES 
                (X'0101', X'0001', X'AAAA', 'reason 1', 'user1', '2026-09-09 12:00:00'),
                (X'0202', X'0002', X'AAAA', 'reason 2', 'user1', '2026-09-09 12:01:00')
        """))

    with pytest.raises(RevocationUpgradeError) as exc_info:
        upgrade_revocation_indexes(engine)

    assert "sn" in str(exc_info.value).lower()

    # Verify original rows and data untouched
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT hash_curr, sn, reason FROM revocation_log ORDER BY hash_curr")
        ).fetchall()
        assert len(rows) == 2
        assert rows[0][1] == b"\xaa\xaa"
        assert rows[1][1] == b"\xaa\xaa"
        assert rows[0][2] == "reason 1"
        assert rows[1][2] == "reason 2"

    engine.dispose()


def test_upgrade_blocked_by_duplicate_hash_prev(tmp_path) -> None:
    db_file = tmp_path / "dup_prev.db"
    db_url = f"sqlite+pysqlite:///{db_file.as_posix()}"
    engine = create_db_engine(db_url)

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE revocation_log (
                hash_curr BLOB PRIMARY KEY,
                hash_prev BLOB,
                sn BLOB NOT NULL,
                reason VARCHAR(500) NOT NULL,
                operator VARCHAR(36) NOT NULL,
                ts DATETIME NOT NULL
            )
        """))
        conn.execute(text("""
            INSERT INTO revocation_log (hash_curr, hash_prev, sn, reason, operator, ts)
            VALUES 
                (X'0101', X'0000', X'AAAA', 'reason 1', 'user1', '2026-09-09 12:00:00'),
                (X'0202', X'0000', X'BBBB', 'reason 2', 'user1', '2026-09-09 12:01:00')
        """))

    with pytest.raises(RevocationUpgradeError) as exc_info:
        upgrade_revocation_indexes(engine)

    assert "hash_prev" in str(exc_info.value).lower()

    # Verify original rows and data untouched
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT hash_curr, hash_prev FROM revocation_log ORDER BY hash_curr")
        ).fetchall()
        assert len(rows) == 2
        assert rows[0][1] == b"\x00\x00"
        assert rows[1][1] == b"\x00\x00"

    engine.dispose()


def test_upgrade_noop_when_revocation_log_table_does_not_exist(tmp_path) -> None:
    db_file = tmp_path / "empty.db"
    db_url = f"sqlite+pysqlite:///{db_file.as_posix()}"
    engine = create_db_engine(db_url)

    # Table doesn't exist; should safely return without error
    upgrade_revocation_indexes(engine)
    engine.dispose()


def test_cli_upgrade_success_on_clean_database(tmp_path) -> None:
    db_file = tmp_path / "cli_clean.db"
    db_url = f"sqlite+pysqlite:///{db_file.as_posix()}"
    engine = create_db_engine(db_url)
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE revocation_log (
                hash_curr BLOB PRIMARY KEY,
                hash_prev BLOB,
                sn BLOB NOT NULL,
                reason VARCHAR(500) NOT NULL,
                operator VARCHAR(36) NOT NULL,
                ts DATETIME NOT NULL
            )
        """))
    engine.dispose()

    env = os.environ.copy()
    env["CRYPTOCAMPUS_DATABASE_URL"] = db_url
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [sys.executable, "-m", "app.db.revocation_upgrade"],
        cwd=project_root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"CLI failed: {result.stderr}"

    engine = create_db_engine(db_url)
    inspector = inspect(engine)
    index_names = {idx["name"] for idx in inspector.get_indexes("revocation_log")}
    assert "uq_revocation_log_sn" in index_names
    assert "uq_revocation_log_hash_prev" in index_names
    engine.dispose()


def test_cli_upgrade_failure_on_duplicate_data(tmp_path) -> None:
    db_file = tmp_path / "cli_error.db"
    db_url = f"sqlite+pysqlite:///{db_file.as_posix()}"
    engine = create_db_engine(db_url)
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE revocation_log (
                hash_curr BLOB PRIMARY KEY,
                hash_prev BLOB,
                sn BLOB NOT NULL,
                reason VARCHAR(500) NOT NULL,
                operator VARCHAR(36) NOT NULL,
                ts DATETIME NOT NULL
            )
        """))
        conn.execute(text("""
            INSERT INTO revocation_log (hash_curr, hash_prev, sn, reason, operator, ts)
            VALUES 
                (X'0101', X'0001', X'AAAA', 'reason 1', 'user1', '2026-09-09 12:00:00'),
                (X'0202', X'0002', X'AAAA', 'reason 2', 'user1', '2026-09-09 12:01:00')
        """))
    engine.dispose()

    env = os.environ.copy()
    env["CRYPTOCAMPUS_DATABASE_URL"] = db_url
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [sys.executable, "-m", "app.db.revocation_upgrade"],
        cwd=project_root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "Revocation upgrade" in result.stderr or "duplicate" in result.stderr.lower()
