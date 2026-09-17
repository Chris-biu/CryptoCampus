import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import text
from sqlalchemy import inspect

from app.db.session import create_db_engine, create_session_factory, init_database


def test_sqlite_engine_enables_foreign_keys(tmp_path) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'foreign_keys.db').as_posix()}"
    engine = create_db_engine(database_url)

    with engine.connect() as connection:
        assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1

    engine.dispose()


def test_sqlite_engine_waits_for_concurrent_writers(tmp_path) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'busy-timeout.db').as_posix()}"
    engine = create_db_engine(database_url)

    with engine.connect() as connection:
        assert connection.execute(text("PRAGMA busy_timeout")).scalar_one() == 30_000

    engine.dispose()


def test_session_factory_executes_query(tmp_path) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'session.db').as_posix()}"
    engine = create_db_engine(database_url)
    session_factory = create_session_factory(engine)

    with session_factory() as session:
        assert session.execute(text("SELECT 1")).scalar_one() == 1

    engine.dispose()


def test_init_database_creates_core_and_pki_tables(tmp_path) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'initialized.db').as_posix()}"
    engine = create_db_engine(database_url)

    init_database(engine)

    assert {
        "users",
        "sessions",
        "credential_ledger",
        "consumed_sn",
        "revocation_log",
        "audit_log",
    } <= set(inspect(engine).get_table_names())
    assert {"certificates", "crl_snapshots"} <= set(inspect(engine).get_table_names())
    engine.dispose()


def test_init_database_upgrades_legacy_user_secret_columns_to_nullable(tmp_path) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'legacy-users.db').as_posix()}"
    engine = create_db_engine(database_url)
    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE users (
                id VARCHAR(36) PRIMARY KEY, email VARCHAR(254) NOT NULL UNIQUE,
                role VARCHAR(16) NOT NULL, status VARCHAR(32) NOT NULL,
                salt_a BLOB NOT NULL, auth_hash BLOB NOT NULL, salt_k BLOB NOT NULL,
                enc_sk BLOB NOT NULL, pubkey BLOB NOT NULL,
                cert_serial VARCHAR(128) NOT NULL UNIQUE,
                pqc_pubkey BLOB, enc_pqc_sk BLOB,
                failed_login_count INTEGER NOT NULL, locked_until DATETIME,
                created_at DATETIME NOT NULL
            )
        """))
        connection.execute(text("""
            INSERT INTO users VALUES (
                '00000000-0000-0000-0000-000000000001', 'legacy@campus.edu', 'student', 'active',
                X'61', X'68', X'6B', X'65', X'70', 'legacy-cert', NULL, NULL, 0, NULL, '2026-09-07 00:00:00'
            )
        """))

    init_database(engine)

    columns = {column["name"]: column for column in inspect(engine).get_columns("users")}
    assert all(columns[name]["nullable"] for name in ("email", "salt_a", "auth_hash", "salt_k", "enc_sk", "pubkey", "cert_serial"))
    with engine.connect() as connection:
        assert connection.execute(text("SELECT email FROM users")).scalar_one() == "legacy@campus.edu"
    engine.dispose()


def test_init_db_module_creates_core_and_pki_tables_in_configured_database(tmp_path) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'command.db').as_posix()}"
    environment = os.environ | {"CRYPTOCAMPUS_DATABASE_URL": database_url}
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [sys.executable, "-m", "app.db.init_db"],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    engine = create_db_engine(database_url)
    assert {
        "users",
        "sessions",
        "credential_ledger",
        "consumed_sn",
        "revocation_log",
        "audit_log",
    } <= set(inspect(engine).get_table_names())
    assert {"certificates", "crl_snapshots"} <= set(inspect(engine).get_table_names())
    engine.dispose()
