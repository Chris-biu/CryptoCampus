from collections.abc import Generator

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.base import Base
from app.db.revocation_upgrade import upgrade_revocation_indexes


def create_db_engine(database_url: str) -> Engine:
    connect_args = (
        {"check_same_thread": False, "timeout": 30.0}
        if database_url.startswith("sqlite")
        else {}
    )
    engine_kwargs: dict[str, object] = {"connect_args": connect_args}
    if ":memory:" in database_url:
        from sqlalchemy.pool import StaticPool

        engine_kwargs["poolclass"] = StaticPool

    database_engine = create_engine(database_url, **engine_kwargs)

    if database_url.startswith("sqlite"):

        @event.listens_for(database_engine, "connect")
        def enable_sqlite_foreign_keys(dbapi_connection, connection_record) -> None:
            del connection_record
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            # File-backed SQLite serializes writes. Allow concurrent requests
            # to wait for the writer instead of surfacing a transient lock as
            # an application-level failure on slower CI and demo machines.
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    return database_engine


def create_session_factory(database_engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=database_engine, autoflush=False, expire_on_commit=False)


engine = create_db_engine(get_settings().database_url)
SessionLocal = create_session_factory(engine)


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session


def init_database(database_engine: Engine) -> None:
    import app.models

    Base.metadata.create_all(database_engine)
    _upgrade_sqlite_vote_scope_columns(database_engine)
    _upgrade_sqlite_user_deletion_columns(database_engine)
    _upgrade_sqlite_drops_cooldown_columns(database_engine)
    upgrade_revocation_indexes(database_engine)


def _upgrade_sqlite_drops_cooldown_columns(database_engine: Engine) -> None:
    if database_engine.dialect.name != "sqlite":
        return
    with database_engine.connect() as connection:
        table_info = connection.exec_driver_sql("PRAGMA table_info(drops)").mappings().all()
        if not table_info:
            return
        col_names = {col["name"] for col in table_info}
        if "failed_attempts" not in col_names:
            connection.exec_driver_sql("ALTER TABLE drops ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
        if "cooldown_until" not in col_names:
            connection.exec_driver_sql("ALTER TABLE drops ADD COLUMN cooldown_until DATETIME")


def _upgrade_sqlite_vote_scope_columns(database_engine: Engine) -> None:
    if database_engine.dialect.name != "sqlite":
        return
    with database_engine.begin() as connection:
        table_info = connection.exec_driver_sql("PRAGMA table_info(votes)").mappings().all()
        if not table_info:
            return
        col_names = {column["name"] for column in table_info}
        if "scope_id" not in col_names:
            connection.exec_driver_sql(
                "ALTER TABLE votes ADD COLUMN scope_id VARCHAR(36) "
                "REFERENCES vote_scope_units(id)"
            )
        if "settled_at" not in col_names:
            connection.exec_driver_sql("ALTER TABLE votes ADD COLUMN settled_at DATETIME")
        if "final_snapshot_id" not in col_names:
            connection.exec_driver_sql(
                "ALTER TABLE votes ADD COLUMN final_snapshot_id VARCHAR(36)"
            )
        connection.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_votes_scope_id ON votes (scope_id)")
        connection.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_votes_final_snapshot_id ON votes (final_snapshot_id)")

        snap_info = connection.exec_driver_sql("PRAGMA table_info(vote_result_snapshots)").mappings().all()
        if snap_info:
            snap_col_names = {c["name"] for c in snap_info}
            if "is_final" not in snap_col_names:
                connection.exec_driver_sql("ALTER TABLE vote_result_snapshots ADD COLUMN is_final BOOLEAN NOT NULL DEFAULT 0")
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS trg_votes_scope_insert
            BEFORE INSERT ON votes
            WHEN
                (NEW.scope = 'public' AND NEW.scope_id IS NOT NULL)
                OR
                (NEW.scope IN ('class', 'group') AND (
                    NEW.scope_id IS NULL
                    OR NOT EXISTS (
                        SELECT 1 FROM vote_scope_units
                        WHERE id = NEW.scope_id AND kind = NEW.scope AND active = 1
                    )
                ))
            BEGIN
                SELECT RAISE(ABORT, 'invalid vote scope binding');
            END
            """
        )
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS trg_votes_scope_update
            BEFORE UPDATE OF scope, scope_id ON votes
            WHEN
                (NEW.scope = 'public' AND NEW.scope_id IS NOT NULL)
                OR
                (NEW.scope IN ('class', 'group') AND (
                    NEW.scope_id IS NULL
                    OR NOT EXISTS (
                        SELECT 1 FROM vote_scope_units
                        WHERE id = NEW.scope_id AND kind = NEW.scope AND active = 1
                    )
                ))
            BEGIN
                SELECT RAISE(ABORT, 'invalid vote scope binding');
            END
            """
        )


def _upgrade_sqlite_user_deletion_columns(database_engine: Engine) -> None:
    if database_engine.dialect.name != "sqlite":
        return
    nullable_columns = {"email", "salt_a", "auth_hash", "salt_k", "enc_sk", "pubkey", "cert_serial"}
    with database_engine.connect() as connection:
        table_info = connection.exec_driver_sql("PRAGMA table_info(users)").mappings().all()
        if not any(column["name"] in nullable_columns and column["notnull"] for column in table_info):
            return
        raw_connection = connection.connection.driver_connection
        raw_connection.execute("PRAGMA foreign_keys=OFF")
        try:
            raw_connection.executescript(
                """
                CREATE TABLE users_issue_61 (
                    id VARCHAR(36) NOT NULL PRIMARY KEY,
                    email VARCHAR(254),
                    role VARCHAR(16) NOT NULL,
                    status VARCHAR(32) NOT NULL,
                    salt_a BLOB,
                    auth_hash BLOB,
                    salt_k BLOB,
                    enc_sk BLOB,
                    pubkey BLOB,
                    cert_serial VARCHAR(128),
                    pqc_pubkey BLOB,
                    enc_pqc_sk BLOB,
                    failed_login_count INTEGER NOT NULL,
                    locked_until DATETIME,
                    created_at DATETIME NOT NULL,
                    CONSTRAINT ck_users_role CHECK (role IN ('student', 'admin', 'teacher', 'system')),
                    CONSTRAINT ck_users_status CHECK (status IN ('active', 'frozen', 'pending_deletion')),
                    CONSTRAINT ck_users_pqc_key_pair CHECK ((pqc_pubkey IS NULL) = (enc_pqc_sk IS NULL)),
                    CONSTRAINT ck_users_failed_login_count_nonnegative CHECK (failed_login_count >= 0)
                );
                INSERT INTO users_issue_61 (
                    id, email, role, status, salt_a, auth_hash, salt_k, enc_sk, pubkey, cert_serial,
                    pqc_pubkey, enc_pqc_sk, failed_login_count, locked_until, created_at
                ) SELECT
                    id, email, role, status, salt_a, auth_hash, salt_k, enc_sk, pubkey, cert_serial,
                    pqc_pubkey, enc_pqc_sk, failed_login_count, locked_until, created_at
                FROM users;
                DROP TABLE users;
                ALTER TABLE users_issue_61 RENAME TO users;
                CREATE UNIQUE INDEX ix_users_email ON users (email);
                CREATE UNIQUE INDEX ix_users_cert_serial ON users (cert_serial);
                """
            )
            raw_connection.commit()
        finally:
            raw_connection.execute("PRAGMA foreign_keys=ON")
