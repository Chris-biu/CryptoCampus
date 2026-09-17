import sys
from sqlalchemy import Engine, inspect, text


class RevocationUpgradeError(Exception):
    """Raised when revocation log explicit index upgrade fails."""


def upgrade_revocation_indexes(database_engine: Engine) -> None:
    inspector = inspect(database_engine)
    if not inspector.has_table("revocation_log"):
        return

    with database_engine.connect() as connection:
        dup_sn = connection.execute(
            text("SELECT sn, count(*) FROM revocation_log GROUP BY sn HAVING count(*) > 1")
        ).fetchall()
        dup_prev = connection.execute(
            text(
                "SELECT hash_prev, count(*) FROM revocation_log "
                "WHERE hash_prev IS NOT NULL "
                "GROUP BY hash_prev HAVING count(*) > 1"
            )
        ).fetchall()

        details: list[str] = []
        if dup_sn:
            total_sn_dups = sum(row[1] for row in dup_sn)
            details.append(
                f"{len(dup_sn)} duplicate sn group(s) with total {total_sn_dups} occurrences"
            )
        if dup_prev:
            total_prev_dups = sum(row[1] for row in dup_prev)
            details.append(
                f"{len(dup_prev)} duplicate hash_prev group(s) with total {total_prev_dups} occurrences"
            )

        if details:
            raise RevocationUpgradeError(
                f"Cannot upgrade revocation_log unique indexes due to duplicate records: {'; '.join(details)}"
            )

    with database_engine.begin() as connection:
        connection.execute(
            text("CREATE UNIQUE INDEX IF NOT EXISTS uq_revocation_log_sn ON revocation_log(sn)")
        )
        connection.execute(
            text("CREATE UNIQUE INDEX IF NOT EXISTS uq_revocation_log_hash_prev ON revocation_log(hash_prev)")
        )


def main() -> None:
    from app.core.config import get_settings
    from app.db.session import create_db_engine

    settings = get_settings()
    engine = create_db_engine(settings.database_url)
    try:
        upgrade_revocation_indexes(engine)
    except RevocationUpgradeError as exc:
        sys.stderr.write(f"Revocation upgrade failed: {exc}\n")
        sys.exit(1)
    except Exception as exc:
        sys.stderr.write(f"Unexpected error during revocation upgrade: {exc}\n")
        sys.exit(1)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
