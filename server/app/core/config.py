import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_name: str = "CryptoCampus API"
    app_version: str = "1.0.0"
    api_prefix: str = "/api/v1"
    database_url: str = "sqlite+pysqlite:///./cryptocampus.db"
    seal_and_verify_max_bytes: int = 10485760
    vote_settlement_scheduler_enabled: bool = False
    vote_settlement_interval_seconds: int = 60
    vote_settlement_batch_size: int = 50


def get_settings() -> Settings:
    max_bytes_env = os.getenv("CRYPTOCAMPUS_SEAL_AND_VERIFY_MAX_BYTES", "10485760")
    try:
        max_bytes = int(max_bytes_env)
        if max_bytes <= 0 or max_bytes > 104857600:
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("seal_and_verify_max_bytes must be a positive integer not exceeding 104857600")

    scheduler_enabled_env = os.getenv("CRYPTOCAMPUS_VOTE_SETTLEMENT_SCHEDULER_ENABLED", "false").lower()
    return Settings(
        database_url=os.getenv(
            "CRYPTOCAMPUS_DATABASE_URL",
            "sqlite+pysqlite:///./cryptocampus.db",
        ),
        seal_and_verify_max_bytes=max_bytes,
        vote_settlement_scheduler_enabled=scheduler_enabled_env in ("true", "1", "yes"),
        vote_settlement_interval_seconds=int(
            os.getenv("CRYPTOCAMPUS_VOTE_SETTLEMENT_INTERVAL_SECONDS", "60")
        ),
        vote_settlement_batch_size=int(
            os.getenv("CRYPTOCAMPUS_VOTE_SETTLEMENT_BATCH_SIZE", "50")
        ),
    )
