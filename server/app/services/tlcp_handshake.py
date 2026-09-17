from datetime import datetime
import json
import os
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.errors import ApiError
from app.schemas.inspect import TlcpHandshake

FORBIDDEN_SENSITIVE_SUBSTRINGS = (
    "private_key",
    "premaster",
    "master_secret",
    "session_secret",
    "session_key",
    "authorization",
    "cookie",
    "bearer ",
    "begin private key",
    "begin ec private key",
    "client_account",
    "password",
)


class RawTlcpHandshakeSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    protocol: Literal["TLCP"]
    cipher_suite: str = Field(min_length=1)
    signing_certificate: str = Field(min_length=1)
    encryption_certificate: str = Field(min_length=1)
    messages: list[str] = Field(min_length=1)
    captured_at: datetime
    schema_version: int = Field(ge=1)


class TlcpHandshakeProvider(Protocol):
    def get_latest_redacted(self) -> TlcpHandshake: ...


class FileTlcpHandshakeProvider:
    """Reads redacted TLCP handshake traces from a configured source file.

    Fails safely with 503 if the file is absent, expired, invalid, or contains sensitive data.
    """

    def __init__(self, data_path: Path | str | None = None) -> None:
        if data_path is None:
            configured_path = os.getenv("CRYPTOCAMPUS_TLCP_DATA_PATH")
            self._data_path = Path(configured_path) if configured_path else None
        else:
            self._data_path = Path(data_path)

    def get_latest_redacted(self) -> TlcpHandshake:
        if self._data_path is None or not self._data_path.is_file():
            raise ApiError(
                503,
                "PROVIDER_UNAVAILABLE",
                "TLCP capture source is not available",
            )

        try:
            content_text = self._data_path.read_text(encoding="utf-8")
        except Exception:
            raise ApiError(
                503,
                "PROVIDER_UNAVAILABLE",
                "TLCP capture source cannot be read",
            )

        # Sensitive content scan
        lower_content = content_text.lower()
        for forbidden in FORBIDDEN_SENSITIVE_SUBSTRINGS:
            if forbidden in lower_content:
                raise ApiError(
                    503,
                    "PROVIDER_UNAVAILABLE",
                    "TLCP capture source contains prohibited sensitive data",
                )

        try:
            raw_dict = json.loads(content_text)
            parsed = RawTlcpHandshakeSchema.model_validate(raw_dict)
        except (json.JSONDecodeError, ValidationError):
            raise ApiError(
                503,
                "PROVIDER_UNAVAILABLE",
                "TLCP capture source does not match required schema",
            )

        # Map to public OpenAPI TlcpHandshake (discarding captured_at, schema_version)
        return TlcpHandshake(
            protocol=parsed.protocol,
            cipher_suite=parsed.cipher_suite,
            signing_certificate=parsed.signing_certificate,
            encryption_certificate=parsed.encryption_certificate,
            messages=parsed.messages,
        )
