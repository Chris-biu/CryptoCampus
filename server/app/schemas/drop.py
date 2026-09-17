from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

TtlPolicy = Literal["burn_after_read", "hours_24", "days_7"]


class CreateTextDropRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(..., min_length=1, max_length=1048576)
    ttl_policy: TtlPolicy
    pqc_mode: bool
    access_password: str | None = Field(default=None, min_length=1, max_length=128)


class CreateDropResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    code: str
    access_code: str = Field(..., min_length=8, max_length=32)
    url: str
    expires_at: datetime | None
    pqc_mode: bool


class DropMetadataResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    kind: Literal["text", "file"]
    status: Literal["available", "consumed", "expired", "destroyed", "cooling_down"]
    requires_password: bool
    burn_after_read: bool
    filename: str | None = None
    size: int | None = None
    expires_at: datetime | None = None


class ExtractDropRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_code: str = Field(..., pattern=r"^[A-Z0-9-]{8,32}$")
    access_password: str | None = Field(default=None, max_length=128)


class ExtractedDropResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["text", "file"]
    content: str | None = None
    download_url: str | None = None
    signature_valid: bool
    certificate_valid: bool
    inspect_record_id: str
    filename: str | None = Field(default=None, exclude=True)

