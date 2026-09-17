from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class Quota(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource: str
    used: int = Field(ge=0)
    limit: int = Field(ge=1)


class QuotaPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[Quota]
    resets_at: datetime
