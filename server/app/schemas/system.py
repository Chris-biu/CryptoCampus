from typing import Literal

from pydantic import BaseModel, ConfigDict


class SystemStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api: Literal["ok", "degraded"]
    engine: Literal["online", "offline", "degraded"]
    version: str
    tlcp: Literal["online", "offline", "unknown"]
    providers: dict[str, bool]
