from datetime import datetime

from pydantic import BaseModel, ConfigDict


class DeviceSession(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    device: str
    ip_masked: str
    last_active_at: datetime
    current: bool


class DeviceSessionPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DeviceSession]
