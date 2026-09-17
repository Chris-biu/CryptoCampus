from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NotificationType = Literal["drop_extracted", "security", "system"]


class NotificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: str
    type: NotificationType
    title: str = Field(..., min_length=1, max_length=200)
    related_resource_id: str | None = None
    read: bool
    created_at: datetime


class NotificationPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[NotificationResponse]
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    total: int = Field(..., ge=0)
