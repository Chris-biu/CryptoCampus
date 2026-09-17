from typing import Any

from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    message: str
    request_id: str
    details: dict[str, Any]
