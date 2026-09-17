from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security.password_policy import normalize_campus_email


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    password: str = Field(min_length=10, max_length=128)
    verification_code: str = Field(pattern=r"^[0-9]{6}$")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return normalize_campus_email(value)


class RequestCodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return normalize_campus_email(value)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    password: str = Field(min_length=1, max_length=128)
    device_name: str | None = Field(default=None, max_length=100)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return normalize_campus_email(value)


class Accepted(BaseModel):
    accepted: bool = True


class UserSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    email: str
    role: str
    status: str
    pqc_mode: bool
    created_at: datetime


class AuthSession(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 7200
    user: UserSummary | dict[str, Any]


class UserPage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[UserSummary]
    page: int
    page_size: int
    total: int
