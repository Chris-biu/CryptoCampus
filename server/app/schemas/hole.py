from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.credential import CredentialProof, CredentialVerification

WITHDRAWN_CONTENT_PLACEHOLDER = "【内容已由管理员撤下（违规）】"


class CreateHolePostRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(..., min_length=1, max_length=5000)
    credential: CredentialProof


class HolePost(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: str
    content: str
    credential_prefix: str
    credential_valid: bool
    status: Literal["published", "withdrawn"]
    created_at: datetime

    @model_validator(mode="after")
    def apply_withdrawn_placeholder(self) -> "HolePost":
        if self.status == "withdrawn":
            self.content = WITHDRAWN_CONTENT_PLACEHOLDER
            self.credential_valid = False
        return self


class HolePostPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[HolePost]
    page: int
    page_size: int
    total: int


class CreateHoleCommentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(..., min_length=1, max_length=2000)
    credential: CredentialProof


class HoleComment(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: str
    post_id: str
    content: str
    credential_prefix: str
    credential_valid: bool
    created_at: datetime


class HoleCommentPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[HoleComment]
    page: int
    page_size: int
    total: int


class LikeHolePostRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential: CredentialProof


class HoleLikeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accepted: Literal[True] = True


class RevocationEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sn: str = Field(pattern=r"^[A-Fa-f0-9]{32,}$")
    reason: str = Field(max_length=500)
    hash_prev: str
    hash_curr: str
    timestamp: datetime


class RevocationPage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[RevocationEntry]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)
