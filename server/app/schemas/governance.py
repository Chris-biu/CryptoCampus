from pydantic import BaseModel, ConfigDict, Field, field_validator


class UserStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    reason: str = Field(min_length=1, max_length=500)


class DeleteAccountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=128)
    confirm: str


class WithdrawHolePostRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=500)

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("理由必须是字符串")
        stripped = value.strip()
        if not (1 <= len(stripped) <= 500):
            raise ValueError("理由去除首尾空格后的字符数必须在 1 到 500 之间")
        return stripped


class UserRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("理由必须是字符串")
        stripped = value.strip()
        if not (1 <= len(stripped) <= 500):
            raise ValueError("理由去除首尾空格后的字符数必须在 1 到 500 之间")
        return stripped


class VoteAuditFlagRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=500)

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("理由必须是字符串")
        stripped = value.strip()
        if not (1 <= len(stripped) <= 500):
            raise ValueError("理由去除首尾空格后的字符数必须在 1 到 500 之间")
        return stripped


class InspectMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    operation: str
    owner_user_id: str
    created_at: str | object


class InspectMetadataPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[InspectMetadata]
    page: int
    page_size: int
    total: int


class AuditEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor_id: str
    action: str
    target: str
    detail_hash: str
    hash_prev: str
    hash_curr: str
    timestamp: str | object

