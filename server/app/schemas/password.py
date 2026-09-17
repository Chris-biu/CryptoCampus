from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security.password_policy import PasswordPolicyError, validate_password


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=10, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        try:
            validate_password(value)
        except PasswordPolicyError:
            raise ValueError("password_policy_invalid") from None
        return value
