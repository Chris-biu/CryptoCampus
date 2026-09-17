from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


VerificationStepName = Literal[
    "digest", "signature", "certificate_chain", "timestamp", "revocation"
]
_STEP_SEQUENCE: tuple[VerificationStepName, ...] = (
    "digest",
    "signature",
    "certificate_chain",
    "timestamp",
    "revocation",
)


class VerificationStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: VerificationStepName
    passed: bool
    message: str = Field(min_length=1, max_length=200)


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    steps: list[VerificationStep] = Field(min_length=5, max_length=5)
    record_digest: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_canonical_steps_and_conclusion(self) -> "VerificationResult":
        if tuple(step.name for step in self.steps) != _STEP_SEQUENCE:
            raise ValueError("验证步骤必须为固定五步且顺序不可变")
        if self.valid != all(step.passed for step in self.steps):
            raise ValueError("valid 必须等于全部步骤通过")
        return self
