from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class KeyringItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["sm2_identity", "certificate", "ml_kem"]
    algorithm: str
    fingerprint: str
    status: Literal["active", "expired", "revoked", "unavailable"]
    expires_at: datetime | None


class KeyringSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[KeyringItem]
    unlocked_until: datetime | None


class KeyringPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=128)


class KeyringRotationRequest(KeyringPasswordRequest):
    acknowledge_inflight_loss: bool


class CertificateVerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    state: Literal["active", "expired", "revoked", "invalid"]
    serial: str | None
    verified_at: datetime
