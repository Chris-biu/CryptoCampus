from __future__ import annotations

from datetime import datetime
import json
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, field_validator


InspectOwner = Literal["self", "other", "system"]
InspectResult = Literal["passed", "failed", "skipped"]

InspectOperation = Literal[
    "drop.envelope.create",
    "drop.envelope.open",
    "drop.destroy",
    "hole.credential.issue",
    "hole.credential.verify",
    "vote.credential.issue",
    "vote.ballot.verify",
    "vote.result.sign",
    "seal.create",
    "seal.verify",
    "chat.session.negotiate",
]

DIGEST_PREFIX_REGEX = r"^[0-9a-f]{16}$"
MAX_STRING_LEN = 200
MAX_REDACTED_JSON_BYTES = 4096


# --- Operation-Specific Redacted Schemas (Strict Whitelist) ---

class BaseRedactedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DropEnvelopeCreateRedacted(BaseRedactedModel):
    content_bytes: StrictInt = Field(ge=0)
    pqc_mode: StrictBool
    digest_prefix: StrictStr = Field(pattern=DIGEST_PREFIX_REGEX)
    recipient_cert_fingerprint: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)


class DropEnvelopeOpenRedacted(BaseRedactedModel):
    pqc_mode: StrictBool
    digest_prefix: StrictStr = Field(pattern=DIGEST_PREFIX_REGEX)
    sender_cert_fingerprint: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)
    signature_valid: StrictBool


class DropDestroyRedacted(BaseRedactedModel):
    reason_code: Literal["expired", "extracted", "manual", "revoked", "admin_destroyed"]
    ciphertext_bytes_cleared: StrictInt = Field(ge=0)


class HoleCredentialIssueRedacted(BaseRedactedModel):
    service: Literal["hole"]
    period: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)
    quota_remaining: StrictInt = Field(ge=0)


class HoleCredentialVerifyRedacted(BaseRedactedModel):
    service: Literal["hole"]
    period: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)
    signature_valid: StrictBool
    revoked: StrictBool


class VoteCredentialIssueRedacted(BaseRedactedModel):
    vote_scope: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)
    credential_issued: StrictBool


class VoteBallotVerifyRedacted(BaseRedactedModel):
    vote_public_id: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)
    signature_valid: StrictBool
    counted: StrictBool


class VoteResultSignRedacted(BaseRedactedModel):
    vote_public_id: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)
    total: StrictInt = Field(ge=0)
    algorithm: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)
    signer_cert_fingerprint: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)


class SealCreateRedacted(BaseRedactedModel):
    file_bytes: StrictInt = Field(ge=0)
    digest_prefix: StrictStr = Field(pattern=DIGEST_PREFIX_REGEX)
    seal_profile: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)
    algorithm: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)
    cert_fingerprint: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)


class SealVerifyRedacted(BaseRedactedModel):
    digest_passed: StrictBool
    signature_passed: StrictBool
    chain_passed: StrictBool
    timestamp_passed: StrictBool
    revocation_passed: StrictBool


class ChatSessionNegotiateRedacted(BaseRedactedModel):
    pqc_mode: StrictBool
    key_agreement: StrictStr = Field(min_length=1, max_length=MAX_STRING_LEN)
    public_material_bytes: StrictInt = Field(ge=0)


OPERATION_SCHEMA_MAP: dict[InspectOperation, type[BaseRedactedModel]] = {
    "drop.envelope.create": DropEnvelopeCreateRedacted,
    "drop.envelope.open": DropEnvelopeOpenRedacted,
    "drop.destroy": DropDestroyRedacted,
    "hole.credential.issue": HoleCredentialIssueRedacted,
    "hole.credential.verify": HoleCredentialVerifyRedacted,
    "vote.credential.issue": VoteCredentialIssueRedacted,
    "vote.ballot.verify": VoteBallotVerifyRedacted,
    "vote.result.sign": VoteResultSignRedacted,
    "seal.create": SealCreateRedacted,
    "seal.verify": SealVerifyRedacted,
    "chat.session.negotiate": ChatSessionNegotiateRedacted,
}


def validate_and_sanitize_step(
    operation: InspectOperation | str,
    raw_values: dict[str, Any],
) -> dict[str, StrictStr | StrictInt | StrictBool | None]:
    if operation not in OPERATION_SCHEMA_MAP:
        raise ValueError(f"Unknown inspect operation: {operation}")
    schema_cls = OPERATION_SCHEMA_MAP[operation]  # type: ignore
    validated = schema_cls.model_validate(raw_values)
    values_dict = validated.model_dump(mode="python")
    encoded_json = json.dumps(values_dict, sort_keys=True, separators=(",", ":"))
    if len(encoded_json.encode("utf-8")) > MAX_REDACTED_JSON_BYTES:
        raise ValueError(
            f"Redacted values JSON exceeds limit of {MAX_REDACTED_JSON_BYTES} bytes"
        )
    return values_dict


# --- Domain & Event Models ---

class InspectStepInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    order: int = Field(ge=1, le=32)
    name: str = Field(min_length=1, max_length=100)
    algorithm: str = Field(min_length=1, max_length=100)
    result: InspectResult
    redacted_values: dict[str, StrictStr | StrictInt | StrictBool | None]

    @field_validator("redacted_values")
    @classmethod
    def validate_values(
        cls, v: dict[str, StrictStr | StrictInt | StrictBool | None]
    ) -> dict[str, StrictStr | StrictInt | StrictBool | None]:
        for key, val in v.items():
            if isinstance(val, str) and len(val) > MAX_STRING_LEN:
                raise ValueError(f"Value for '{key}' exceeds max length {MAX_STRING_LEN}")
        return v


class InspectEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: InspectOperation
    owner_user_id: UUID | None
    steps: tuple[InspectStepInput, ...] = Field(min_length=1, max_length=32)
    occurred_at: datetime


# --- API Request & Response Models ---

class InspectStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: int = Field(ge=1)
    name: str
    algorithm: str
    result: InspectResult
    redacted_values: dict[str, Any]


class InspectRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    operation: str
    owner: InspectOwner
    steps: list[InspectStep]
    created_at: datetime


class InspectRecordDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    owner_user_id: str | None
    owner: InspectOwner
    operation: str
    status: Literal["passed", "failed"]
    schema_version: int
    created_at: datetime
    steps: list[InspectStep]


class InspectRecordPage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[InspectRecord]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    total: int = Field(ge=0)


class ExperimentType(str):
    SM4_MODE_COMPARE = "sm4_mode_compare"
    SM3_AVALANCHE = "sm3_avalanche"
    SM2_CURVE = "sm2_curve"
    ECDH = "ecdh"
    ML_KEM = "ml_kem"
    ML_DSA = "ml_dsa"
    KAT = "kat"


class ExperimentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    experiment: Literal[
        "sm4_mode_compare",
        "sm3_avalanche",
        "sm2_curve",
        "ecdh",
        "ml_kem",
        "ml_dsa",
        "kat",
    ]
    input: str = Field(max_length=1048576)


class ExperimentResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    experiment: str
    passed: bool
    steps: list[str]
    redacted_values: dict[str, Any]


class TlcpHandshake(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["TLCP"] = "TLCP"
    cipher_suite: str
    signing_certificate: str
    encryption_certificate: str
    messages: list[str]
