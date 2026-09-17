from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class CreateVoteOption(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(..., min_length=1, max_length=100)


class CreateVoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    options: List[CreateVoteOption] = Field(..., min_length=2, max_length=20)
    scope: Literal["public", "class", "group"]
    scope_id: Optional[str] = None
    closes_at: datetime

    @field_validator("scope_id")
    @classmethod
    def validate_scope_id_uuid(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        try:
            return str(UUID(value))
        except (TypeError, ValueError, AttributeError) as err:
            raise ValueError("scope_id 必须是合法 UUID") from err

    @model_validator(mode="after")
    def validate_scope_id_matches_scope(self) -> "CreateVoteRequest":
        if self.scope == "public" and self.scope_id is not None:
            raise ValueError("public 范围不应携带 scope_id")
        if self.scope in ("class", "group") and self.scope_id is None:
            raise ValueError("class 或 group 范围必须携带 scope_id")
        return self

    @field_validator("closes_at")
    @classmethod
    def validate_closes_at_timezone(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError("closes_at 必须包含明确的时区信息 (aware datetime)")
        return v


class VoteOptionOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: str


class Vote(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    options: List[VoteOptionOut]
    scope: str
    status: Literal["open", "closed", "published"]
    closes_at: datetime


class VotePage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: List[Vote]
    page: int
    page_size: int
    total: int


class VoteCredentialProof(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sn: str
    service: Literal["vote_ballot"]
    period: str
    signature: str

    @field_validator("sn")
    @classmethod
    def validate_sn(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("sn 必须是字符串")
        v_strip = v.strip()
        if len(v_strip) < 32 or len(v_strip) % 2 != 0:
            raise ValueError("sn 必须是偶数长度十六进制且至少32个字符")
        try:
            sn_bytes = bytes.fromhex(v_strip)
            if len(sn_bytes) < 16:
                raise ValueError("sn 解码后不能少于 16 字节")
        except ValueError as err:
            raise ValueError("sn 必须是合法十六进制字符串") from err
        return v_strip.lower()

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, v: str) -> str:
        import base64
        if not isinstance(v, str) or not v:
            raise ValueError("signature 不能为空")
        try:
            sig_bytes = base64.b64decode(v, validate=True)
            if len(sig_bytes) != 64:
                raise ValueError("signature 解码后必须严格为 64 字节")
        except Exception as err:
            if isinstance(err, ValueError):
                raise
            raise ValueError("signature 必须是合法 base64 编码") from err
        return v


class SubmitBallotRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    option_id: str
    credential: VoteCredentialProof

    @field_validator("option_id")
    @classmethod
    def validate_option_id(cls, v: str) -> str:
        try:
            return str(UUID(v))
        except Exception as err:
            raise ValueError("option_id 必须是合法 UUID") from err


class VoteResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vote_id: str
    counts: Dict[str, int]
    total: int
    signature: str
    signer_certificate: str
    published_at: datetime


class SignatureVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    algorithm: Literal["SM3-with-SM2", "ML-DSA-65"] = "SM3-with-SM2"
    certificate_valid: bool
    message: str


class Accepted(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accepted: Literal[True] = True


class VoteAuditBallot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sn: str
    signature: str
    valid: bool


class VoteAuditReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vote_id: str
    ballots: List[VoteAuditBallot]
    total: int
    result_signature: str

