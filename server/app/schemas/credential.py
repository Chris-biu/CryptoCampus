import base64
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class BlindCommitmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: Literal["hole_post", "hole_comment", "hole_like", "vote_ballot"]
    period: str = Field(..., min_length=4, max_length=64)


class BlindCommitmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    commitment_id: str
    commitment_point: str
    expires_at: datetime
    algorithm: Literal["SM2-BLIND-PROTOCOL-V1"] = "SM2-BLIND-PROTOCOL-V1"
    signer_public_key: str


class BlindCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: Literal["hole_post", "hole_comment", "hole_like", "vote_ballot"]
    period: str = Field(..., max_length=64)
    blinded_message: str

    @field_validator("blinded_message")
    @classmethod
    def validate_blinded_message(cls, v: str) -> str:
        if not isinstance(v, str) or not v:
            raise ValueError("blinded_message 必须是非空有效 base64 字符串")
        try:
            decoded = base64.b64decode(v, validate=True)
            if not decoded:
                raise ValueError("blinded_message 解码后不能为空")
        except Exception:
            raise ValueError("blinded_message 必须是合法 base64 编码")
        return v


class BlindCredentialResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    blind_signature: str
    algorithm: Literal["SM2-BLIND-PROTOCOL-V1"] = "SM2-BLIND-PROTOCOL-V1"


def encode_credential_message(sn_hex: str, service: str, period: str) -> bytes:
    sn_bytes = bytes.fromhex(sn_hex)
    return sn_bytes + service.encode("ascii") + period.encode("ascii")


class CredentialProof(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sn: str
    service: Literal["hole_post", "hole_comment", "hole_like", "vote_ballot"]
    period: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
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


class CredentialVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    service: Literal["hole_post", "hole_comment", "hole_like", "vote_ballot"]
    period: str
    consumed: bool
    revoked: bool
