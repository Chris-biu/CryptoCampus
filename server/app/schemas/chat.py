import base64
import binascii
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


def decode_base64(value: str, *, minimum: int, maximum: int, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field} 必须是 Base64 字符串")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"{field} 必须是严格 Base64") from error
    if not minimum <= len(decoded) <= maximum:
        raise ValueError(f"{field} 解码后长度不合法")
    return decoded


class CreateChatSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    peer_user_id: str
    pqc_mode: bool

    @field_validator("peer_user_id")
    @classmethod
    def validate_peer_user_id(cls, value: str) -> str:
        try:
            return str(UUID(value))
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError("peer_user_id 必须是合法 UUID") from error


class PeerKeyBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sm2_certificate: str
    ml_kem_public_key: str | None = None


class ChatSessionOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    peer_user_id: str
    pqc_mode: bool
    key_agreement: Literal["SM2-ECDH", "X25519-ML-KEM-768"]
    peer_key_bundle: PeerKeyBundle
    created_at: datetime


class ChatSessionList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ChatSessionOut]


class ChatHandshakeInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    type: Literal["handshake"] = "handshake"
    session_id: str
    payload: str

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, value: str) -> str:
        try:
            return str(UUID(value))
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError("session_id 必须是合法 UUID") from error

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: str) -> str:
        decode_base64(value, minimum=1, maximum=8192, field="payload")
        return value


class ChatEncryptedMessageInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    type: Literal["encrypted_message"] = "encrypted_message"
    session_id: str
    sequence: int = Field(..., ge=1)
    ciphertext: str
    nonce: str
    tag: str
    signature: str

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, value: str) -> str:
        try:
            return str(UUID(value))
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError("session_id 必须是合法 UUID") from error

    @field_validator("ciphertext")
    @classmethod
    def validate_ciphertext(cls, value: str) -> str:
        decode_base64(value, minimum=1, maximum=65536, field="ciphertext")
        return value

    @field_validator("nonce")
    @classmethod
    def validate_nonce(cls, value: str) -> str:
        decode_base64(value, minimum=12, maximum=12, field="nonce")
        return value

    @field_validator("tag")
    @classmethod
    def validate_tag(cls, value: str) -> str:
        decode_base64(value, minimum=16, maximum=16, field="tag")
        return value

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        decode_base64(value, minimum=1, maximum=4096, field="signature")
        return value


class EncryptedMessageOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["encrypted_message"] = "encrypted_message"
    id: str
    session_id: str
    sender_id: str
    sequence: int
    ciphertext: str
    nonce: str
    tag: str
    signature: str
    created_at: datetime


class EncryptedMessagePage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EncryptedMessageOut]
    page: int
    page_size: int
    total: int


class ChatHandshakeRelay(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["handshake"] = "handshake"
    session_id: str
    sender_id: str
    payload: str


class ChatErrorFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["error"] = "error"
    code: Literal["INVALID_FRAME", "FORBIDDEN", "DUPLICATE_SEQUENCE", "INTERNAL_ERROR"]
    message: str = Field(..., max_length=128)
