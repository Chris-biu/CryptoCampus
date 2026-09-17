from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Literal

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError

SM3_DIGEST_SIZE = 32
SM4_KEY_SIZE = 16
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
SM2_PRIVATE_KEY_SIZE = 32
SM2_PUBLIC_KEY_SIZE = 65
SM2_SIGNATURE_SIZE = 64
MAX_DER_CERTIFICATE_SIZE = 64 * 1024
MAX_DER_CRL_SIZE = 4 * 1024 * 1024

EngineState = Literal["online", "offline", "degraded"]


def require_exact_length(value: bytes, expected_length: int) -> None:
    if not isinstance(value, bytes) or len(value) != expected_length:
        raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)


def _require_der(value: bytes, maximum_size: int) -> None:
    if not isinstance(value, bytes) or not value or len(value) > maximum_size:
        raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)


def _require_increasing_times(earlier: int, later: int) -> None:
    if type(earlier) is not int or type(later) is not int or later <= earlier:
        raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)


@dataclass(frozen=True)
class ProviderStatus:
    state: EngineState
    version: str
    provider: str
    capabilities: Mapping[str, bool]


@dataclass(frozen=True)
class Sm4GcmCiphertext:
    ciphertext: bytes
    nonce: bytes
    tag: bytes

    def __post_init__(self) -> None:
        require_exact_length(self.nonce, GCM_NONCE_SIZE)
        require_exact_length(self.tag, GCM_TAG_SIZE)


@dataclass(frozen=True)
class Sm2KeyPair:
    private_key: bytes
    public_key: bytes

    def __post_init__(self) -> None:
        require_exact_length(self.private_key, SM2_PRIVATE_KEY_SIZE)
        require_exact_length(self.public_key, SM2_PUBLIC_KEY_SIZE)


@dataclass(frozen=True)
class SignedCertificate:
    der: bytes
    serial: str
    not_before: int
    not_after: int

    def __post_init__(self) -> None:
        _require_der(self.der, MAX_DER_CERTIFICATE_SIZE)
        if not isinstance(self.serial, str) or not re.fullmatch(r"[A-Za-z0-9:-]{1,128}", self.serial):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        _require_increasing_times(self.not_before, self.not_after)


@dataclass(frozen=True)
class CrlArtifact:
    der: bytes
    this_update: int
    next_update: int

    def __post_init__(self) -> None:
        _require_der(self.der, MAX_DER_CRL_SIZE)
        _require_increasing_times(self.this_update, self.next_update)


MAX_DROP_CONTENT_SIZE = 104857600
MAX_SM2_ENC_KEY_SIZE = 512
MLKEM_ENC_KEY_SIZE = 1088
MLKEM_PUBLIC_KEY_SIZE = 1184
MLKEM_PRIVATE_KEY_SIZE = 2400



@dataclass(frozen=True)
class EnvelopeArtifact:
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    enc_key_sm2: bytes
    enc_key_mlkem: bytes | None
    sender_signature: bytes
    sender_certificate: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.ciphertext, bytes) or not self.ciphertext or len(self.ciphertext) > MAX_DROP_CONTENT_SIZE:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(self.nonce, GCM_NONCE_SIZE)
        require_exact_length(self.tag, GCM_TAG_SIZE)
        if not isinstance(self.enc_key_sm2, bytes) or not self.enc_key_sm2 or len(self.enc_key_sm2) > MAX_SM2_ENC_KEY_SIZE:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        if self.enc_key_mlkem is not None:
            require_exact_length(self.enc_key_mlkem, MLKEM_ENC_KEY_SIZE)
        require_exact_length(self.sender_signature, SM2_SIGNATURE_SIZE)
        _require_der(self.sender_certificate, MAX_DER_CERTIFICATE_SIZE)
