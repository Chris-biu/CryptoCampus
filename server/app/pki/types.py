from dataclasses import dataclass, field
import re
from typing import Literal

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import MAX_DER_CERTIFICATE_SIZE, SM2_PRIVATE_KEY_SIZE, SignedCertificate

CertificateState = Literal["active", "expired", "revoked", "invalid"]
USER_IDENTITY_KEY_USAGE = ("digitalSignature", "keyEncipherment", "keyAgreement")


@dataclass(frozen=True)
class PlatformCAMaterial:
    system_user_id: str
    certificate_serial: str
    certificate_der: bytes
    not_before: int
    not_after: int
    private_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.system_user_id, str)
            or not self.system_user_id
            or not isinstance(self.certificate_serial, str)
            or not re.fullmatch(r"[A-Za-z0-9:-]{1,128}", self.certificate_serial)
            or not isinstance(self.certificate_der, bytes)
            or not self.certificate_der
            or len(self.certificate_der) > MAX_DER_CERTIFICATE_SIZE
            or type(self.not_before) is not int
            or type(self.not_after) is not int
            or self.not_after <= self.not_before
            or not isinstance(self.private_key, bytes)
            or len(self.private_key) != SM2_PRIVATE_KEY_SIZE
        ):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)


@dataclass(frozen=True)
class IssuedUserCertificate:
    subject_user_id: str
    role: str
    issuer_serial: str
    key_usage: tuple[str, ...]
    certificate: SignedCertificate


@dataclass(frozen=True)
class CertificateVerification:
    valid: bool
    state: CertificateState
    serial: str | None
