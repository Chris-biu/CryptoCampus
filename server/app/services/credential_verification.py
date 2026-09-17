import base64
from datetime import datetime, timezone
from typing import NamedTuple
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import SM2_PUBLIC_KEY_SIZE
from app.models.audit import RevocationLog
from app.models.credential import ConsumedSN
from app.schemas.credential import (
    CredentialProof,
    CredentialVerification,
    encode_credential_message,
)
from app.services.signer_provider import (
    ServerSignerVerificationKeyProvider,
    get_signer_verification_key_provider,
)


class VerifiedCredential(NamedTuple):
    sn_bytes: bytes
    signature_bytes: bytes
    normalized_sn: str
    service: str
    period: str


class ConsumptionCredentialVerificationError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


def verify_consumption_credential(
    *,
    session: Session,
    crypto_engine: CryptoEngine,
    signer_verification_key_provider: ServerSignerVerificationKeyProvider,
    credential: CredentialProof,
    expected_service: str,
    now: datetime,
    check_revocation: bool = True,
) -> VerifiedCredential:

    # 1. Service check: strictly must match expected_service
    if credential.service != expected_service:
        raise ConsumptionCredentialVerificationError("invalid_service", f"发布凭证仅支持 {expected_service} 服务")

    # 2. Period check: must equal server's current UTC date
    now_utc = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)
    current_period = now_utc.date().isoformat()
    if credential.period != current_period:
        raise ConsumptionCredentialVerificationError("invalid_period", "凭证周期必须为服务端当前 UTC 日期")

    # 3. Decode SN and signature
    sn_bytes = bytes.fromhex(credential.sn)
    try:
        sig_bytes = base64.b64decode(credential.signature, validate=True)
        if len(sig_bytes) != 64:
            raise ValueError("signature length mismatch")
    except Exception as err:
        raise ConsumptionCredentialVerificationError("invalid_signature", "凭证签名格式非法") from err

    # 4. Signer public key availability
    public_key = signer_verification_key_provider.get_signer_public_key(credential.service)
    if public_key is None or len(public_key) != SM2_PUBLIC_KEY_SIZE:
        raise ConsumptionCredentialVerificationError("engine_unavailable", "服务端验签公钥不可用")

    # 5. Cryptographic signature verification
    canonical_msg = encode_credential_message(credential.sn, credential.service, credential.period)
    try:
        valid = crypto_engine.blind_verify(
            message=canonical_msg,
            signature=sig_bytes,
            signer_public_key=public_key,
        )
    except CryptoBridgeError as cbe:
        if cbe.code == BridgeErrorCode.PROVIDER_UNAVAILABLE:
            raise ConsumptionCredentialVerificationError("engine_unavailable", "密码引擎服务不可用") from cbe
        valid = False
    except Exception:
        valid = False

    if not valid:
        raise ConsumptionCredentialVerificationError("invalid_signature", "凭证盲签名验证失败")

    # 6. Revocation check
    if check_revocation:
        revoked = (
            session.query(RevocationLog).filter_by(sn=sn_bytes).first() is not None
        )
        if revoked:
            raise ConsumptionCredentialVerificationError("credential_revoked", "凭证已被撤销")


    return VerifiedCredential(
        sn_bytes=sn_bytes,
        signature_bytes=sig_bytes,
        normalized_sn=credential.sn.lower(),
        service=credential.service,
        period=credential.period,
    )


class CredentialVerificationError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


class CredentialVerificationService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        signer_verification_key_provider: ServerSignerVerificationKeyProvider | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.signer_verification_key_provider = (
            signer_verification_key_provider or get_signer_verification_key_provider()
        )

    def verify(self, credential: CredentialProof) -> CredentialVerification:
        sn_bytes = bytes.fromhex(credential.sn)
        try:
            sig_bytes = base64.b64decode(credential.signature, validate=True)
        except Exception:
            return CredentialVerification(
                valid=False,
                service=credential.service,
                period=credential.period,
                consumed=False,
                revoked=False,
            )

        # 1. Check ConsumedSN
        consumed = (
            self.session.get(ConsumedSN, (sn_bytes, credential.service)) is not None
        )

        # 2. Check RevocationLog
        revoked = (
            self.session.query(RevocationLog).filter_by(sn=sn_bytes).first() is not None
        )

        # 3. Get signer verification public key
        public_key = self.signer_verification_key_provider.get_signer_public_key(credential.service)
        if public_key is None or len(public_key) != SM2_PUBLIC_KEY_SIZE:
            raise CredentialVerificationError("engine_unavailable", "服务端验签公钥不可用")

        # 4. Construct canonical message M = SN || service || period
        message = encode_credential_message(credential.sn, credential.service, credential.period)

        # 5. Call crypto_engine.blind_verify
        try:
            is_valid = self.crypto_engine.blind_verify(
                message=message,
                signature=sig_bytes,
                signer_public_key=public_key,
            )
        except CryptoBridgeError as cbe:
            if cbe.code == BridgeErrorCode.PROVIDER_UNAVAILABLE:
                raise CredentialVerificationError("engine_unavailable", "密码引擎服务不可用") from cbe
            is_valid = False
        except Exception:
            is_valid = False

        return CredentialVerification(
            valid=bool(is_valid),
            service=credential.service,
            period=credential.period,
            consumed=consumed,
            revoked=revoked,
        )
