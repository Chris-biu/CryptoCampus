import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import uuid

from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import SM2_PUBLIC_KEY_SIZE
from app.models.vote import VoteOption, VoteRecord
from app.schemas.vote import VoteCredentialProof
from app.services.vote_signer import VoteSignerMaterialProvider

BALLOT_MESSAGE_DOMAIN = b"CryptoCampus-Vote-Ballot-v1\x00"


class VoteBallotVerificationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class VerifiedBallotCredential:
    sn_bytes: bytes
    normalized_sn: str
    service: str
    period: str
    signature_bytes: bytes
    vote_id: str
    option_id: str


def encode_vote_ballot_message(
    *,
    sn_hex: str,
    service: str,
    vote_id: str,
    option_id: str,
) -> bytes:
    try:
        sn_bytes = bytes.fromhex(sn_hex)
        if len(sn_bytes) < 16:
            raise ValueError("SN 长度不能少于 16 字节")
    except Exception as err:
        raise ValueError(f"SN 十六进制无效: {sn_hex}") from err

    try:
        vote_uuid_bytes = uuid.UUID(vote_id).bytes
    except Exception as err:
        raise ValueError(f"vote_id UUID 无效: {vote_id}") from err

    try:
        option_uuid_bytes = uuid.UUID(option_id).bytes
    except Exception as err:
        raise ValueError(f"option_id UUID 无效: {option_id}") from err

    service_bytes = service.encode("ascii")
    return (
        BALLOT_MESSAGE_DOMAIN
        + sn_bytes
        + len(service_bytes).to_bytes(2, "big")
        + service_bytes
        + vote_uuid_bytes
        + option_uuid_bytes
    )


def verify_vote_ballot(
    *,
    session: Session,
    crypto_engine: CryptoEngine,
    signer_provider: VoteSignerMaterialProvider,
    vote_id: str,
    option_id: str,
    credential: VoteCredentialProof,
    now: datetime,
) -> VerifiedBallotCredential:
    now_utc = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)

    # 1. Query vote and check public scope
    vote = session.get(VoteRecord, vote_id)
    if vote is None or vote.scope != "public":
        raise VoteBallotVerificationError("vote_not_found", "投票不存在或未公开")

    # 2. Check option belongs to vote
    option = session.get(VoteOption, option_id)
    if option is None or option.vote_id != vote_id:
        raise VoteBallotVerificationError("option_not_found", "选项不存在或不属于该投票")

    # 3. Check vote status and deadline (now < closes_at)
    closes_at_utc = (
        vote.closes_at.replace(tzinfo=timezone.utc)
        if vote.closes_at.tzinfo is None
        else vote.closes_at.astimezone(timezone.utc)
    )
    if vote.status != "open" or now_utc >= closes_at_utc:
        raise VoteBallotVerificationError("vote_closed", "投票已截止或未开放")

    # 4. Service check: strictly must be vote_ballot
    if credential.service != "vote_ballot":
        raise VoteBallotVerificationError("invalid_service", "选票凭证仅支持 vote_ballot 服务")

    # 5. Period check: must match vote_id
    if credential.period != vote_id:
        raise VoteBallotVerificationError("invalid_period", "选票凭证周期与当前投票不匹配")

    # 6. Decode SN and signature
    sn_bytes = bytes.fromhex(credential.sn)
    try:
        sig_bytes = base64.b64decode(credential.signature, validate=True)
        if len(sig_bytes) != 64:
            raise ValueError("Invalid signature length")
    except Exception as err:
        raise VoteBallotVerificationError("invalid_signature", "选票凭证签名格式非法") from err

    # 7. Obtain signer public key for this vote
    public_key = signer_provider.get_signer_public_key(vote_id=vote_id)
    if public_key is None or len(public_key) != SM2_PUBLIC_KEY_SIZE:
        raise VoteBallotVerificationError("engine_unavailable", "服务端投票验签公钥不可用")

    # 8. Construct canonical message and verify blind signature
    canonical_msg = encode_vote_ballot_message(
        sn_hex=credential.sn,
        service=credential.service,
        vote_id=vote_id,
        option_id=option_id,
    )

    try:
        valid = crypto_engine.blind_verify(
            message=canonical_msg,
            signature=sig_bytes,
            signer_public_key=public_key,
        )
    except CryptoBridgeError as cbe:
        if cbe.code == BridgeErrorCode.PROVIDER_UNAVAILABLE:
            raise VoteBallotVerificationError("engine_unavailable", "密码引擎服务不可用") from cbe
        valid = False
    except Exception:
        valid = False

    if not valid:
        raise VoteBallotVerificationError("invalid_signature", "选票凭证盲签名验证失败或未绑定当前投票与选项")

    return VerifiedBallotCredential(
        sn_bytes=sn_bytes,
        normalized_sn=credential.sn.lower(),
        service=credential.service,
        period=credential.period,
        signature_bytes=sig_bytes,
        vote_id=vote_id,
        option_id=option_id,
    )
