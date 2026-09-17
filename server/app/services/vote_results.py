from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
import uuid

from app.crypto.engine import CryptoEngine
from app.services.vote_tally_provider import VoteTallyMaterial

RESULT_DOMAIN = b"CryptoCampus-Vote-Result-v1\x00"


class VoteResultEncodingError(ValueError):
    pass


class VoteResultSigningError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def encode_vote_result(
    *,
    vote_id: str,
    ordered_counts: Sequence[tuple[str, int]],
    total: int,
    published_at: datetime,
) -> bytes:
    # 1. Validate domain and vote_id
    try:
        vote_uuid_bytes = uuid.UUID(vote_id).bytes
    except Exception as err:
        raise VoteResultEncodingError(f"非法 UUID vote_id: {vote_id}") from err

    # 2. Validate published_at: must be timezone-aware UTC
    if published_at.tzinfo is None or published_at.utcoffset() != timedelta(0):
        raise VoteResultEncodingError("published_at 必须是带时区的 UTC 时间")

    # 3. Validate options, counts, and total
    if not isinstance(total, int) or total < 0 or total > 0xFFFFFFFFFFFFFFFF:
        raise VoteResultEncodingError(f"total 超出上限或不能为负数: {total}")

    seen_options: set[str] = set()
    calculated_total = 0
    options_part = bytearray()

    for option_id, count in ordered_counts:
        if option_id in seen_options:
            raise VoteResultEncodingError(f"编码包含重复选项: {option_id}")
        seen_options.add(option_id)

        try:
            option_uuid_bytes = uuid.UUID(option_id).bytes
        except Exception as err:
            raise VoteResultEncodingError(f"非法 UUID option_id: {option_id}") from err

        if not isinstance(count, int) or count < 0:
            raise VoteResultEncodingError(f"选项计数不能为负数: {count}")
        if count > 0xFFFFFFFFFFFFFFFF:
            raise VoteResultEncodingError(f"选项计数超出上限: {count}")

        calculated_total += count
        options_part.extend(option_uuid_bytes)
        options_part.extend(count.to_bytes(8, "big"))

    if calculated_total != total:
        raise VoteResultEncodingError(f"选项计数总和 ({calculated_total}) 与给定 total ({total}) 总数不符")

    # 4. Format published_at as YYYY-MM-DDTHH:MM:SS.ffffffZ
    time_str = published_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    time_bytes = time_str.encode("ascii")
    time_len = len(time_bytes)

    # 5. Assemble binary layout:
    # [RESULT_DOMAIN (28B)]
    # [vote_uuid_bytes (16B)]
    # [num_options uint32 big (4B)]
    # [options_part (24B * num_options)]
    # [total uint64 big (8B)]
    # [time_len uint32 big (4B)]
    # [time_bytes]
    num_options = len(ordered_counts)
    return (
        RESULT_DOMAIN
        + vote_uuid_bytes
        + num_options.to_bytes(4, "big")
        + bytes(options_part)
        + total.to_bytes(8, "big")
        + time_len.to_bytes(4, "big")
        + time_bytes
    )


def sign_vote_result(
    *,
    crypto_engine: CryptoEngine,
    material: VoteTallyMaterial,
    vote_id: str,
    ordered_counts: Sequence[tuple[str, int]],
    total: int,
    published_at: datetime,
) -> tuple[bytes, bytes]:
    encoded = encode_vote_result(
        vote_id=vote_id,
        ordered_counts=ordered_counts,
        total=total,
        published_at=published_at,
    )
    digest = crypto_engine.sm3_digest(encoded)
    signature = crypto_engine.sm2_sign(material.private_key, digest)

    if not crypto_engine.sm2_verify(material.public_key, digest, signature):
        raise VoteResultSigningError("signature_self_verify_failed", "计票结果签名自校验失败")

    return digest, signature
