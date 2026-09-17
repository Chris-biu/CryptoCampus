import base64
from collections.abc import Sequence
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.models.audit import RevocationLog
from app.schemas.hole import RevocationEntry, RevocationPage

REVOCATION_DOMAIN = b"CryptoCampus-Hole-Revocation-v1\x00"
GENESIS_HASH = b"\x00" * 32

__all__ = [
    "REVOCATION_DOMAIN",
    "GENESIS_HASH",
    "canonical_utc",
    "normalize_reason",
    "length_prefix",
    "encode_revocation_entry",
    "calculate_revocation_hash",
    "verify_entries",
    "order_and_verify_chain",
    "RevocationLogServiceError",
    "RevocationLogService",
]


def canonical_utc(value: datetime) -> str:
    """Format a datetime into canonical UTC string YYYY-MM-DDTHH:MM:SS.ffffffZ."""
    if value.tzinfo is None:
        utc_dt = value.replace(tzinfo=timezone.utc)
    else:
        utc_dt = value.astimezone(timezone.utc)
    return f"{utc_dt.strftime('%Y-%m-%dT%H:%M:%S')}.{utc_dt.microsecond:06d}Z"


def normalize_reason(value: str) -> str:
    """Normalize a revocation reason by stripping leading/trailing whitespace.

    Character count must be within [1, 500].
    """
    if not isinstance(value, str):
        raise ValueError("Revocation reason must be a string")
    stripped = value.strip()
    if not (1 <= len(stripped) <= 500):
        raise ValueError("Revocation reason must be between 1 and 500 characters")
    return stripped


def length_prefix(value: bytes) -> bytes:
    """Prefix bytes with 4-byte big-endian unsigned length."""
    return len(value).to_bytes(4, byteorder="big", signed=False) + bytes(value)


def encode_revocation_entry(
    *,
    hash_prev: bytes,
    sn: bytes,
    reason: str,
    timestamp: datetime,
) -> bytes:
    """Canonical encoding of a revocation entry."""
    if not isinstance(hash_prev, (bytes, bytearray)) or len(hash_prev) != 32:
        raise ValueError("hash_prev must be exactly 32 bytes")
    if not isinstance(sn, (bytes, bytearray)) or len(sn) < 16:
        raise ValueError("sn must be at least 16 bytes")
    if not isinstance(timestamp, datetime):
        raise ValueError("timestamp must be a datetime object")

    norm_reason = normalize_reason(reason)
    reason_bytes = norm_reason.encode("utf-8")
    ts_ascii = canonical_utc(timestamp).encode("ascii")

    return (
        REVOCATION_DOMAIN
        + bytes(hash_prev)
        + length_prefix(sn)
        + length_prefix(reason_bytes)
        + length_prefix(ts_ascii)
    )


def calculate_revocation_hash(
    crypto_engine: CryptoEngine,
    *,
    hash_prev: bytes,
    sn: bytes,
    reason: str,
    timestamp: datetime,
) -> bytes:
    """Calculate SM3 digest for a canonical revocation entry using CryptoEngine."""
    encoded = encode_revocation_entry(
        hash_prev=hash_prev,
        sn=sn,
        reason=reason,
        timestamp=timestamp,
    )
    return crypto_engine.sm3_digest(encoded)


def order_and_verify_chain(
    entries: Sequence[RevocationLog],
    crypto_engine: CryptoEngine,
) -> list[RevocationLog] | None:
    """Verify single-chain revocation log entries and return ordered list from genesis.

    Returns ordered list of RevocationLog if valid, or None if invalid.
    Propagates CryptoBridgeError if crypto_engine raises it.
    """
    if not entries:
        return []

    prev_map: dict[bytes, RevocationLog] = {}
    curr_set: set[bytes] = set()

    for entry in entries:
        if entry is None:
            return None

        # Validate hash_curr
        hash_curr = getattr(entry, "hash_curr", None)
        if not isinstance(hash_curr, (bytes, bytearray)) or len(hash_curr) != 32:
            return None
        hash_curr_bytes = bytes(hash_curr)

        # Validate hash_prev
        hash_prev = getattr(entry, "hash_prev", None)
        if (
            hash_prev is None
            or not isinstance(hash_prev, (bytes, bytearray))
            or len(hash_prev) != 32
        ):
            return None
        hash_prev_bytes = bytes(hash_prev)

        # Self-reference check
        if hash_curr_bytes == hash_prev_bytes:
            return None
        # Disallow hash_curr being GENESIS_HASH
        if hash_curr_bytes == GENESIS_HASH:
            return None

        # Validate sn
        sn = getattr(entry, "sn", None)
        if not isinstance(sn, (bytes, bytearray)) or len(sn) < 16:
            return None

        # Validate reason: must not be altered, no silent strip allowed
        reason = getattr(entry, "reason", None)
        if not isinstance(reason, str):
            return None
        if reason != reason.strip() or not (1 <= len(reason) <= 500):
            return None

        # Validate timestamp
        ts = getattr(entry, "ts", None)
        if not isinstance(ts, datetime):
            return None

        # Check curr uniqueness
        if hash_curr_bytes in curr_set:
            return None
        curr_set.add(hash_curr_bytes)

        # Check fork (duplicate hash_prev)
        if hash_prev_bytes in prev_map:
            return None
        prev_map[hash_prev_bytes] = entry

    # Chain must originate from GENESIS_HASH
    if GENESIS_HASH not in prev_map:
        return None

    ordered: list[RevocationLog] = []
    curr_hash: bytes = GENESIS_HASH
    visited_hashes: set[bytes] = set()

    while curr_hash in prev_map:
        if curr_hash in visited_hashes:
            # Cycle detected
            return None
        visited_hashes.add(curr_hash)
        current_entry = prev_map[curr_hash]
        ordered.append(current_entry)
        curr_hash = bytes(current_entry.hash_curr)

    # All entries must be part of the single linear chain
    if len(ordered) != len(entries):
        return None

    # Cryptographic integrity check
    for entry in ordered:
        try:
            expected_hash = calculate_revocation_hash(
                crypto_engine,
                hash_prev=bytes(entry.hash_prev),
                sn=bytes(entry.sn),
                reason=entry.reason,
                timestamp=entry.ts,
            )
        except CryptoBridgeError:
            raise
        except Exception:
            return None

        if expected_hash != bytes(entry.hash_curr):
            return None

    return ordered


def verify_entries(
    entries: Sequence[RevocationLog],
    crypto_engine: CryptoEngine,
) -> bool:
    """Verify single-chain revocation log entries integrity."""
    return order_and_verify_chain(entries, crypto_engine) is not None


class RevocationLogServiceError(ValueError, Exception):
    """Exception raised by RevocationLogService."""

    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


class RevocationLogService:
    """Service handling public queries and verification of the revocation hash chain."""

    def __init__(self, session: Session, crypto_engine: CryptoEngine) -> None:
        self.session = session
        self.crypto_engine = crypto_engine

    def list_entries(self, *, page: int = 1, page_size: int = 20) -> RevocationPage:
        if page < 1:
            raise RevocationLogServiceError("invalid_param", "page must be greater than or equal to 1")
        if page_size < 1 or page_size > 100:
            raise RevocationLogServiceError("invalid_param", "page_size must be between 1 and 100")

        records = list(self.session.execute(select(RevocationLog)).scalars().all())
        try:
            ordered_chain = order_and_verify_chain(records, self.crypto_engine)
        except CryptoBridgeError as exc:
            raise RevocationLogServiceError("engine_unavailable", str(exc)) from exc

        if ordered_chain is None:
            raise RevocationLogServiceError("chain_corrupted", "撤销日志完整性损坏")

        total = len(ordered_chain)
        offset = (page - 1) * page_size
        paged_records = ordered_chain[offset : offset + page_size] if offset < total else []

        items: list[RevocationEntry] = []
        for record in paged_records:
            sn_hex = bytes(record.sn).hex().lower()
            if record.hash_prev is not None:
                hash_prev_str = base64.b64encode(bytes(record.hash_prev)).decode("ascii")
            else:
                hash_prev_str = base64.b64encode(GENESIS_HASH).decode("ascii")
            hash_curr_str = base64.b64encode(bytes(record.hash_curr)).decode("ascii")

            ts = record.ts
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            else:
                ts = ts.astimezone(timezone.utc)

            items.append(
                RevocationEntry(
                    sn=sn_hex,
                    reason=record.reason,
                    hash_prev=hash_prev_str,
                    hash_curr=hash_curr_str,
                    timestamp=ts,
                )
            )

        return RevocationPage(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
        )

