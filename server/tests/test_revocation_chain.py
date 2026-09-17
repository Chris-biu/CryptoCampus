from datetime import datetime, timedelta, timezone
import hashlib
import pytest

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.models.audit import RevocationLog
from app.services.revocation_log import (
    GENESIS_HASH,
    REVOCATION_DOMAIN,
    calculate_revocation_hash,
    canonical_utc,
    encode_revocation_entry,
    length_prefix,
    normalize_reason,
    order_and_verify_chain,
    verify_entries,
)


class DeterministicMockCryptoEngine(MockCryptoEngine):
    """Deterministic mock crypto engine computing 32-byte hashes from input."""

    def __init__(self) -> None:
        super().__init__()
        self._error_to_raise: CryptoBridgeError | None = None

    def set_error_to_raise(self, error: CryptoBridgeError | None) -> None:
        self._error_to_raise = error

    def sm3_digest(self, message: bytes) -> bytes:
        if self._error_to_raise is not None:
            raise self._error_to_raise
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


def test_canonical_utc() -> None:
    # Test naive datetime gets treated as UTC
    naive_dt = datetime(2026, 9, 9, 12, 0, 0, 0)
    assert canonical_utc(naive_dt) == "2026-09-09T12:00:00.000000Z"

    # Test aware UTC datetime with microseconds
    utc_dt = datetime(2026, 9, 9, 12, 34, 56, 789, tzinfo=timezone.utc)
    assert canonical_utc(utc_dt) == "2026-09-09T12:34:56.000789Z"

    # Test non-UTC timezone converts to UTC
    tz_east8 = timezone(timedelta(hours=8))
    east8_dt = datetime(2026, 9, 9, 20, 0, 0, 0, tzinfo=tz_east8)
    assert canonical_utc(east8_dt) == "2026-09-09T12:00:00.000000Z"


def test_normalize_reason() -> None:
    # Strips whitespace
    assert normalize_reason("  test reason  ") == "test reason"
    # Single character
    assert normalize_reason("a") == "a"
    # 500 characters
    long_reason = "r" * 500
    assert normalize_reason(long_reason) == long_reason

    # Rejects empty or whitespace-only
    with pytest.raises(ValueError):
        normalize_reason("")
    with pytest.raises(ValueError):
        normalize_reason("   ")

    # Rejects > 500 characters
    with pytest.raises(ValueError):
        normalize_reason("r" * 501)

    # Rejects non-string
    with pytest.raises(ValueError):
        normalize_reason(123)  # type: ignore[arg-type]


def test_length_prefix() -> None:
    raw = b"hello"
    prefixed = length_prefix(raw)
    assert prefixed[:4] == (5).to_bytes(4, byteorder="big", signed=False)
    assert prefixed[4:] == b"hello"


def test_encoding_uses_utf8_lengths() -> None:
    hash_prev = GENESIS_HASH
    sn = b"0123456789abcdef"  # 16 bytes
    reason = "违规撤销测试🏷️"
    ts = datetime(2026, 9, 9, 12, 0, 0, 0, tzinfo=timezone.utc)

    encoded = encode_revocation_entry(
        hash_prev=hash_prev,
        sn=sn,
        reason=reason,
        timestamp=ts,
    )

    # 1. Prefix: REVOCATION_DOMAIN
    assert encoded.startswith(REVOCATION_DOMAIN)
    offset = len(REVOCATION_DOMAIN)

    # 2. hash_prev (32 bytes)
    assert encoded[offset : offset + 32] == hash_prev
    offset += 32

    # 3. length_prefix(sn): 4 bytes length + 16 bytes
    sn_len = int.from_bytes(encoded[offset : offset + 4], byteorder="big")
    assert sn_len == 16
    offset += 4
    assert encoded[offset : offset + 16] == sn
    offset += 16

    # 4. length_prefix(reason_bytes): UTF-8 encoded length
    reason_bytes = reason.encode("utf-8")
    expected_reason_len = len(reason_bytes)
    reason_len = int.from_bytes(encoded[offset : offset + 4], byteorder="big")
    assert reason_len == expected_reason_len
    # Character count != byte count for Chinese and emoji
    assert reason_len != len(reason)
    offset += 4
    assert encoded[offset : offset + expected_reason_len] == reason_bytes
    offset += expected_reason_len

    # 5. length_prefix(timestamp_bytes): 27 bytes ASCII string ending with 'Z'
    expected_ts_str = "2026-09-09T12:00:00.000000Z"
    expected_ts_bytes = expected_ts_str.encode("ascii")
    ts_len = int.from_bytes(encoded[offset : offset + 4], byteorder="big")
    assert ts_len == len(expected_ts_bytes)
    offset += 4
    assert encoded[offset : offset + len(expected_ts_bytes)] == expected_ts_bytes
    assert encoded.endswith(b"Z")
    assert offset + len(expected_ts_bytes) == len(encoded)


def test_encode_parameter_validation() -> None:
    valid_hash = GENESIS_HASH
    valid_sn = b"0123456789abcdef"
    valid_reason = "valid reason"
    valid_ts = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)

    # Invalid hash_prev length
    with pytest.raises(ValueError):
        encode_revocation_entry(
            hash_prev=b"too_short",
            sn=valid_sn,
            reason=valid_reason,
            timestamp=valid_ts,
        )

    # Invalid sn length (< 16)
    with pytest.raises(ValueError):
        encode_revocation_entry(
            hash_prev=valid_hash,
            sn=b"short_sn_15byte",
            reason=valid_reason,
            timestamp=valid_ts,
        )

    # Invalid reason
    with pytest.raises(ValueError):
        encode_revocation_entry(
            hash_prev=valid_hash,
            sn=valid_sn,
            reason="   ",
            timestamp=valid_ts,
        )


def test_verify_empty_chain() -> None:
    crypto = DeterministicMockCryptoEngine()
    assert verify_entries([], crypto) is True
    assert order_and_verify_chain([], crypto) == []


def test_verify_two_entries() -> None:
    crypto = DeterministicMockCryptoEngine()

    ts1 = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    sn1 = b"sn1_123456789012"
    reason1 = "reason one"
    h1 = calculate_revocation_hash(
        crypto,
        hash_prev=GENESIS_HASH,
        sn=sn1,
        reason=reason1,
        timestamp=ts1,
    )
    e1 = RevocationLog(
        hash_curr=h1,
        hash_prev=GENESIS_HASH,
        sn=sn1,
        reason=reason1,
        operator="op1",
        ts=ts1,
    )

    ts2 = datetime(2026, 9, 9, 11, 0, 0, tzinfo=timezone.utc)
    sn2 = b"sn2_123456789012"
    reason2 = "reason two"
    h2 = calculate_revocation_hash(
        crypto,
        hash_prev=h1,
        sn=sn2,
        reason=reason2,
        timestamp=ts2,
    )
    e2 = RevocationLog(
        hash_curr=h2,
        hash_prev=h1,
        sn=sn2,
        reason=reason2,
        operator="op1",
        ts=ts2,
    )

    # Shuffled input order: [e2, e1]
    assert verify_entries([e2, e1], crypto) is True
    ordered = order_and_verify_chain([e2, e1], crypto)
    assert ordered == [e1, e2]


def test_tampered_reason() -> None:
    crypto = DeterministicMockCryptoEngine()
    ts = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    sn = b"sn1_123456789012"
    h = calculate_revocation_hash(
        crypto,
        hash_prev=GENESIS_HASH,
        sn=sn,
        reason="original reason",
        timestamp=ts,
    )
    e = RevocationLog(
        hash_curr=h,
        hash_prev=GENESIS_HASH,
        sn=sn,
        reason="tampered reason",
        operator="op1",
        ts=ts,
    )
    assert verify_entries([e], crypto) is False
    assert order_and_verify_chain([e], crypto) is None


def test_unnormalized_reason() -> None:
    crypto = DeterministicMockCryptoEngine()
    ts = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    sn = b"sn1_123456789012"
    # Reason with leading/trailing spaces must fail directly without silent stripping
    e = RevocationLog(
        hash_curr=b"\x01" * 32,
        hash_prev=GENESIS_HASH,
        sn=sn,
        reason="  unstripped reason  ",
        operator="op1",
        ts=ts,
    )
    assert verify_entries([e], crypto) is False
    assert order_and_verify_chain([e], crypto) is None


def test_missing_middle() -> None:
    crypto = DeterministicMockCryptoEngine()

    ts1 = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    sn1 = b"sn1_123456789012"
    h1 = calculate_revocation_hash(
        crypto, hash_prev=GENESIS_HASH, sn=sn1, reason="r1", timestamp=ts1
    )
    e1 = RevocationLog(
        hash_curr=h1, hash_prev=GENESIS_HASH, sn=sn1, reason="r1", operator="op1", ts=ts1
    )

    ts2 = datetime(2026, 9, 9, 11, 0, 0, tzinfo=timezone.utc)
    sn2 = b"sn2_123456789012"
    h2 = calculate_revocation_hash(
        crypto, hash_prev=h1, sn=sn2, reason="r2", timestamp=ts2
    )
    # e2 is skipped

    ts3 = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    sn3 = b"sn3_123456789012"
    h3 = calculate_revocation_hash(
        crypto, hash_prev=h2, sn=sn3, reason="r3", timestamp=ts3
    )
    e3 = RevocationLog(
        hash_curr=h3, hash_prev=h2, sn=sn3, reason="r3", operator="op1", ts=ts3
    )

    # e1 and e3 without e2
    assert verify_entries([e1, e3], crypto) is False
    assert order_and_verify_chain([e1, e3], crypto) is None


def test_fork() -> None:
    crypto = DeterministicMockCryptoEngine()

    ts1 = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    sn1 = b"sn1_123456789012"
    h1 = calculate_revocation_hash(
        crypto, hash_prev=GENESIS_HASH, sn=sn1, reason="r1", timestamp=ts1
    )
    e1 = RevocationLog(
        hash_curr=h1, hash_prev=GENESIS_HASH, sn=sn1, reason="r1", operator="op1", ts=ts1
    )

    ts2 = datetime(2026, 9, 9, 10, 30, 0, tzinfo=timezone.utc)
    sn2 = b"sn2_123456789012"
    h2 = calculate_revocation_hash(
        crypto, hash_prev=GENESIS_HASH, sn=sn2, reason="r2", timestamp=ts2
    )
    e2 = RevocationLog(
        hash_curr=h2, hash_prev=GENESIS_HASH, sn=sn2, reason="r2", operator="op1", ts=ts2
    )

    # Two records both branching from GENESIS_HASH
    assert verify_entries([e1, e2], crypto) is False
    assert order_and_verify_chain([e1, e2], crypto) is None


def test_cycle() -> None:
    crypto = DeterministicMockCryptoEngine()

    ts1 = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    sn1 = b"sn1_123456789012"
    h1 = calculate_revocation_hash(
        crypto, hash_prev=GENESIS_HASH, sn=sn1, reason="r1", timestamp=ts1
    )
    e1 = RevocationLog(
        hash_curr=h1, hash_prev=GENESIS_HASH, sn=sn1, reason="r1", operator="op1", ts=ts1
    )

    ts2 = datetime(2026, 9, 9, 11, 0, 0, tzinfo=timezone.utc)
    sn2 = b"sn2_123456789012"
    h2 = calculate_revocation_hash(
        crypto, hash_prev=h1, sn=sn2, reason="r2", timestamp=ts2
    )
    e2 = RevocationLog(
        hash_curr=h2, hash_prev=h1, sn=sn2, reason="r2", operator="op1", ts=ts2
    )

    # e3 points back to h1 as next hash, creating a cycle
    ts3 = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    sn3 = b"sn3_123456789012"
    e3 = RevocationLog(
        hash_curr=h1, hash_prev=h2, sn=sn3, reason="r3", operator="op1", ts=ts3
    )

    assert verify_entries([e1, e2, e3], crypto) is False
    assert order_and_verify_chain([e1, e2, e3], crypto) is None


def test_orphan() -> None:
    crypto = DeterministicMockCryptoEngine()

    ts1 = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    sn1 = b"sn1_123456789012"
    h1 = calculate_revocation_hash(
        crypto, hash_prev=GENESIS_HASH, sn=sn1, reason="r1", timestamp=ts1
    )
    e1 = RevocationLog(
        hash_curr=h1, hash_prev=GENESIS_HASH, sn=sn1, reason="r1", operator="op1", ts=ts1
    )

    # Orphan record not connected to e1 or genesis
    ts_orphan = datetime(2026, 9, 9, 11, 0, 0, tzinfo=timezone.utc)
    sn_orphan = b"sn_orphan_123456"
    orphan_prev = b"\xaa" * 32
    h_orphan = calculate_revocation_hash(
        crypto, hash_prev=orphan_prev, sn=sn_orphan, reason="orphan", timestamp=ts_orphan
    )
    orphan = RevocationLog(
        hash_curr=h_orphan,
        hash_prev=orphan_prev,
        sn=sn_orphan,
        reason="orphan",
        operator="op1",
        ts=ts_orphan,
    )

    assert verify_entries([e1, orphan], crypto) is False
    assert order_and_verify_chain([e1, orphan], crypto) is None


def test_provider_error_propagates() -> None:
    crypto = DeterministicMockCryptoEngine()
    ts = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    sn = b"sn1_123456789012"
    h = calculate_revocation_hash(
        crypto, hash_prev=GENESIS_HASH, sn=sn, reason="r1", timestamp=ts
    )
    e = RevocationLog(
        hash_curr=h, hash_prev=GENESIS_HASH, sn=sn, reason="r1", operator="op1", ts=ts
    )

    # Inject provider failure
    crypto.set_error_to_raise(CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))

    with pytest.raises(CryptoBridgeError) as exc_verify:
        verify_entries([e], crypto)
    assert exc_verify.value.code == BridgeErrorCode.PROVIDER_UNAVAILABLE

    with pytest.raises(CryptoBridgeError) as exc_order:
        order_and_verify_chain([e], crypto)
    assert exc_order.value.code == BridgeErrorCode.PROVIDER_UNAVAILABLE


def test_invalid_entry_fields_fail_verification() -> None:
    crypto = DeterministicMockCryptoEngine()
    ts = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    sn = b"sn1_123456789012"
    h = calculate_revocation_hash(
        crypto, hash_prev=GENESIS_HASH, sn=sn, reason="r1", timestamp=ts
    )

    # 1. hash_prev is None
    e_none_prev = RevocationLog(
        hash_curr=h, hash_prev=None, sn=sn, reason="r1", operator="op1", ts=ts
    )
    assert verify_entries([e_none_prev], crypto) is False

    # 2. sn too short (< 16 bytes)
    e_short_sn = RevocationLog(
        hash_curr=h,
        hash_prev=GENESIS_HASH,
        sn=b"short_15bytes12",
        reason="r1",
        operator="op1",
        ts=ts,
    )
    assert verify_entries([e_short_sn], crypto) is False

    # 3. hash_curr wrong length
    e_bad_curr = RevocationLog(
        hash_curr=b"bad_len",
        hash_prev=GENESIS_HASH,
        sn=sn,
        reason="r1",
        operator="op1",
        ts=ts,
    )
    assert verify_entries([e_bad_curr], crypto) is False

    # 4. Self reference (hash_curr == hash_prev)
    self_hash = b"\x33" * 32
    e_self = RevocationLog(
        hash_curr=self_hash,
        hash_prev=self_hash,
        sn=sn,
        reason="r1",
        operator="op1",
        ts=ts,
    )
    assert verify_entries([e_self], crypto) is False

    # 5. Non-datetime ts or invalid reason length
    e_empty_reason = RevocationLog(
        hash_curr=h, hash_prev=GENESIS_HASH, sn=sn, reason="", operator="op1", ts=ts
    )
    assert verify_entries([e_empty_reason], crypto) is False

    e_overlong_reason = RevocationLog(
        hash_curr=h,
        hash_prev=GENESIS_HASH,
        sn=sn,
        reason="x" * 501,
        operator="op1",
        ts=ts,
    )
    assert verify_entries([e_overlong_reason], crypto) is False


def test_three_entries_reordered() -> None:
    crypto = DeterministicMockCryptoEngine()

    ts1 = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)
    sn1 = b"sn1_123456789012"
    h1 = calculate_revocation_hash(
        crypto, hash_prev=GENESIS_HASH, sn=sn1, reason="r1", timestamp=ts1
    )
    e1 = RevocationLog(
        hash_curr=h1, hash_prev=GENESIS_HASH, sn=sn1, reason="r1", operator="op1", ts=ts1
    )

    ts2 = datetime(2026, 9, 9, 11, 0, 0, tzinfo=timezone.utc)
    sn2 = b"sn2_123456789012"
    h2 = calculate_revocation_hash(
        crypto, hash_prev=h1, sn=sn2, reason="r2", timestamp=ts2
    )
    e2 = RevocationLog(
        hash_curr=h2, hash_prev=h1, sn=sn2, reason="r2", operator="op1", ts=ts2
    )

    ts3 = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    sn3 = b"sn3_123456789012"
    h3 = calculate_revocation_hash(
        crypto, hash_prev=h2, sn=sn3, reason="r3", timestamp=ts3
    )
    e3 = RevocationLog(
        hash_curr=h3, hash_prev=h2, sn=sn3, reason="r3", operator="op1", ts=ts3
    )

    # Shuffled input order: [e3, e1, e2]
    assert verify_entries([e3, e1, e2], crypto) is True
    ordered = order_and_verify_chain([e3, e1, e2], crypto)
    assert ordered == [e1, e2, e3]

