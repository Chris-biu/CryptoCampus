from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import threading
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.models.admin_audit import AdminAuditEntry

DOMAIN_TAG = b"CryptoCampus-Admin-Audit-v1\x00"
GENESIS_HASH_PREV = b"\x00" * 32
_CHAIN_WRITE_LOCK = threading.Lock()


class AuditChainIntegrityError(Exception):
    """Raised when admin audit chain integrity is broken (tampered, split, disconnected)."""
    pass


def format_rfc3339_micros(dt: datetime) -> str:
    """Format UTC datetime to fixed RFC3339 with 6 microsecond digits and Z."""
    utc_dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def encode_admin_audit_entry(
    *,
    hash_prev: bytes,
    actor_id: str,
    action: str,
    target: str,
    detail_hash: bytes,
    timestamp: datetime,
) -> bytes:
    if not isinstance(hash_prev, (bytes, bytearray)) or len(hash_prev) != 32:
        raise ValueError("hash_prev must be exactly 32 bytes")
    if not isinstance(detail_hash, (bytes, bytearray)) or len(detail_hash) != 32:
        raise ValueError("detail_hash must be exactly 32 bytes")

    actor_uuid = uuid.UUID(actor_id)
    action_bytes = action.encode("utf-8")
    target_bytes = target.encode("utf-8")
    ts_bytes = format_rfc3339_micros(timestamp).encode("utf-8")

    encoded = bytearray()
    encoded.extend(DOMAIN_TAG)
    encoded.extend(hash_prev)
    encoded.extend(actor_uuid.bytes)
    encoded.extend(len(action_bytes).to_bytes(4, "big"))
    encoded.extend(action_bytes)
    encoded.extend(len(target_bytes).to_bytes(4, "big"))
    encoded.extend(target_bytes)
    encoded.extend(detail_hash)
    encoded.extend(len(ts_bytes).to_bytes(4, "big"))
    encoded.extend(ts_bytes)

    return bytes(encoded)


class AdminAuditChainService:
    def __init__(
        self,
        crypto_engine: CryptoEngine | Any,
        write_lock: threading.Lock | None = None,
    ) -> None:
        self.crypto_engine = crypto_engine
        self._write_lock = write_lock if write_lock is not None else _CHAIN_WRITE_LOCK

    def _digest(self, data: bytes) -> bytes:
        if hasattr(self.crypto_engine, "sm3_digest"):
            return self.crypto_engine.sm3_digest(data)
        if callable(self.crypto_engine):
            return self.crypto_engine(data)
        raise RuntimeError("Crypto engine does not provide SM3 digest")

    def get_chain_tail(self, session: Session) -> AdminAuditEntry | None:
        """Find the single tail entry of the audit chain (entry with no successor)."""
        entries = list(session.execute(select(AdminAuditEntry)).scalars().all())
        if not entries:
            return None

        # Build set of all hash_prev
        prev_hashes = {e.hash_prev for e in entries}
        # Tail has hash_curr that is not any entry's hash_prev
        tails = [e for e in entries if e.hash_curr not in prev_hashes]
        if len(tails) > 1:
            raise AuditChainIntegrityError(f"Multiple chain tails found: {len(tails)} (fork detected)")
        if len(tails) == 0:
            raise AuditChainIntegrityError("Cycle detected in audit chain, no tail entry found")
        return tails[0]

    def append(
        self,
        *,
        session: Session,
        actor_id: str,
        action: str,
        target: str,
        detail_hash: bytes,
        timestamp: datetime,
    ) -> AdminAuditEntry:
        """Append a new audit entry to the chain. Flushes to session without committing."""
        with self._write_lock:
            tail = self.get_chain_tail(session)
            hash_prev = tail.hash_curr if tail is not None else GENESIS_HASH_PREV

            utc_ts = timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp.astimezone(timezone.utc)
            encoded = encode_admin_audit_entry(
                hash_prev=hash_prev,
                actor_id=actor_id,
                action=action,
                target=target,
                detail_hash=detail_hash,
                timestamp=utc_ts,
            )
            hash_curr = self._digest(encoded)

            entry = AdminAuditEntry(
                id=str(uuid.uuid4()),
                actor_id=actor_id,
                action=action,
                target=target,
                detail_hash=detail_hash,
                hash_prev=hash_prev,
                hash_curr=hash_curr,
                timestamp=utc_ts,
            )
            session.add(entry)
            session.flush()
            return entry

    def verify_chain(self, session: Session) -> list[AdminAuditEntry]:
        """Verify the full integrity of the audit chain from genesis to tail. Returns ordered entries."""
        entries = list(session.execute(select(AdminAuditEntry)).scalars().all())
        if not entries:
            return []

        by_prev: dict[bytes, AdminAuditEntry] = {}
        for e in entries:
            prev = bytes(e.hash_prev)
            if prev in by_prev:
                raise AuditChainIntegrityError(f"Duplicate hash_prev detected: {prev.hex()} (branching)")
            by_prev[prev] = e

        if GENESIS_HASH_PREV not in by_prev:
            raise AuditChainIntegrityError("Genesis entry missing from audit chain")

        ordered: list[AdminAuditEntry] = []
        curr_prev = GENESIS_HASH_PREV
        while curr_prev in by_prev:
            entry = by_prev[curr_prev]
            # Verify hash recalculation
            encoded = encode_admin_audit_entry(
                hash_prev=curr_prev,
                actor_id=entry.actor_id,
                action=entry.action,
                target=entry.target,
                detail_hash=bytes(entry.detail_hash),
                timestamp=entry.timestamp,
            )
            expected_hash = self._digest(encoded)
            if bytes(entry.hash_curr) != expected_hash:
                raise AuditChainIntegrityError(
                    f"Hash mismatch for entry {entry.id}: recorded={bytes(entry.hash_curr).hex()}, expected={expected_hash.hex()}"
                )
            ordered.append(entry)
            curr_prev = bytes(entry.hash_curr)

        if len(ordered) != len(entries):
            raise AuditChainIntegrityError(
                f"Disconnected chain entries detected: verified {len(ordered)} of {len(entries)} total records"
            )

        return ordered
