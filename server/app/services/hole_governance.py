from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import sqlite3
import threading
import time
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.models.audit import AuditLog, RevocationLog
from app.models.hole import HolePost
from app.models.user import User
from app.services.revocation_log import (
    GENESIS_HASH,
    calculate_revocation_hash,
    normalize_reason,
    order_and_verify_chain,
)

AUDIT_WITHDRAW_DOMAIN = b"CryptoCampus-Hole-Withdraw-Audit-v1\x00"

__all__ = [
    "HoleGovernanceError",
    "RevocationEntryDTO",
    "HoleContentGovernanceService",
]


class HoleGovernanceError(Exception):
    """Exception raised for hole content governance domain errors."""

    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


@dataclass(frozen=True)
class RevocationEntryDTO:
    """Data transfer object for a revocation entry."""

    sn: str
    reason: str
    hash_prev: str
    hash_curr: str
    timestamp: datetime

    @classmethod
    def from_record(cls, record: RevocationLog) -> "RevocationEntryDTO":
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

        return cls(
            sn=sn_hex,
            reason=record.reason,
            hash_prev=hash_prev_str,
            hash_curr=hash_curr_str,
            timestamp=ts,
        )


_MODULE_WRITE_LOCK = threading.Lock()


class HoleContentGovernanceService:
    """Service handling hole content governance, post revocation, and audit logging."""

    def __init__(
        self,
        session_factory: sessionmaker[Session] | Callable[[], Session],
        crypto_engine: CryptoEngine,
        write_lock: threading.Lock | None = None,
        audit_chain_service: Any | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.crypto_engine = crypto_engine
        self._write_lock = write_lock if write_lock is not None else _MODULE_WRITE_LOCK
        self.audit_chain_service = audit_chain_service

    def withdraw_post(
        self,
        *,
        post_id: str,
        reason: str,
        operator_id: str,
        now: datetime,
    ) -> RevocationEntryDTO:
        """Atomically withdraw a post, append to revocation chain, and write an audit log."""
        # 1. Parameter and format validations
        if not isinstance(post_id, str):
            raise HoleGovernanceError("invalid_param", "post_id must be a string")
        try:
            post_uuid = uuid.UUID(post_id)
        except (ValueError, AttributeError, TypeError):
            raise HoleGovernanceError("invalid_param", f"Invalid post_id: {post_id}")

        if not isinstance(operator_id, str):
            raise HoleGovernanceError("invalid_param", "operator_id must be a string")
        try:
            operator_uuid = uuid.UUID(operator_id)
        except (ValueError, AttributeError, TypeError):
            raise HoleGovernanceError("invalid_param", f"Invalid operator_id: {operator_id}")

        try:
            normalized_reason = normalize_reason(reason)
        except (ValueError, TypeError) as exc:
            raise HoleGovernanceError("invalid_reason", str(exc))

        if not isinstance(now, datetime):
            raise HoleGovernanceError("invalid_param", "now must be a datetime object")
        if now.tzinfo is None:
            now_utc = now.replace(tzinfo=timezone.utc)
        else:
            now_utc = now.astimezone(timezone.utc)

        # 2. Scoped lock and retry lifecycle
        max_retries = 3
        for attempt in range(max_retries + 1):
            conflict_exc: Exception | None = None
            with self._write_lock:
                session: Session = self.session_factory()
                try:
                    # 3. Validate operator
                    operator = session.get(User, operator_id)
                    if operator is None or operator.status != "active":
                        raise HoleGovernanceError("unauthorized", "Operator not found or not active")
                    if operator.role not in ("admin", "teacher"):
                        raise HoleGovernanceError("forbidden", "Operator does not have admin or teacher role")

                    # 4. Validate post
                    post = session.get(HolePost, post_id)
                    if post is None:
                        raise HoleGovernanceError("post_not_found", f"Post not found: {post_id}")
                    if post.credential_service != "hole_post":
                        raise HoleGovernanceError("invalid_service", f"Invalid credential service: {post.credential_service}")
                    if not post.credential_sn or len(post.credential_sn) < 16:
                        raise HoleGovernanceError("integrity_error", "帖子凭据 SN 格式不合法")

                    # 5. Check idempotency and existing status
                    if post.status == "withdrawn":
                        stmt = select(RevocationLog).where(RevocationLog.sn == post.credential_sn)
                        existing_rev = session.execute(stmt).scalar_one_or_none()
                        if existing_rev is None:
                            raise HoleGovernanceError(
                                "integrity_error",
                                "Post status is withdrawn but revocation log is missing",
                            )
                        return RevocationEntryDTO.from_record(existing_rev)

                    if post.status != "published":
                        raise HoleGovernanceError("conflict", f"Unsupported post status: {post.status}")

                    # Published post must not have an existing revocation record
                    stmt = select(RevocationLog).where(RevocationLog.sn == post.credential_sn)
                    if session.execute(stmt).scalar_one_or_none() is not None:
                        raise HoleGovernanceError(
                            "integrity_error",
                            "Post is published but revocation log already exists",
                        )

                    # 6. Read entire RevocationLog chain and verify
                    all_records = list(session.execute(select(RevocationLog)).scalars().all())
                    ordered_chain = order_and_verify_chain(all_records, self.crypto_engine)
                    if ordered_chain is None:
                        raise HoleGovernanceError("integrity_error", "Revocation chain verification failed")

                    # Determine hash_prev
                    if not ordered_chain:
                        hash_prev = GENESIS_HASH
                    else:
                        hash_prev = bytes(ordered_chain[-1].hash_curr)

                    # 7. Calculate new revocation hash
                    hash_curr = calculate_revocation_hash(
                        self.crypto_engine,
                        hash_prev=hash_prev,
                        sn=bytes(post.credential_sn),
                        reason=normalized_reason,
                        timestamp=now_utc,
                    )

                    # 8. Update post status and validity (original content and other fields untouched)
                    post.status = "withdrawn"
                    post.credential_valid = False

                    # 9. Insert new RevocationLog entry
                    revocation_entry = RevocationLog(
                        hash_curr=hash_curr,
                        hash_prev=hash_prev,
                        sn=bytes(post.credential_sn),
                        reason=normalized_reason,
                        operator=operator_id,
                        ts=now_utc,
                    )
                    session.add(revocation_entry)

                    # 10. Calculate AuditLog detail_hash
                    detail_payload = (
                        AUDIT_WITHDRAW_DOMAIN
                        + post_uuid.bytes
                        + operator_uuid.bytes
                        + hash_curr
                    )
                    detail_hash = self.crypto_engine.sm3_digest(detail_payload)

                    # 11. Insert AuditLog entry
                    audit_entry = AuditLog(
                        actor=operator_id,
                        action="hole.post.withdraw",
                        target=f"hole_post:{post_id}",
                        detail_hash=detail_hash,
                        ts=now_utc,
                    )
                    session.add(audit_entry)

                    if self.audit_chain_service is not None:
                        self.audit_chain_service.append(
                            session=session,
                            actor_id=operator_id,
                            action="hole.post.withdraw",
                            target=f"hole_post:{post_id}",
                            detail_hash=detail_hash,
                            timestamp=now_utc,
                        )

                    # 12. Flush and commit
                    session.flush()
                    session.commit()

                    return RevocationEntryDTO(
                        sn=bytes(post.credential_sn).hex().lower(),
                        reason=normalized_reason,
                        hash_prev=base64.b64encode(hash_prev).decode("ascii"),
                        hash_curr=base64.b64encode(hash_curr).decode("ascii"),
                        timestamp=now_utc,
                    )
                except HoleGovernanceError:
                    session.rollback()
                    raise
                except CryptoBridgeError as exc:
                    session.rollback()
                    if exc.code == BridgeErrorCode.PROVIDER_UNAVAILABLE:
                        raise HoleGovernanceError("engine_unavailable", "Crypto engine unavailable") from exc
                    raise HoleGovernanceError("engine_unavailable", str(exc)) from exc
                except (IntegrityError, OperationalError, sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
                    session.rollback()
                    err_msg = str(exc).lower()
                    is_integrity = isinstance(exc, (IntegrityError, sqlite3.IntegrityError))
                    is_locked_or_busy = (
                        "database is locked" in err_msg
                        or "database is busy" in err_msg
                        or "locked" in err_msg
                        or "busy" in err_msg
                    )

                    if not (is_integrity or is_locked_or_busy):
                        raise HoleGovernanceError("conflict", str(exc)) from exc

                    conflict_exc = exc
                except SQLAlchemyError as exc:
                    session.rollback()
                    raise HoleGovernanceError("conflict", str(exc)) from exc
                except Exception:
                    session.rollback()
                    raise
                finally:
                    session.close()

            # Process lock is now released, session is rolled back and closed.
            if conflict_exc is not None:
                # Use fresh session to re-read post status for idempotency check
                check_session: Session = self.session_factory()
                try:
                    post_check = check_session.get(HolePost, post_id)
                    if post_check is not None and post_check.status == "withdrawn":
                        stmt = select(RevocationLog).where(RevocationLog.sn == post_check.credential_sn)
                        existing_rev = check_session.execute(stmt).scalar_one_or_none()
                        if existing_rev is None:
                            raise HoleGovernanceError(
                                "integrity_error",
                                "Post status is withdrawn but revocation log is missing",
                            )
                        return RevocationEntryDTO.from_record(existing_rev)
                finally:
                    check_session.close()

                # Chain head conflict or lock contention retry check
                if attempt >= max_retries:
                    raise HoleGovernanceError("conflict", "撤帖写入冲突，请稍后重试") from conflict_exc

                time.sleep(0.01 * (attempt + 1))
                continue
