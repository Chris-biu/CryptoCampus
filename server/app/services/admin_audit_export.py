from __future__ import annotations

import base64
import csv
from datetime import datetime, timezone
import io
from typing import Any

from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.services.admin_audit import (
    AdminAuditChainService,
    AuditChainIntegrityError,
    format_rfc3339_micros,
)


class AdminAuditExportError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


def sanitize_csv_field(value: str) -> str:
    """Escape formula injection triggers in CSV strings."""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{value}"
    return value


class AdminAuditExportService:
    """
    Export service for verified SM3 chained admin audit logs.
    Takes a snapshot of verified entries up to the current tail,
    and appends a new export audit entry after snapshotting.
    """

    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine | Any,
        audit_chain_service: AdminAuditChainService,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.audit_chain_service = audit_chain_service

    def export(
        self,
        *,
        format: str,
        actor_id: str,
        now: datetime,
    ) -> list[dict[str, Any]] | str:
        clean_format = format.lower().strip()
        if clean_format not in ("csv", "json"):
            raise AdminAuditExportError("validation_error", f"Unsupported export format: {format}")

        # 1. Full verification of chain integrity before export
        try:
            entries = self.audit_chain_service.verify_chain(self.session)
        except AuditChainIntegrityError as err:
            raise AdminAuditExportError("integrity_error", f"Audit chain integrity verification failed: {err}") from err

        # 2. Snapshot entries up to the verified tail
        snapshot_entries = list(entries)
        formatted_items: list[dict[str, Any]] = []
        for e in snapshot_entries:
            formatted_items.append(
                {
                    "actor_id": e.actor_id,
                    "action": e.action,
                    "target": e.target,
                    "detail_hash": base64.b64encode(bytes(e.detail_hash)).decode("ascii"),
                    "hash_prev": base64.b64encode(bytes(e.hash_prev)).decode("ascii"),
                    "hash_curr": base64.b64encode(bytes(e.hash_curr)).decode("ascii"),
                    "timestamp": format_rfc3339_micros(e.timestamp),
                }
            )

        # 3. Snapshot tail rule: append export action itself after snapshotting
        utc_now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)
        detail_bytes = f"admin.audit.export|format:{clean_format}|count:{len(snapshot_entries)}".encode("utf-8")
        detail_hash = self.crypto_engine.sm3_digest(detail_bytes)

        self.audit_chain_service.append(
            session=self.session,
            actor_id=actor_id,
            action="admin.audit.export",
            target=f"format:{clean_format}",
            detail_hash=detail_hash,
            timestamp=utc_now,
        )
        self.session.flush()

        # 4. Return formatted output according to requested format
        if clean_format == "json":
            return formatted_items

        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(
            ["actor_id", "action", "target", "detail_hash", "hash_prev", "hash_curr", "timestamp"]
        )
        for item in formatted_items:
            writer.writerow(
                [
                    sanitize_csv_field(item["actor_id"]),
                    sanitize_csv_field(item["action"]),
                    sanitize_csv_field(item["target"]),
                    item["detail_hash"],
                    item["hash_prev"],
                    item["hash_curr"],
                    item["timestamp"],
                ]
            )
        return output.getvalue()
