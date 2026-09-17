from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.models.inspect import InspectRecord
from app.services.admin_audit import AdminAuditChainService


@dataclass(frozen=True)
class InspectMetadataDTO:
    id: str
    operation: str
    owner_user_id: str
    created_at: datetime


@dataclass(frozen=True)
class InspectMetadataPageDTO:
    items: list[InspectMetadataDTO]
    page: int
    page_size: int
    total: int


class AdminInspectQueryService:
    """
    Query service for inspecting other users' cryptographic inspection metadata.
    Strictly projects only the 4 metadata columns without touching steps or redacted values.
    Filters out anonymous and system records.
    Records admin viewing action into the audit chain.
    """

    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine | Any,
        audit_chain_service: AdminAuditChainService | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.audit_chain_service = audit_chain_service

    def list_metadata(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        actor_id: str,
        now: datetime,
    ) -> InspectMetadataPageDTO:
        if page < 1:
            page = 1
        if page_size < 1:
            page_size = 20
        if page_size > 100:
            page_size = 100

        base_filter = [
            InspectRecord.owner_user_id.is_not(None),
            InspectRecord.owner_user_id != "system",
        ]

        total = self.session.scalar(
            select(func.count(InspectRecord.id)).where(*base_filter)
        ) or 0

        stmt = (
            select(
                InspectRecord.id,
                InspectRecord.operation,
                InspectRecord.owner_user_id,
                InspectRecord.created_at,
            )
            .where(*base_filter)
            .order_by(InspectRecord.created_at.desc(), InspectRecord.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        rows = self.session.execute(stmt).all()
        items = [
            InspectMetadataDTO(
                id=row[0],
                operation=row[1],
                owner_user_id=row[2],
                created_at=row[3],
            )
            for row in rows
        ]

        utc_now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)

        detail_bytes = f"inspect.metadata.view|page:{page}|page_size:{page_size}|total:{total}".encode("utf-8")
        detail_hash = self.crypto_engine.sm3_digest(detail_bytes)

        if self.audit_chain_service is not None:
            self.audit_chain_service.append(
                session=self.session,
                actor_id=actor_id,
                action="inspect.metadata.view",
                target="inspect_records",
                detail_hash=detail_hash,
                timestamp=utc_now,
            )

        self.session.flush()

        return InspectMetadataPageDTO(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
        )
