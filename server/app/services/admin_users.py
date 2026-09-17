from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.user import User


@dataclass(frozen=True)
class AdminUserItemDTO:
    id: str
    email: str | None
    role: Literal["student", "admin", "teacher"]
    status: Literal["active", "frozen", "pending_deletion"]
    pqc_mode: bool
    created_at: datetime


@dataclass(frozen=True)
class AdminUserPageDTO:
    items: list[AdminUserItemDTO]
    page: int
    page_size: int
    total: int


class AdminUserQueryService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_users(self, *, page: int = 1, page_size: int = 20) -> AdminUserPageDTO:
        if page < 1 or page_size < 1:
            raise ValueError("invalid pagination parameters")
        safe_page_size = min(page_size, 100)

        base_filter = User.role != "system"
        total = self.session.query(func.count(User.id)).filter(base_filter).scalar() or 0

        offset = (page - 1) * safe_page_size
        query = (
            self.session.query(
                User.id,
                User.email,
                User.role,
                User.status,
                (User.pqc_pubkey.is_not(None)).label("pqc_mode"),
                User.created_at,
            )
            .filter(base_filter)
            .order_by(User.created_at.desc(), User.id.desc())
            .offset(offset)
            .limit(safe_page_size)
        )
        rows = query.all()
        items = [
            AdminUserItemDTO(
                id=row.id,
                email=row.email,
                role=row.role,
                status=row.status,
                pqc_mode=bool(row.pqc_mode),
                created_at=row.created_at,
            )
            for row in rows
        ]
        return AdminUserPageDTO(items=items, page=page, page_size=safe_page_size, total=total)
