from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.notification import Notification
from app.models.user import User
from app.schemas.notification import NotificationPage, NotificationResponse


class NotificationService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_drop_extracted(
        self,
        *,
        owner_user_id: str,
        drop_id: str,
        source_event_id: str,
        created_at: datetime,
    ) -> Notification | None:
        user = self.session.get(User, owner_user_id)
        if user is None or user.status == "pending_deletion":
            return None

        utc_now = (
            created_at.replace(tzinfo=timezone.utc)
            if created_at.tzinfo is None
            else created_at.astimezone(timezone.utc)
        )

        notif = Notification(
            id=str(uuid4()),
            user_id=owner_user_id,
            type="drop_extracted",
            title="你的密信已被成功提取",
            related_resource_id=drop_id,
            read=False,
            source_event_id=source_event_id,
            created_at=utc_now,
        )
        self.session.add(notif)
        try:
            self.session.flush()
        except IntegrityError as exc:
            existing = (
                self.session.query(Notification)
                .filter_by(source_event_id=source_event_id)
                .first()
            )
            if existing is not None:
                return existing
            raise exc
        return notif

    def list_for_user(
        self,
        *,
        user_id: str,
        page: int = 1,
        page_size: int = 20,
    ) -> NotificationPage:
        if page < 1:
            page = 1
        if page_size < 1:
            page_size = 1
        elif page_size > 100:
            page_size = 100

        total_stmt = (
            select(func.count())
            .select_from(Notification)
            .where(Notification.user_id == user_id)
        )
        total = self.session.scalar(total_stmt) or 0

        offset = (page - 1) * page_size
        query_stmt = (
            select(Notification)
            .where(Notification.user_id == user_id)
            .order_by(Notification.created_at.desc(), Notification.id.desc())
            .offset(offset)
            .limit(page_size)
        )
        rows = self.session.scalars(query_stmt).all()

        items = [
            NotificationResponse(
                id=row.id,
                type=row.type,
                title=row.title,
                related_resource_id=row.related_resource_id,
                read=row.read,
                created_at=row.created_at,
            )
            for row in rows
        ]

        return NotificationPage(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
        )
