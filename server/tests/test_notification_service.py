from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models.notification import Notification
from app.models.user import User


def _create_sqlite_session():
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_notification_service_list_for_user_pagination_and_isolation():
    from app.services.notification import NotificationService

    session = _create_sqlite_session()
    service = NotificationService(session)

    user_a = User(id=str(uuid.uuid4()), email="user_a@stu.edu.cn", role="student", status="active")
    user_b = User(id=str(uuid.uuid4()), email="user_b@stu.edu.cn", role="student", status="active")
    session.add_all([user_a, user_b])
    session.commit()

    base_time = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)

    # Add 25 notifications for user_a
    notifs_a = []
    for i in range(25):
        notifs_a.append(
            Notification(
                id=f"notif-a-{i:03d}",
                user_id=user_a.id,
                type="drop_extracted",
                title="你的密信已被成功提取",
                related_resource_id=str(uuid.uuid4()),
                source_event_id=f"event-a-{i:03d}",
                read=False,
                created_at=base_time + timedelta(minutes=i),
            )
        )

    # Add 5 notifications for user_b
    notifs_b = []
    for i in range(5):
        notifs_b.append(
            Notification(
                id=f"notif-b-{i:03d}",
                user_id=user_b.id,
                type="drop_extracted",
                title="你的密信已被成功提取",
                related_resource_id=str(uuid.uuid4()),
                source_event_id=f"event-b-{i:03d}",
                read=False,
                created_at=base_time + timedelta(minutes=i),
            )
        )

    session.add_all(notifs_a + notifs_b)
    session.commit()

    # Query user_a page 1 (default page_size=20)
    page1 = service.list_for_user(user_id=user_a.id, page=1, page_size=20)
    assert page1.page == 1
    assert page1.page_size == 20
    assert page1.total == 25
    assert len(page1.items) == 20
    # Most recent first: index 24 is the latest
    assert page1.items[0].id == "notif-a-024"
    assert page1.items[19].id == "notif-a-005"

    # Query user_a page 2 (remaining 5 items)
    page2 = service.list_for_user(user_id=user_a.id, page=2, page_size=20)
    assert page2.page == 2
    assert page2.page_size == 20
    assert page2.total == 25
    assert len(page2.items) == 5
    assert page2.items[0].id == "notif-a-004"
    assert page2.items[4].id == "notif-a-000"

    # Query user_a page 3 (beyond total, returns empty list, does not error)
    page3 = service.list_for_user(user_id=user_a.id, page=3, page_size=20)
    assert page3.page == 3
    assert page3.total == 25
    assert len(page3.items) == 0

    # User isolation: user_b only sees their 5 notifications
    b_page = service.list_for_user(user_id=user_b.id, page=1, page_size=20)
    assert b_page.total == 5
    assert len(b_page.items) == 5
    for item in b_page.items:
        assert item.id.startswith("notif-b-")


def test_notification_service_stable_sorting_by_id_when_same_timestamp():
    from app.services.notification import NotificationService

    session = _create_sqlite_session()
    service = NotificationService(session)

    user = User(id=str(uuid.uuid4()), email="user_c@stu.edu.cn", role="student", status="active")
    session.add(user)
    session.commit()

    same_time = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    # Add 3 notifications with exact same timestamp but different IDs
    n1 = Notification(
        id="notif-100",
        user_id=user.id,
        type="drop_extracted",
        title="你的密信已被成功提取",
        source_event_id=str(uuid.uuid4()),
        created_at=same_time,
    )
    n2 = Notification(
        id="notif-300",
        user_id=user.id,
        type="drop_extracted",
        title="你的密信已被成功提取",
        source_event_id=str(uuid.uuid4()),
        created_at=same_time,
    )
    n3 = Notification(
        id="notif-200",
        user_id=user.id,
        type="drop_extracted",
        title="你的密信已被成功提取",
        source_event_id=str(uuid.uuid4()),
        created_at=same_time,
    )
    session.add_all([n1, n2, n3])
    session.commit()

    page = service.list_for_user(user_id=user.id, page=1, page_size=10)
    # Sorting must be id desc when created_at is identical
    ids = [item.id for item in page.items]
    assert ids == ["notif-300", "notif-200", "notif-100"]


def test_notification_service_create_drop_extracted_and_pending_deletion():
    from app.services.notification import NotificationService

    session = _create_sqlite_session()
    service = NotificationService(session)

    active_user = User(id=str(uuid.uuid4()), email="active@stu.edu.cn", role="student", status="active")
    pending_user = User(id=str(uuid.uuid4()), email="pending@stu.edu.cn", role="student", status="pending_deletion")
    session.add_all([active_user, pending_user])
    session.commit()

    now = datetime.now(timezone.utc)
    drop_id = str(uuid.uuid4())
    event_id = str(uuid.uuid4())

    # Active user receives notification
    notif = service.create_drop_extracted(
        owner_user_id=active_user.id,
        drop_id=drop_id,
        source_event_id=event_id,
        created_at=now,
    )
    assert notif is not None
    assert notif.user_id == active_user.id
    assert notif.type == "drop_extracted"
    assert notif.title == "你的密信已被成功提取"
    assert notif.related_resource_id == drop_id
    assert notif.source_event_id == event_id

    # Pending deletion user does not receive notification
    drop_id2 = str(uuid.uuid4())
    event_id2 = str(uuid.uuid4())
    notif_none = service.create_drop_extracted(
        owner_user_id=pending_user.id,
        drop_id=drop_id2,
        source_event_id=event_id2,
        created_at=now,
    )
    assert notif_none is None
