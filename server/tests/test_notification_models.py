from datetime import datetime, timezone
import uuid
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models.user import User


def _create_sqlite_session():
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_notification_model_registered_and_table_structure():
    from app.models.notification import Notification

    session = _create_sqlite_session()

    cols = {c.name: c for c in inspect(Notification).columns}
    required_cols = {
        "id",
        "user_id",
        "type",
        "title",
        "related_resource_id",
        "read",
        "source_event_id",
        "created_at",
    }
    assert required_cols <= set(cols.keys())

    # Prohibited columns check
    prohibited = {
        "plaintext",
        "filename",
        "link_code",
        "access_code",
        "access_password",
        "private_key",
        "session_key",
        "kek",
        "recipient_user_id",
    }
    assert not (set(cols.keys()) & prohibited)

    user = User(id=str(uuid.uuid4()), email="test@stu.edu.cn", role="student", status="active")
    session.add(user)
    session.commit()

    source_event_id = str(uuid.uuid4())
    drop_id = str(uuid.uuid4())
    notif = Notification(
        user_id=user.id,
        type="drop_extracted",
        title="你的密信已被成功提取",
        related_resource_id=drop_id,
        source_event_id=source_event_id,
    )
    session.add(notif)
    session.commit()

    assert notif.id is not None
    assert notif.read is False
    assert notif.created_at is not None
    assert notif.created_at.tzinfo is not None or notif.created_at <= datetime.now(timezone.utc)


def test_notification_source_event_id_unique_constraint():
    from app.models.notification import Notification

    session = _create_sqlite_session()
    user = User(id=str(uuid.uuid4()), email="user2@stu.edu.cn", role="student", status="active")
    session.add(user)
    session.commit()

    shared_source_event_id = str(uuid.uuid4())
    n1 = Notification(
        user_id=user.id,
        type="drop_extracted",
        title="你的密信已被成功提取",
        source_event_id=shared_source_event_id,
    )
    session.add(n1)
    session.commit()

    n2 = Notification(
        user_id=user.id,
        type="drop_extracted",
        title="你的密信已被成功提取",
        source_event_id=shared_source_event_id,
    )
    session.add(n2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_notification_type_check_constraint():
    from app.models.notification import Notification

    session = _create_sqlite_session()
    user = User(id=str(uuid.uuid4()), email="user3@stu.edu.cn", role="student", status="active")
    session.add(user)
    session.commit()

    invalid_notif = Notification(
        user_id=user.id,
        type="invalid_type",
        title="测试标题",
        source_event_id=str(uuid.uuid4()),
    )
    session.add(invalid_notif)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_notification_schemas_extra_forbid():
    from app.schemas.notification import NotificationPage, NotificationResponse

    now = datetime.now(timezone.utc)
    item = NotificationResponse(
        id=str(uuid.uuid4()),
        type="drop_extracted",
        title="你的密信已被成功提取",
        related_resource_id=str(uuid.uuid4()),
        read=False,
        created_at=now,
    )
    assert item.title == "你的密信已被成功提取"
    assert item.read is False

    # Extra fields must be forbidden
    with pytest.raises(ValidationError):
        NotificationResponse(
            id=str(uuid.uuid4()),
            type="drop_extracted",
            title="你的密信已被成功提取",
            read=False,
            created_at=now,
            user_id=str(uuid.uuid4()),  # Forbidden extra field!
        )

    with pytest.raises(ValidationError):
        NotificationResponse(
            id=str(uuid.uuid4()),
            type="drop_extracted",
            title="你的密信已被成功提取",
            read=False,
            created_at=now,
            source_event_id=str(uuid.uuid4()),  # Forbidden extra field!
        )

    page = NotificationPage(
        items=[item],
        page=1,
        page_size=20,
        total=1,
    )
    assert page.total == 1
    assert len(page.items) == 1

    with pytest.raises(ValidationError):
        NotificationPage(
            items=[item],
            page=1,
            page_size=20,
            total=1,
            extra_field="illegal",
        )
