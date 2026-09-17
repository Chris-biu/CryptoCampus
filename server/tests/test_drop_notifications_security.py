from datetime import datetime, timezone
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.notification import Notification
from app.models.user import User
from app.schemas.notification import NotificationPage, NotificationResponse
from app.security.auth_dependencies import CurrentUser, get_current_user


def test_notification_schema_extra_forbid():
    """NotificationResponse must forbid extra fields to prevent accidental leakage."""
    valid_data = {
        "id": "notif-uuid-1",
        "type": "drop_extracted",
        "title": "你的密信已被成功提取",
        "related_resource_id": "drop-uuid-1234",
        "read": False,
        "created_at": datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc),
    }
    resp = NotificationResponse(**valid_data)
    assert resp.id == "notif-uuid-1"

    # Extra fields must raise ValidationError
    sensitive_extra = dict(valid_data)
    sensitive_extra["plaintext"] = "sensitive content"
    with pytest.raises(ValidationError):
        NotificationResponse(**sensitive_extra)

    sensitive_extra2 = dict(valid_data)
    sensitive_extra2["recipient_user_id"] = "user-recipient-123"
    with pytest.raises(ValidationError):
        NotificationResponse(**sensitive_extra2)

    sensitive_extra3 = dict(valid_data)
    sensitive_extra3["access_code"] = "SECRET123"
    with pytest.raises(ValidationError):
        NotificationResponse(**sensitive_extra3)


def test_notification_model_columns_no_sensitive_fields():
    """Notification table model columns must strictly avoid sensitive information."""
    column_names = {c.name for c in Notification.__table__.columns}
    forbidden_terms = {
        "plaintext",
        "filename",
        "link_code",
        "access_code",
        "access_password",
        "private_key",
        "session_key",
        "kek",
        "recipient_user_id",
        "recipient_id",
        "token",
        "password",
    }
    for forbidden in forbidden_terms:
        assert forbidden not in column_names, f"Sensitive column {forbidden} found in Notification table!"


def test_notification_api_strict_user_isolation():
    """GET /api/v1/me/notifications strictly isolates user data."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    SessionMaker = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    db_session = SessionMaker()

    user_a = User(
        id="user-a-1111",
        email="user_a@campus.edu",
        role="student",
        status="active",
    )
    user_b = User(
        id="user-b-2222",
        email="user_b@campus.edu",
        role="student",
        status="active",
    )
    db_session.add_all([user_a, user_b])
    db_session.flush()

    notif_a = Notification(
        id="notif-a-1",
        user_id=user_a.id,
        type="drop_extracted",
        title="你的密信已被成功提取",
        related_resource_id="drop-a-1",
        source_event_id="evt-a-1",
        read=False,
        created_at=datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc),
    )
    notif_b = Notification(
        id="notif-b-1",
        user_id=user_b.id,
        type="drop_extracted",
        title="你的密信已被成功提取",
        related_resource_id="drop-b-1",
        source_event_id="evt-b-1",
        read=False,
        created_at=datetime(2026, 9, 9, 12, 1, 0, tzinfo=timezone.utc),
    )
    db_session.add_all([notif_a, notif_b])
    db_session.commit()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    # Authenticate as user_a
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id=user_a.id, role="student", status="active"
    )

    client = TestClient(app)
    response = client.get("/api/v1/me/notifications?page=1&page_size=20")
    assert response.status_code == 200
    data = response.json()

    assert data["total"] == 1
    assert len(data["items"]) == 1
    item = data["items"][0]
    assert item["id"] == "notif-a-1"
    assert item["related_resource_id"] == "drop-a-1"
    # Ensure no fields leak user_b's info or sensitive fields
    assert "user_b" not in str(data)
    assert "drop-b-1" not in str(data)

    # Now authenticate as user_b
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id=user_b.id, role="student", status="active"
    )
    response_b = client.get("/api/v1/me/notifications?page=1&page_size=20")
    assert response_b.status_code == 200
    data_b = response_b.json()
    assert data_b["total"] == 1
    assert len(data_b["items"]) == 1
    assert data_b["items"][0]["id"] == "notif-b-1"
    assert data_b["items"][0]["related_resource_id"] == "drop-b-1"
    assert "drop-a-1" not in str(data_b)

    # Missing authentication
    app.dependency_overrides.pop(get_current_user, None)
    unauth_resp = client.get("/api/v1/me/notifications")
    assert unauth_resp.status_code == 401
