from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.session import create_db_engine, create_session_factory, get_db
from app.main import create_app
from app.models.notification import Notification
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user


@pytest.fixture
def test_app(tmp_path):
    db_path = (tmp_path / "routes_test.db").as_posix()
    engine = create_db_engine(f"sqlite:///{db_path}")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)

    app = create_app()

    def override_get_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    return app, session_factory


def test_list_notifications_unauthenticated_returns_401(test_app):
    app, _ = test_app
    client = TestClient(app)
    response = client.get("/api/v1/me/notifications")
    assert response.status_code == 401
    data = response.json()
    assert data["code"] == "UNAUTHORIZED"


def test_list_notifications_invalid_query_params_returns_422(test_app):
    app, _ = test_app
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser("user-1", "student", "active")
    client = TestClient(app)

    # page < 1
    r1 = client.get("/api/v1/me/notifications?page=0")
    assert r1.status_code == 422

    # page_size < 1
    r2 = client.get("/api/v1/me/notifications?page_size=0")
    assert r2.status_code == 422

    # page_size > 100
    r3 = client.get("/api/v1/me/notifications?page_size=101")
    assert r3.status_code == 422


def test_list_notifications_returns_user_notifications_strictly_matching_schema(test_app):
    app, session_factory = test_app
    user_id = str(uuid.uuid4())
    other_user_id = str(uuid.uuid4())

    with session_factory() as session:
        u1 = User(id=user_id, email="u1@stu.edu.cn", role="student", status="active")
        u2 = User(id=other_user_id, email="u2@stu.edu.cn", role="student", status="active")
        session.add_all([u1, u2])
        session.flush()

        now = datetime.now(timezone.utc)
        drop_id = str(uuid.uuid4())
        n1 = Notification(
            id=str(uuid.uuid4()),
            user_id=user_id,
            type="drop_extracted",
            title="你的密信已被成功提取",
            related_resource_id=drop_id,
            read=False,
            source_event_id=str(uuid.uuid4()),
            created_at=now,
        )
        n_other = Notification(
            id=str(uuid.uuid4()),
            user_id=other_user_id,
            type="drop_extracted",
            title="你的密信已被成功提取",
            related_resource_id=str(uuid.uuid4()),
            read=False,
            source_event_id=str(uuid.uuid4()),
            created_at=now,
        )
        session.add_all([n1, n_other])
        session.commit()

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(user_id, "student", "active")
    client = TestClient(app)

    response = client.get("/api/v1/me/notifications?page=1&page_size=20")
    assert response.status_code == 200
    data = response.json()

    assert data["page"] == 1
    assert data["page_size"] == 20
    assert data["total"] == 1
    assert len(data["items"]) == 1

    item = data["items"][0]
    assert item["id"] == n1.id
    assert item["type"] == "drop_extracted"
    assert item["title"] == "你的密信已被成功提取"
    assert item["related_resource_id"] == drop_id
    assert item["read"] is False
    assert "created_at" in item

    # Strict privacy checks: forbidden fields must not exist
    forbidden_keys = {"user_id", "source_event_id", "plaintext", "link_code", "access_code"}
    assert not (set(item.keys()) & forbidden_keys)
