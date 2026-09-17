from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.errors import ApiError
from app.db.base import Base
from app.models.user import User
from app.schemas.inspect import InspectEvent, InspectStepInput
from app.services.inspection import DatabaseInspectionRecorder
from app.services.inspect_records import InspectRecordService


def _create_sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_list_owned_returns_only_self_records_and_correct_pagination():
    session = _create_sqlite_session()
    user_a = User(id=str(uuid.uuid4()), email="a@stu.edu.cn", role="student", status="active")
    user_b = User(id=str(uuid.uuid4()), email="b@stu.edu.cn", role="student", status="active")
    session.add_all([user_a, user_b])
    session.commit()

    recorder = DatabaseInspectionRecorder()
    service = InspectRecordService(session)

    # 1. Record for user A
    recorder.record(
        event=InspectEvent(
            operation="drop.envelope.create",
            owner_user_id=uuid.UUID(user_a.id),
            steps=(
                InspectStepInput(
                    order=1,
                    name="创建",
                    algorithm="SM4",
                    result="passed",
                    redacted_values={
                        "content_bytes": 100,
                        "pqc_mode": False,
                        "digest_prefix": "0123456789abcdef",
                        "recipient_cert_fingerprint": "fp",
                    },
                ),
            ),
            occurred_at=datetime.now(timezone.utc),
        ),
        session=session,
    )

    # 2. Record for user B
    recorder.record(
        event=InspectEvent(
            operation="drop.envelope.create",
            owner_user_id=uuid.UUID(user_b.id),
            steps=(
                InspectStepInput(
                    order=1,
                    name="创建",
                    algorithm="SM4",
                    result="passed",
                    redacted_values={
                        "content_bytes": 200,
                        "pqc_mode": False,
                        "digest_prefix": "0123456789abcdef",
                        "recipient_cert_fingerprint": "fp",
                    },
                ),
            ),
            occurred_at=datetime.now(timezone.utc),
        ),
        session=session,
    )

    # 3. System anonymous record
    recorder.record(
        event=InspectEvent(
            operation="hole.credential.verify",
            owner_user_id=None,
            steps=(
                InspectStepInput(
                    order=1,
                    name="核验",
                    algorithm="SM2",
                    result="passed",
                    redacted_values={
                        "service": "hole",
                        "period": "2026-09",
                        "signature_valid": True,
                        "revoked": False,
                    },
                ),
            ),
            occurred_at=datetime.now(timezone.utc),
        ),
        session=session,
    )
    session.commit()

    page_a = service.list_owned(owner_user_id=user_a.id, page=1, page_size=10)
    assert page_a.total == 1
    assert len(page_a.items) == 1
    assert page_a.items[0].owner == "self"
    assert page_a.items[0].operation == "drop.envelope.create"

    page_b = service.list_owned(owner_user_id=user_b.id, page=1, page_size=10)
    assert page_b.total == 1

    # Nonexistent user
    page_none = service.list_owned(owner_user_id=str(uuid.uuid4()), page=1, page_size=10)
    assert page_none.total == 0
    assert len(page_none.items) == 0


def test_get_owned_idor_protection():
    session = _create_sqlite_session()
    user_a = User(id=str(uuid.uuid4()), email="a@stu.edu.cn", role="student", status="active")
    user_b = User(id=str(uuid.uuid4()), email="b@stu.edu.cn", role="student", status="active")
    session.add_all([user_a, user_b])
    session.commit()

    recorder = DatabaseInspectionRecorder()
    service = InspectRecordService(session)

    dto_a = recorder.record(
        event=InspectEvent(
            operation="drop.envelope.create",
            owner_user_id=uuid.UUID(user_a.id),
            steps=(
                InspectStepInput(
                    order=1,
                    name="创建",
                    algorithm="SM4",
                    result="passed",
                    redacted_values={
                        "content_bytes": 100,
                        "pqc_mode": False,
                        "digest_prefix": "0123456789abcdef",
                        "recipient_cert_fingerprint": "fp",
                    },
                ),
            ),
            occurred_at=datetime.now(timezone.utc),
        ),
        session=session,
    )

    dto_system = recorder.record(
        event=InspectEvent(
            operation="hole.credential.verify",
            owner_user_id=None,
            steps=(
                InspectStepInput(
                    order=1,
                    name="核验",
                    algorithm="SM2",
                    result="passed",
                    redacted_values={
                        "service": "hole",
                        "period": "2026-09",
                        "signature_valid": True,
                        "revoked": False,
                    },
                ),
            ),
            occurred_at=datetime.now(timezone.utc),
        ),
        session=session,
    )
    session.commit()

    # User A gets own record -> success
    record_a = service.get_owned(owner_user_id=user_a.id, record_id=dto_a.id)
    assert record_a.id == dto_a.id
    assert record_a.owner == "self"

    # User B tries to get User A's record -> 403 Forbidden
    with pytest.raises(ApiError) as exc_info:
        service.get_owned(owner_user_id=user_b.id, record_id=dto_a.id)
    assert exc_info.value.status_code == 403

    # User A tries to get system record -> 403 Forbidden
    with pytest.raises(ApiError) as exc_info:
        service.get_owned(owner_user_id=user_a.id, record_id=dto_system.id)
    assert exc_info.value.status_code == 403

    # Nonexistent record -> 404 Not Found
    with pytest.raises(ApiError) as exc_info:
        service.get_owned(owner_user_id=user_a.id, record_id=str(uuid.uuid4()))
    assert exc_info.value.status_code == 404
