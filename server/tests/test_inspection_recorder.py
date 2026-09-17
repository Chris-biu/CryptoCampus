from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.models.user import User
from app.schemas.inspect import InspectEvent, InspectStepInput
from app.services.inspection import DatabaseInspectionRecorder, NoopInspectionRecorder


def _create_sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_recorder_records_named_event_atomically():
    from app.models.inspect import InspectRecordEntity

    session = _create_sqlite_session()
    user = User(id=str(uuid.uuid4()), email="test@stu.edu.cn", role="student", status="active")
    session.add(user)
    session.commit()

    recorder = DatabaseInspectionRecorder()

    event = InspectEvent(
        operation="drop.envelope.create",
        owner_user_id=uuid.UUID(user.id),
        steps=(
            InspectStepInput(
                order=1,
                name="信封加密",
                algorithm="SM4-GCM",
                result="passed",
                redacted_values={
                    "content_bytes": 1024,
                    "pqc_mode": False,
                    "digest_prefix": "0123456789abcdef",
                    "recipient_cert_fingerprint": "abc",
                },
            ),
        ),
        occurred_at=datetime.now(timezone.utc),
    )

    dto = recorder.record(event=event, session=session)
    assert dto.owner == "self"
    assert dto.owner_user_id == user.id
    assert dto.status == "passed"
    assert len(dto.steps) == 1

    # Check that record is in session flushed but not committed
    entity = session.get(InspectRecordEntity, dto.id)
    assert entity is not None
    assert len(entity.steps) == 1

    session.commit()
    entity_after = session.get(InspectRecordEntity, dto.id)
    assert entity_after is not None


def test_recorder_records_anonymous_event_as_system():
    from app.models.inspect import InspectRecordEntity

    session = _create_sqlite_session()
    recorder = DatabaseInspectionRecorder()

    event = InspectEvent(
        operation="hole.credential.verify",
        owner_user_id=None,
        steps=(
            InspectStepInput(
                order=1,
                name="凭证核验",
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
    )

    dto = recorder.record(event=event, session=session)
    assert dto.owner == "system"
    assert dto.owner_user_id is None
    assert dto.status == "passed"

    entity = session.get(InspectRecordEntity, dto.id)
    assert entity is not None
    assert entity.owner == "system"
    assert entity.owner_user_id is None


def test_recorder_rolls_back_when_transaction_fails():
    from app.models.inspect import InspectRecordEntity

    session = _create_sqlite_session()
    recorder = DatabaseInspectionRecorder()

    event = InspectEvent(
        operation="drop.destroy",
        owner_user_id=None,
        steps=(
            InspectStepInput(
                order=1,
                name="销毁密文",
                algorithm="SM4",
                result="passed",
                redacted_values={
                    "reason_code": "expired",
                    "ciphertext_bytes_cleared": 2048,
                },
            ),
        ),
        occurred_at=datetime.now(timezone.utc),
    )

    dto = recorder.record(event=event, session=session)
    # Rollback transaction
    session.rollback()

    entity = session.get(InspectRecordEntity, dto.id)
    assert entity is None


def test_noop_recorder():
    session = _create_sqlite_session()
    recorder = NoopInspectionRecorder()

    event = InspectEvent(
        operation="drop.destroy",
        owner_user_id=None,
        steps=(
            InspectStepInput(
                order=1,
                name="销毁密文",
                algorithm="SM4",
                result="passed",
                redacted_values={
                    "reason_code": "expired",
                    "ciphertext_bytes_cleared": 2048,
                },
            ),
        ),
        occurred_at=datetime.now(timezone.utc),
    )

    dto = recorder.record(event=event, session=session)
    assert dto.operation == "drop.destroy"
