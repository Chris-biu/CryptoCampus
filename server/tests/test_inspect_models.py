from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.models.user import User


def _create_sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_inspect_models_registered_and_boundaries():
    from app.models.inspect import InspectRecordEntity, InspectStepEntity

    session = _create_sqlite_session()

    record_cols = {c.name for c in inspect(InspectRecordEntity).columns}
    step_cols = {c.name for c in inspect(InspectStepEntity).columns}

    # Verify expected columns
    assert "id" in record_cols
    assert "owner_user_id" in record_cols
    assert "owner" in record_cols
    assert "operation" in record_cols
    assert "status" in record_cols
    assert "schema_version" in record_cols
    assert "created_at" in record_cols

    assert "id" in step_cols
    assert "record_id" in step_cols
    assert "order" in step_cols
    assert "name" in step_cols
    assert "algorithm" in step_cols
    assert "result" in step_cols
    assert "redacted_values_json" in step_cols

    # Verify no sensitive columns exist
    sensitive_cols = {
        "plaintext", "private_key", "session_key", "password", "token",
        "secret", "blind_factor", "sn", "content"
    }
    assert not (record_cols & sensitive_cols)
    assert not (step_cols & sensitive_cols)


def test_inspect_step_order_unique_constraint():
    from app.models.inspect import InspectRecordEntity, InspectStepEntity

    session = _create_sqlite_session()
    record_id = str(uuid.uuid4())
    record = InspectRecordEntity(
        id=record_id,
        owner="system",
        operation="drop.destroy",
        status="passed",
        schema_version=1,
        created_at=datetime.now(timezone.utc),
    )
    session.add(record)
    session.flush()

    step1 = InspectStepEntity(
        id=str(uuid.uuid4()),
        record_id=record_id,
        order=1,
        name="step1",
        algorithm="SM3",
        result="passed",
        redacted_values_json="{}",
    )
    step2 = InspectStepEntity(
        id=str(uuid.uuid4()),
        record_id=record_id,
        order=1,  # duplicate order!
        name="step2",
        algorithm="SM4",
        result="passed",
        redacted_values_json="{}",
    )
    session.add(step1)
    session.add(step2)

    with pytest.raises(IntegrityError):
        session.flush()
