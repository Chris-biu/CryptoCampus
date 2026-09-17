from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.models.credential import CredentialLedger
from app.models.hole import HolePost
from app.models.inspect import InspectRecordEntity, InspectStepEntity
from app.models.user import User
from app.schemas.inspect import InspectEvent, InspectStepInput
from app.services.inspection import DatabaseInspectionRecorder


def _create_sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_anonymous_inspection_cannot_correlate_identity():
    session = _create_sqlite_session()
    user = User(id=str(uuid.uuid4()), email="anon@stu.edu.cn", role="student", status="active")
    session.add(user)

    # 1. Registered issuance stage (user known, but blinded)
    ledger = CredentialLedger(
        id=str(uuid.uuid4()),
        user_id=user.id,
        service="hole",
        period="2026-09",
        issued_count=1,
    )
    session.add(ledger)

    recorder = DatabaseInspectionRecorder()

    # Inspect record for issuance (self)
    dto_issue = recorder.record(
        event=InspectEvent(
            operation="hole.credential.issue",
            owner_user_id=uuid.UUID(user.id),
            steps=(
                InspectStepInput(
                    order=1,
                    name="盲签名签发",
                    algorithm="SM2-Blind",
                    result="passed",
                    redacted_values={
                        "service": "hole",
                        "period": "2026-09",
                        "quota_remaining": 9,
                    },
                ),
            ),
            occurred_at=datetime.now(timezone.utc),
        ),
        session=session,
    )

    # 2. Anonymous consumption stage (user unknown, system owner)
    post_id = str(uuid.uuid4())
    post = HolePost(
        id=post_id,
        content="匿名测试帖子",
        credential_sn=b"unblinded_sn_32_bytes_random_hex",
        credential_service="hole",
        credential_period="2026-09",
        credential_signature=b"\x00" * 64,
        credential_prefix="00000000",
        credential_valid=True,
        status="published",
        created_at=datetime.now(timezone.utc),
    )
    session.add(post)

    # Inspect record for anonymous verify/publish (system)
    dto_verify = recorder.record(
        event=InspectEvent(
            operation="hole.credential.verify",
            owner_user_id=None,
            steps=(
                InspectStepInput(
                    order=1,
                    name="凭证验签",
                    algorithm="SM2-Verify",
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

    # Query anonymous inspect record
    anon_record = session.get(InspectRecordEntity, dto_verify.id)
    assert anon_record is not None
    assert anon_record.owner == "system"
    assert anon_record.owner_user_id is None

    # Verify there is NO common column / value to perform a direct equality JOIN
    # between inspect_records (for anonymous consumption) and users or credential_ledgers
    stmt = (
        select(InspectRecordEntity)
        .join(CredentialLedger, InspectRecordEntity.owner_user_id == CredentialLedger.user_id)
        .where(InspectRecordEntity.id == dto_verify.id)
    )
    correlated = session.scalars(stmt).all()
    assert len(correlated) == 0, "Security violation: anonymous record should never join with user credential ledger"
