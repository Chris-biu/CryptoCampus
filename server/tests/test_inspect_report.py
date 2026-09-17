from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.models.user import User
from app.schemas.inspect import InspectEvent, InspectStepInput
from app.services.inspection import DatabaseInspectionRecorder
from app.services.inspect_records import InspectRecordService, generate_markdown_report


def _create_sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_markdown_report_template_structure_and_anti_injection():
    session = _create_sqlite_session()
    user = User(id=str(uuid.uuid4()), email="test@stu.edu.cn", role="student", status="active")
    session.add(user)
    session.commit()

    recorder = DatabaseInspectionRecorder()
    service = InspectRecordService(session)

    # Attempt markdown/html injection in step name and algorithm
    malicious_step_name = "<script>alert(1)</script> [evil link](http://evil.com) # Header \n## Injected"
    malicious_algorithm = "SM4` ; rm -rf /; ```bash\ncat /etc/passwd\n```"

    dto = recorder.record(
        event=InspectEvent(
            operation="drop.envelope.create",
            owner_user_id=uuid.UUID(user.id),
            steps=(
                InspectStepInput(
                    order=1,
                    name=malicious_step_name,
                    algorithm=malicious_algorithm,
                    result="passed",
                    redacted_values={
                        "content_bytes": 1024,
                        "pqc_mode": False,
                        "digest_prefix": "0123456789abcdef",
                        "recipient_cert_fingerprint": "<img src=x onerror=alert(2)>",
                    },
                ),
            ),
            occurred_at=datetime.now(timezone.utc),
        ),
        session=session,
    )
    session.commit()

    report = service.export_owned_report(owner_user_id=user.id, record_id=dto.id)

    # Check required headings
    assert "# CryptoCampus 密码透视实验记录" in report
    assert f"- 记录编号：{dto.id}" in report
    assert "- 操作类型：drop.envelope.create" in report
    assert "## 密码流程" in report
    assert "### 第 1 步：" in report
    assert "## 安全边界" in report

    # Check anti-injection escaping
    assert "<script>" not in report
    assert "&lt;script&gt;" in report or "\\<script\\>" in report
    assert "<img" not in report
    assert "```bash" not in report
    # No raw newlines in step name or algorithm
    assert "\n## Injected" not in report


def test_report_deterministic_output():
    session = _create_sqlite_session()
    user = User(id=str(uuid.uuid4()), email="test@stu.edu.cn", role="student", status="active")
    session.add(user)
    session.commit()

    recorder = DatabaseInspectionRecorder()
    service = InspectRecordService(session)

    dto = recorder.record(
        event=InspectEvent(
            operation="drop.destroy",
            owner_user_id=uuid.UUID(user.id),
            steps=(
                InspectStepInput(
                    order=1,
                    name="销毁",
                    algorithm="SM4",
                    result="passed",
                    redacted_values={
                        "reason_code": "expired",
                        "ciphertext_bytes_cleared": 100,
                    },
                ),
            ),
            occurred_at=datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc),
        ),
        session=session,
    )
    session.commit()

    report1 = service.export_owned_report(owner_user_id=user.id, record_id=dto.id)
    report2 = service.export_owned_report(owner_user_id=user.id, record_id=dto.id)
    assert report1 == report2
