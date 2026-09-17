from datetime import datetime, timezone, timedelta
import hashlib
import uuid
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.models.admin_audit import AdminAuditEntry
from app.models.inspect import InspectRecord
from app.models.user import User
from app.services.admin_audit import AdminAuditChainService
from app.services.admin_inspect import AdminInspectQueryService


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def crypto_engine():
    return DeterministicMockCryptoEngine()


@pytest.fixture
def audit_chain_service(crypto_engine):
    return AdminAuditChainService(crypto_engine)


@pytest.fixture
def admin_user(db_session):
    admin = User(
        id=str(uuid.uuid4()),
        email="admin@campus.edu",
        role="admin",
        status="active",
    )
    db_session.add(admin)
    db_session.commit()
    return admin


def test_list_metadata_returns_strictly_four_fields_and_paginates(db_session, crypto_engine, audit_chain_service, admin_user):
    user1 = User(id=str(uuid.uuid4()), email="u1@campus.edu", role="student", status="active")
    user2 = User(id=str(uuid.uuid4()), email="u2@campus.edu", role="student", status="active")
    db_session.add_all([user1, user2])
    db_session.commit()

    base_time = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    # Insert 5 records for user1/user2
    for i in range(5):
        record = InspectRecord(
            id=str(uuid.uuid4()),
            operation=f"sm4_cbc_decrypt_{i}",
            owner_user_id=user1.id if i % 2 == 0 else user2.id,
            steps_json='["step1", "step2", "secret_intermediate_key"]',
            redacted_values_json='{"key": "REDACTED", "plaintext": "hidden"}',
            created_at=base_time + timedelta(minutes=i),
        )
        db_session.add(record)

    # Insert an anonymous record (owner_user_id is None) and a system record
    anon_record = InspectRecord(
        id=str(uuid.uuid4()),
        operation="anon_operation",
        owner_user_id=None,
        steps_json="[]",
        redacted_values_json="{}",
        created_at=base_time + timedelta(minutes=10),
    )
    system_record = InspectRecord(
        id=str(uuid.uuid4()),
        operation="system_operation",
        owner_user_id="system",
        steps_json="[]",
        redacted_values_json="{}",
        created_at=base_time + timedelta(minutes=11),
    )
    db_session.add_all([anon_record, system_record])
    db_session.commit()

    service = AdminInspectQueryService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    now = datetime.now(timezone.utc)
    page_result = service.list_metadata(page=1, page_size=3, actor_id=admin_user.id, now=now)
    db_session.commit()

    # Anonymous and system records should be filtered out
    assert page_result.total == 5
    assert len(page_result.items) == 3
    assert page_result.page == 1
    assert page_result.page_size == 3

    # Check that item strictly contains id, operation, owner_user_id, created_at
    for item in page_result.items:
        assert hasattr(item, "id")
        assert hasattr(item, "operation")
        assert hasattr(item, "owner_user_id")
        assert hasattr(item, "created_at")
        assert not hasattr(item, "steps")
        assert not hasattr(item, "steps_json")
        assert not hasattr(item, "redacted_values")
        assert not hasattr(item, "redacted_values_json")
        assert item.owner_user_id in (user1.id, user2.id)

    # Verify query itself logged an admin audit chain entry
    entries = list(db_session.execute(select(AdminAuditEntry)).scalars().all())
    assert len(entries) == 1
    assert entries[0].action == "inspect.metadata.view"
    assert entries[0].target == "inspect_records"
    assert entries[0].actor_id == admin_user.id
