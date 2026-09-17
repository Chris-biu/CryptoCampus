import base64
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import uuid
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.models.admin_audit import AdminAuditEntry
from app.models.user import User
from app.services.admin_audit import (
    AdminAuditChainService,
    AuditChainIntegrityError,
    GENESIS_HASH_PREV,
    format_rfc3339_micros,
)
from app.services.admin_audit_export import (
    AdminAuditExportError,
    AdminAuditExportService,
    sanitize_csv_field,
)


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


def test_sanitize_csv_field():
    assert sanitize_csv_field("=SUM(A1:A10)") == "'=SUM(A1:A10)"
    assert sanitize_csv_field("+12345") == "'+12345"
    assert sanitize_csv_field("-cmd|'/C calc'!A0") == "'-cmd|'/C calc'!A0"
    assert sanitize_csv_field("@eval") == "'@eval"
    assert sanitize_csv_field("normal_action") == "normal_action"
    assert sanitize_csv_field("") == ""


def test_export_json_format(db_session, crypto_engine, audit_chain_service, admin_user):
    now = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    # Add 2 audit entries
    e1 = audit_chain_service.append(
        session=db_session,
        actor_id=admin_user.id,
        action="user.status.update",
        target="user:123",
        detail_hash=b"d" * 32,
        timestamp=now,
    )
    e2 = audit_chain_service.append(
        session=db_session,
        actor_id=admin_user.id,
        action="user.role.update",
        target="user:456",
        detail_hash=b"e" * 32,
        timestamp=now,
    )
    db_session.commit()

    service = AdminAuditExportService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    export_now = datetime(2026, 9, 10, 10, 5, 0, tzinfo=timezone.utc)
    result = service.export(format="json", actor_id=admin_user.id, now=export_now)
    db_session.commit()

    assert isinstance(result, list)
    assert len(result) == 2

    # Check structure
    entry0 = result[0]
    assert entry0["actor_id"] == admin_user.id
    assert entry0["action"] == "user.status.update"
    assert entry0["target"] == "user:123"
    assert entry0["hash_prev"] == base64.b64encode(GENESIS_HASH_PREV).decode("ascii")
    assert entry0["hash_curr"] == base64.b64encode(e1.hash_curr).decode("ascii")

    entry1 = result[1]
    assert entry1["action"] == "user.role.update"
    assert entry1["hash_prev"] == base64.b64encode(e1.hash_curr).decode("ascii")
    assert entry1["hash_curr"] == base64.b64encode(e2.hash_curr).decode("ascii")

    # Verify that the export appended its own audit entry to the chain
    all_entries = db_session.execute(select(AdminAuditEntry)).scalars().all()
    assert len(all_entries) == 3
    last_entry = audit_chain_service.get_chain_tail(db_session)
    assert last_entry.action == "admin.audit.export"
    assert last_entry.target == "format:json"
    assert last_entry.hash_prev == e2.hash_curr


def test_export_csv_format(db_session, crypto_engine, audit_chain_service, admin_user):
    now = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    # Entry with formula prefix target to test injection mitigation
    audit_chain_service.append(
        session=db_session,
        actor_id=admin_user.id,
        action="user.quota.reset",
        target="=MALICIOUS_FORMULA",
        detail_hash=b"f" * 32,
        timestamp=now,
    )
    db_session.commit()

    service = AdminAuditExportService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    export_now = datetime(2026, 9, 10, 10, 5, 0, tzinfo=timezone.utc)
    csv_text = service.export(format="csv", actor_id=admin_user.id, now=export_now)
    db_session.commit()

    assert isinstance(csv_text, str)
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 2  # header + 1 row
    assert rows[0] == ["actor_id", "action", "target", "detail_hash", "hash_prev", "hash_curr", "timestamp"]
    # Verify escaped formula target
    assert rows[1][2] == "'=MALICIOUS_FORMULA"


def test_export_empty_chain(db_session, crypto_engine, audit_chain_service, admin_user):
    service = AdminAuditExportService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    now = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

    json_result = service.export(format="json", actor_id=admin_user.id, now=now)
    assert json_result == []

    # One audit entry for the export itself was appended
    all_entries = db_session.execute(select(AdminAuditEntry)).scalars().all()
    assert len(all_entries) == 1
    assert all_entries[0].action == "admin.audit.export"


def test_export_tampered_chain_fails_safely(db_session, crypto_engine, audit_chain_service, admin_user):
    now = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    entry = audit_chain_service.append(
        session=db_session,
        actor_id=admin_user.id,
        action="user.status.update",
        target="user:123",
        detail_hash=b"d" * 32,
        timestamp=now,
    )
    db_session.commit()

    # Tamper with the entry
    entry.target = "tampered_target"
    db_session.commit()

    service = AdminAuditExportService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    with pytest.raises(AdminAuditExportError) as exc_info:
        service.export(format="json", actor_id=admin_user.id, now=now)
    assert exc_info.value.code == "integrity_error"
