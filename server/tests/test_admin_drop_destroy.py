from datetime import datetime, timezone
import hashlib
import uuid
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.models.admin_audit import AdminAuditEntry
from app.models.drop import Drop, DropExtractIdempotency
from app.models.user import User
from app.services.admin_audit import AdminAuditChainService
from app.services.admin_drop_governance import AdminDropGovernanceError, AdminDropGovernanceService


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


def _create_drop(db_session, crypto_engine, *, status="available", code="testlinkcode123456"):
    user1 = User(id=str(uuid.uuid4()), email="u1@campus.edu", role="student", status="active")
    user2 = User(id=str(uuid.uuid4()), email="u2@campus.edu", role="student", status="active")
    db_session.add_all([user1, user2])
    db_session.flush()

    code_hash = crypto_engine.sm3_digest(code.encode("utf-8"))
    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=user1.id,
        recipient_user_id=user2.id,
        link_code_hash=code_hash,
        kind="text",
        ciphertext=b"sensitive_secret_ciphertext",
        nonce=b"123456789012",
        tag=b"1234567890123456",
        enc_key_sm2=b"enc_key_sm2_bytes",
        enc_key_mlkem=b"enc_key_mlkem_bytes",
        sender_signature=b"sig" * 16,
        sender_certificate_der=b"cert_der",
        sender_cert_serial="cert_serial_1",
        recipient_sm2_fingerprint=b"fp" * 16,
        access_code_hash=crypto_engine.sm3_digest(b"secret_access_code"),
        access_factor_salt=b"salt" * 4,
        ttl_policy="hours_24",
        content_size=100,
        status=status,
    )
    db_session.add(drop)
    db_session.flush()

    # Add an extraction idempotency record
    extract_idemp = DropExtractIdempotency(
        drop_id=drop.id,
        key_hash=b"key_hash_" + b"0" * 23,
        request_hash=b"req_hash_" + b"0" * 23,
        inspect_record_id=str(uuid.uuid4()),
    )
    db_session.add(extract_idemp)
    db_session.commit()
    return drop


def test_admin_drop_destroy_success_wipes_sensitive_materials(db_session, crypto_engine, audit_chain_service, admin_user):
    drop_code = "mysecretlinkcode123"
    drop = _create_drop(db_session, crypto_engine, status="available", code=drop_code)
    drop_id = drop.id

    service = AdminDropGovernanceService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    now = datetime.now(timezone.utc)
    service.destroy(code=drop_code, actor_id=admin_user.id, now=now)
    db_session.commit()

    updated_drop = db_session.get(Drop, drop_id)
    assert updated_drop.status == "destroyed"
    assert updated_drop.ciphertext is None
    assert updated_drop.nonce is None
    assert updated_drop.tag is None
    assert updated_drop.enc_key_sm2 is None
    assert updated_drop.enc_key_mlkem is None
    assert updated_drop.sender_signature is None
    assert updated_drop.sender_certificate_der is None
    assert updated_drop.access_factor_salt is None
    # access_code_hash should be wiped to zeros so access code never matches
    assert updated_drop.access_code_hash == b"\x00" * 32

    # Extraction idempotency should be purged
    idemp_count = db_session.query(DropExtractIdempotency).filter_by(drop_id=drop_id).count()
    assert idemp_count == 0

    # Audit chain should contain drop.destroy
    entries = db_session.execute(select(AdminAuditEntry)).scalars().all()
    assert len(entries) == 1
    assert entries[0].action == "drop.destroy"
    assert entries[0].target == f"drop:{drop_id}"
    assert entries[0].actor_id == admin_user.id


def test_admin_drop_destroy_idempotent_no_duplicate_audit(db_session, crypto_engine, audit_chain_service, admin_user):
    drop_code = "already_destroyed_code"
    drop = _create_drop(db_session, crypto_engine, status="destroyed", code=drop_code)

    service = AdminDropGovernanceService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    now = datetime.now(timezone.utc)
    # First destroy on already destroyed drop
    service.destroy(code=drop_code, actor_id=admin_user.id, now=now)
    db_session.commit()

    # Second call
    service.destroy(code=drop_code, actor_id=admin_user.id, now=now)
    db_session.commit()

    # No audit entry should be written for already destroyed drop
    entries = db_session.execute(select(AdminAuditEntry)).scalars().all()
    assert len(entries) == 0


def test_admin_drop_destroy_not_found(db_session, crypto_engine, audit_chain_service, admin_user):
    service = AdminDropGovernanceService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    now = datetime.now(timezone.utc)
    with pytest.raises(AdminDropGovernanceError) as exc_info:
        service.destroy(code="nonexistent_code_xyz", actor_id=admin_user.id, now=now)
    assert exc_info.value.code == "not_found"


def test_admin_drop_destroy_does_not_invoke_decryption(db_session, crypto_engine, audit_chain_service, admin_user, monkeypatch):
    drop_code = "nodecryptcode123"
    drop = _create_drop(db_session, crypto_engine, status="available", code=drop_code)

    # Monkeypatch any potential decrypt method to raise if called
    def fail_if_called(*args, **kwargs):
        raise AssertionError("Decryption was invoked during drop destroy!")

    for method in ["sm2_decrypt", "envelope_open", "sm4_decrypt_cbc", "sm4_decrypt_gcm"]:
        if hasattr(crypto_engine, method):
            monkeypatch.setattr(crypto_engine, method, fail_if_called)

    service = AdminDropGovernanceService(
        session=db_session,
        crypto_engine=crypto_engine,
        audit_chain_service=audit_chain_service,
    )
    now = datetime.now(timezone.utc)
    # Must succeed without decrypting
    service.destroy(code=drop_code, actor_id=admin_user.id, now=now)
    db_session.commit()

    updated = db_session.get(Drop, drop.id)
    assert updated.status == "destroyed"
