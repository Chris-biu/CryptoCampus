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
    # import app.models to ensure all models are registered on Base.metadata
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_drop_and_idempotency_models_registered_and_boundaries() -> None:
    from app.models.drop import Drop, DropIdempotency

    session = _create_sqlite_session()

    # Verify no prohibited columns exist
    drop_cols = {c.name for c in inspect(Drop).columns}
    prohibited = {"access_code", "access_password", "plaintext", "private_key", "session_key", "kek"}
    assert not (drop_cols & prohibited)

    idemp_cols = {c.name for c in inspect(DropIdempotency).columns}
    assert not (idemp_cols & prohibited)

    # Create users
    owner = User(id=str(uuid.uuid4()), email="owner@stu.edu.cn", role="student", status="active")
    recipient = User(id=str(uuid.uuid4()), email="recv@stu.edu.cn", role="student", status="active")
    session.add_all([owner, recipient])
    session.commit()

    # Create Drop
    drop_id = str(uuid.uuid4())
    drop = Drop(
        id=drop_id,
        owner_user_id=owner.id,
        recipient_user_id=recipient.id,
        link_code_hash=b"\x01" * 32,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted",
        nonce=b"\x02" * 12,
        tag=b"\x03" * 16,
        enc_key_sm2=b"\x04" * 96,
        enc_key_mlkem=None,
        sender_signature=b"\x05" * 64,
        sender_certificate_der=b"\x30\x82\x01\x00" + b"\x06" * 50,
        sender_cert_serial="CERT-001",
        recipient_sm2_fingerprint=b"\x07" * 32,
        recipient_mlkem_fingerprint=None,
        access_code_hash=b"\x08" * 32,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=datetime.now(timezone.utc),
        filename=None,
        content_size=len("hello"),
        pqc_mode=False,
        status="available",
    )
    session.add(drop)
    session.commit()

    loaded_drop = session.get(Drop, drop_id)
    assert loaded_drop is not None
    assert loaded_drop.kind == "text"
    assert loaded_drop.link_code_hash == b"\x01" * 32
    assert loaded_drop.status == "available"

    # Test link_code_hash unique constraint
    duplicate_drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=owner.id,
        recipient_user_id=recipient.id,
        link_code_hash=b"\x01" * 32,  # duplicate
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted2",
        nonce=b"\x02" * 12,
        tag=b"\x03" * 16,
        enc_key_sm2=b"\x04" * 96,
        sender_signature=b"\x05" * 64,
        sender_certificate_der=b"\x30\x82\x01\x00" + b"\x06" * 50,
        sender_cert_serial="CERT-002",
        recipient_sm2_fingerprint=b"\x07" * 32,
        access_code_hash=b"\x09" * 32,
        ttl_policy="hours_24",
        burn_after_read=False,
        content_size=10,
        pqc_mode=False,
    )
    session.add(duplicate_drop)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

    # Create DropIdempotency
    idemp_id = str(uuid.uuid4())
    idemp = DropIdempotency(
        id=idemp_id,
        owner_user_id=owner.id,
        operation="create_text",
        key_hash=b"\xaa" * 32,
        request_hash=b"\xbb" * 32,
        drop_id=drop_id,
    )
    session.add(idemp)
    session.commit()

    loaded_idemp = session.get(DropIdempotency, idemp_id)
    assert loaded_idemp is not None
    assert loaded_idemp.operation == "create_text"

    # Test (owner_user_id, operation, key_hash) unique constraint
    dup_idemp = DropIdempotency(
        id=str(uuid.uuid4()),
        owner_user_id=owner.id,
        operation="create_text",
        key_hash=b"\xaa" * 32,  # duplicate
        request_hash=b"\xcc" * 32,
        drop_id=drop_id,
    )
    session.add(dup_idemp)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_drop_schemas_validation() -> None:
    from app.schemas.drop import CreateDropResponse, CreateTextDropRequest

    # Valid text drop request
    req = CreateTextDropRequest(
        content="Secret message",
        ttl_policy="hours_24",
        pqc_mode=False,
        access_password="custom_password_123",
    )
    assert req.content == "Secret message"
    assert req.ttl_policy == "hours_24"
    assert req.pqc_mode is False
    assert req.access_password == "custom_password_123"

    # Invalid empty content
    with pytest.raises(Exception):
        CreateTextDropRequest(content="", ttl_policy="hours_24", pqc_mode=False)

    # Invalid ttl_policy
    with pytest.raises(Exception):
        CreateTextDropRequest(content="hello", ttl_policy="invalid_ttl", pqc_mode=False)

    # Valid response
    now = datetime.now(timezone.utc)
    drop_uuid = str(uuid.uuid4())
    resp = CreateDropResponse(
        id=drop_uuid,
        code="abc123DEF456ghi7",
        access_code="ABCD1234EFGH5678",
        url="/d/abc123DEF456ghi7",
        expires_at=now,
        pqc_mode=False,
    )
    assert resp.id == drop_uuid
    assert resp.code == "abc123DEF456ghi7"
    assert resp.access_code == "ABCD1234EFGH5678"
