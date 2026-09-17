import base64
from datetime import datetime, timezone
import uuid
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.crypto.unavailable import UnavailableCryptoEngine
from app.db.base import Base
from app.db.session import create_db_engine, init_database
from app.models.user import User


def _create_sqlite_session():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_credential_issue_idempotency_table_structure_and_constraints():
    from app.models.credential import CredentialIssueIdempotency

    session = _create_sqlite_session()

    cols = {c.name: c for c in inspect(CredentialIssueIdempotency).columns}
    required_cols = {
        "id",
        "user_id",
        "service",
        "period",
        "key_hash",
        "request_hash",
        "blind_signature",
        "created_at",
    }
    assert required_cols <= set(cols.keys())

    # Verify no prohibited columns exist
    prohibited_cols = {
        "sn",
        "serial_number",
        "blinding_factor",
        "unblinded",
        "plaintext",
        "raw_message",
        "m",
        "private_key",
        "token",
    }
    assert not (set(cols.keys()) & prohibited_cols)

    # Insert test user
    user = User(
        id=str(uuid.uuid4()),
        email="student@campus.edu.cn",
        role="student",
        status="active",
    )
    session.add(user)
    session.commit()

    key_hash = b"\x01" * 32
    request_hash = b"\x02" * 32
    blind_sig = b"\x03" * 64

    record = CredentialIssueIdempotency(
        user_id=user.id,
        service="hole_post",
        period="2026-09-09",
        key_hash=key_hash,
        request_hash=request_hash,
        blind_signature=blind_sig,
    )
    session.add(record)
    session.commit()

    assert record.id is not None
    assert record.created_at is not None
    assert record.created_at.tzinfo is not None or record.created_at <= datetime.now(timezone.utc)
    assert record.blind_signature == blind_sig


def test_credential_issue_idempotency_unique_constraint():
    from app.models.credential import CredentialIssueIdempotency

    session = _create_sqlite_session()

    user = User(
        id=str(uuid.uuid4()),
        email="student2@campus.edu.cn",
        role="student",
        status="active",
    )
    session.add(user)
    session.commit()

    key_hash = b"\x11" * 32
    request_hash1 = b"\x22" * 32
    request_hash2 = b"\x33" * 32

    r1 = CredentialIssueIdempotency(
        user_id=user.id,
        service="hole_post",
        period="2026-09-09",
        key_hash=key_hash,
        request_hash=request_hash1,
        blind_signature=b"sig1",
    )
    session.add(r1)
    session.commit()

    # Same (user_id, service, period, key_hash) must violate unique constraint
    r2 = CredentialIssueIdempotency(
        user_id=user.id,
        service="hole_post",
        period="2026-09-09",
        key_hash=key_hash,
        request_hash=request_hash2,
        blind_signature=b"sig2",
    )
    session.add(r2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_credential_issue_idempotency_user_cascade_delete():
    from app.models.credential import CredentialIssueIdempotency

    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    user = User(
        id=str(uuid.uuid4()),
        email="student3@campus.edu.cn",
        role="student",
        status="active",
    )
    session.add(user)
    session.commit()

    r = CredentialIssueIdempotency(
        user_id=user.id,
        service="hole_post",
        period="2026-09-09",
        key_hash=b"\x44" * 32,
        request_hash=b"\x55" * 32,
        blind_signature=b"sig",
    )
    session.add(r)
    session.commit()
    record_id = r.id

    session.delete(user)
    session.commit()

    session2 = session_factory()
    assert session2.get(CredentialIssueIdempotency, record_id) is None
    session.close()
    session2.close()


def test_blind_credential_request_schema_validation():
    from app.schemas.credential import BlindCredentialRequest

    valid_b64 = base64.b64encode(b"test-blinded-message").decode("ascii")

    req = BlindCredentialRequest(
        service="hole_post",
        period="2026-09-09",
        blinded_message=valid_b64,
    )
    assert req.service == "hole_post"
    assert req.period == "2026-09-09"
    assert req.blinded_message == valid_b64

    # Extra fields forbidden
    with pytest.raises(ValidationError):
        BlindCredentialRequest(
            service="hole_post",
            period="2026-09-09",
            blinded_message=valid_b64,
            sn="should-not-exist",
        )

    # Invalid service enum
    with pytest.raises(ValidationError):
        BlindCredentialRequest(
            service="invalid_service",
            period="2026-09-09",
            blinded_message=valid_b64,
        )

    # Period too long
    with pytest.raises(ValidationError):
        BlindCredentialRequest(
            service="hole_post",
            period="a" * 65,
            blinded_message=valid_b64,
        )

    # Invalid base64
    with pytest.raises(ValidationError):
        BlindCredentialRequest(
            service="hole_post",
            period="2026-09-09",
            blinded_message="!!!not-valid-base64!!!",
        )


def test_blind_credential_response_schema_validation():
    from app.schemas.credential import BlindCredentialResponse

    valid_sig_b64 = base64.b64encode(b"dummy-blind-signature-bytes").decode("ascii")

    resp = BlindCredentialResponse(
        blind_signature=valid_sig_b64,
        algorithm="SM2-BLIND-PROTOCOL-V1",
    )
    assert resp.blind_signature == valid_sig_b64
    assert resp.algorithm == "SM2-BLIND-PROTOCOL-V1"

    # Default algorithm
    resp_default = BlindCredentialResponse(blind_signature=valid_sig_b64)
    assert resp_default.algorithm == "SM2-BLIND-PROTOCOL-V1"

    # Extra fields forbidden
    with pytest.raises(ValidationError):
        BlindCredentialResponse(
            blind_signature=valid_sig_b64,
            algorithm="SM2-BLIND-PROTOCOL-V1",
            user_id=str(uuid.uuid4()),
        )

    # Invalid algorithm
    with pytest.raises(ValidationError):
        BlindCredentialResponse(
            blind_signature=valid_sig_b64,
            algorithm="INVALID-ALGO",  # type: ignore
        )


def test_crypto_engine_blind_sign_protocol_and_unavailable():
    engine = UnavailableCryptoEngine()
    assert isinstance(engine, CryptoEngine)

    with pytest.raises(CryptoBridgeError) as exc_info:
        engine.blind_sign(
            blinded_message=b"blinded",
            signer_private_key=b"\xaa" * SM2_PRIVATE_KEY_SIZE,
        )
    assert exc_info.value.code == BridgeErrorCode.PROVIDER_UNAVAILABLE


def test_mock_crypto_engine_blind_sign_behaviour():
    mock = MockCryptoEngine()
    assert isinstance(mock, CryptoEngine)

    blinded_msg = b"some-blinded-bytes-12345"
    key = b"\xbb" * SM2_PRIVATE_KEY_SIZE
    fake_sig = b"\xcc" * 64

    # Default without set_result raises UNSUPPORTED
    with pytest.raises(CryptoBridgeError) as exc_info:
        mock.blind_sign(blinded_message=blinded_msg, signer_private_key=key)
    assert exc_info.value.code == BridgeErrorCode.UNSUPPORTED

    # Calls record only lengths, not plaintext content
    assert len(mock.calls) == 1
    op_name, lengths = mock.calls[0]
    assert op_name == "blind_sign"
    assert lengths == {
        "blinded_message": len(blinded_msg),
        "signer_private_key": SM2_PRIVATE_KEY_SIZE,
    }

    # Set success result
    mock.set_result("blind_sign", fake_sig)
    sig = mock.blind_sign(blinded_message=blinded_msg, signer_private_key=key)
    assert sig == fake_sig

    # Invalid key length
    with pytest.raises(CryptoBridgeError) as exc_info:
        mock.blind_sign(blinded_message=blinded_msg, signer_private_key=b"short-key")
    assert exc_info.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # Empty blinded message
    with pytest.raises(CryptoBridgeError) as exc_info:
        mock.blind_sign(blinded_message=b"", signer_private_key=key)
    assert exc_info.value.code == BridgeErrorCode.INVALID_ARGUMENT
