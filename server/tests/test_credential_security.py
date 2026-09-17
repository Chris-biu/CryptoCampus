import base64
from datetime import datetime, timezone
import json
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.dependencies import get_crypto_engine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit import AuditLog
from app.models.credential import CredentialIssueIdempotency, CredentialLedger
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user
from app.services.signer_provider import get_signer_key_provider


class MockServerSignerKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x33" * SM2_PRIVATE_KEY_SIZE)

    def get_signer_private_key(self, service: str) -> bytes | None:
        return self.key


class DynamicMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            seed = f"hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


def _create_sqlite_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def _setup_security_env():
    session = _create_sqlite_session()
    user = User(
        id=str(uuid.uuid4()),
        email="security_test@campus.edu.cn",
        role="student",
        status="active",
    )
    session.add(user)
    session.commit()

    crypto = DynamicMockCryptoEngine()
    crypto.set_result("blind_sign", b"\x55" * 64)
    signer_provider = MockServerSignerKeyProvider()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_signer_key_provider] = lambda: signer_provider
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=user.id,
        role="student",
        status="active",
    )

    client = TestClient(app)
    today = datetime.now(timezone.utc).date().isoformat()
    return client, session, user, crypto, signer_provider, today


def test_security_prohibited_terms_not_in_database_and_audit_log():
    client, session, user, crypto, signer_provider, today = _setup_security_env()

    blinded_b64 = base64.b64encode(b"sens-blinded-data-sample").decode("ascii")
    idemp_key = "idemp-security-check-001"

    resp = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": idemp_key},
        json={
            "service": "hole_post",
            "period": today,
            "blinded_message": blinded_b64,
        },
    )
    assert resp.status_code == 201

    # Check database column names of CredentialIssueIdempotency
    inspector = inspect(session.bind)
    cols = [c["name"].lower() for c in inspector.get_columns("credential_issue_idempotency")]
    forbidden = ["sn", "serial_number", "blinding_factor", "unblinded", "raw_message", "plaintext", "private_key"]
    for f in forbidden:
        assert f not in cols, f"Forbidden column {f} found in credential_issue_idempotency"

    # Check audit log entries
    audit = session.query(AuditLog).filter_by(actor=user.id, action="credential.issue").one()
    assert len(audit.detail_hash) == 32
    # Ensure audit target does not include credential content
    assert audit.target == f"user:{user.id}"
    assert audit.action == "credential.issue"

    # Verify CryptoEngine call logs only contain lengths, not plaintext
    calls = [c for c in crypto.calls if c[0] == "blind_sign"]
    assert len(calls) == 1
    call_name, lengths = calls[0]
    assert "blinded_message" in lengths
    assert "signer_private_key" in lengths
    # Content must not be stored in call dict
    for k, v in lengths.items():
        assert isinstance(v, int), f"Call record for {k} must only record integer length"


def test_security_error_responses_never_leak_sensitive_internals():
    client, session, user, crypto, signer_provider, today = _setup_security_env()

    # 1. Validation error
    resp_val = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "short"},
        json={"service": "hole_post", "period": today, "blinded_message": "invalid"},
    )
    assert resp_val.status_code == 422
    val_body = resp_val.text.lower()
    for sensitive in ["private_key", "password", "token", "traceback", "exception"]:
        assert sensitive not in val_body

    # 2. Engine error
    crypto.set_error("blind_sign", CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))
    resp_eng = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "idemp-key-eng-err-001"},
        json={
            "service": "hole_post",
            "period": today,
            "blinded_message": base64.b64encode(b"test").decode("ascii"),
        },
    )
    assert resp_eng.status_code == 503
    eng_data = resp_eng.json()
    assert eng_data["code"] == "PROVIDER_UNAVAILABLE"
    # Never leak stack traces or engine internal representations
    assert "traceback" not in resp_eng.text.lower()
    assert "file " not in resp_eng.text.lower()


def test_security_frozen_and_pending_deletion_cannot_issue_and_no_side_effects():
    client, session, user, crypto, signer_provider, today = _setup_security_env()

    blinded_b64 = base64.b64encode(b"frozen-test-blinded").decode("ascii")

    # Frozen status
    user.status = "frozen"
    session.commit()

    resp_frozen = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "idemp-key-frozen-0001"},
        json={"service": "hole_post", "period": today, "blinded_message": blinded_b64},
    )
    assert resp_frozen.status_code == 401

    # Pending deletion status
    user.status = "pending_deletion"
    session.commit()

    resp_pending = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "idemp-key-pending-0001"},
        json={"service": "hole_post", "period": today, "blinded_message": blinded_b64},
    )
    assert resp_pending.status_code == 401

    # Zero side effects: no ledger, no idempotency, no audit
    assert session.query(CredentialLedger).count() == 0
    assert session.query(CredentialIssueIdempotency).count() == 0
    assert session.query(AuditLog).count() == 0
