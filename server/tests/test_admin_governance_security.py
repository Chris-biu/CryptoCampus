from datetime import datetime, timezone
import hashlib
import json
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.system import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.drop import Drop
from app.models.hole import HolePost
from app.models.inspect import InspectRecord
from app.models.user import User
from app.models.vote import VoteRecord
from app.security.auth_dependencies import CurrentUser, get_current_user


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


FORBIDDEN_SENSITIVE_PATTERNS = [
    "PRIVATE KEY",
    "auth_hash",
    "salt_a",
    "salt_k",
    "enc_sk",
    "enc_pqc_sk",
    "super_secret_cleartext",
    "secret_author_identity",
    "anonymous_voter_ssn",
    "classified_reason_detail_leak",
    "raw_intermediate_step_trace",
]


@pytest.fixture
def app_with_seed():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    crypto_engine = DeterministicMockCryptoEngine()

    session = session_factory()
    admin = User(
        id=str(uuid.uuid4()),
        email="admin@campus.edu",
        role="admin",
        status="active",
        auth_hash=b"secret_auth_hash_bytes",
        salt_a=b"salt_a_secret",
        salt_k=b"salt_k_secret",
    )
    student = User(
        id=str(uuid.uuid4()),
        email="student@campus.edu",
        role="student",
        status="active",
        auth_hash=b"student_auth_hash_bytes",
    )
    session.add_all([admin, student])
    session.commit()

    # Create drop
    code = "securitylink1234"
    code_hash = crypto_engine.sm3_digest(code.encode("utf-8"))
    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=student.id,
        recipient_user_id=admin.id,
        link_code_hash=code_hash,
        kind="text",
        ciphertext=b"super_secret_cleartext_ciphertext",
        nonce=b"1" * 12,
        tag=b"2" * 16,
        enc_key_sm2=b"sm2",
        sender_cert_serial="serial",
        recipient_sm2_fingerprint=b"fp" * 16,
        access_code_hash=b"0" * 32,
        ttl_policy="hours_24",
        content_size=100,
        status="available",
    )
    # Create hole post
    post = HolePost(
        id=str(uuid.uuid4()),
        content="Hole post content with secret_author_identity",
        credential_sn=b"cred_sn_12345678",
        credential_service="hole_post",
        credential_period="2026-09",
        credential_signature=b"sig" * 16,
        credential_prefix="ABCD",
        credential_valid=True,
        status="published",
        created_at=datetime.now(timezone.utc),
    )
    # Create inspect record with sensitive steps
    inspect = InspectRecord(
        id=str(uuid.uuid4()),
        operation="sm4_ecb_inspect",
        owner_user_id=student.id,
        steps_json='["raw_intermediate_step_trace", "secret_round_key"]',
        redacted_values_json='{"classified_reason_detail_leak": "value"}',
        created_at=datetime.now(timezone.utc),
    )
    # Create vote
    vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=admin.id,
        title="Vote Title",
        description="Vote Description",
        scope="public",
        closes_at=datetime.now(timezone.utc),
        status="open",
    )
    session.add_all([drop, post, inspect, vote])
    session.commit()
    session.close()

    app = create_app()

    def override_get_db():
        s = session_factory()
        try:
            yield s
        finally:
            s.close()

    def override_crypto_engine():
        return crypto_engine

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_crypto_engine] = override_crypto_engine

    return {
        "app": app,
        "admin": admin,
        "student": student,
        "code": code,
        "vote": vote,
        "post": post,
    }


def _admin_client(app, admin):
    client = TestClient(app)
    current = CurrentUser(
        user_id=admin.id,
        role=admin.role,
        status=admin.status,
        session_id=str(uuid.uuid4()),
    )
    app.dependency_overrides[get_current_user] = lambda: current
    return client


def test_no_sensitive_fields_in_admin_responses_and_exports(app_with_seed):
    app = app_with_seed["app"]
    admin = app_with_seed["admin"]
    code = app_with_seed["code"]
    vote = app_with_seed["vote"]
    post = app_with_seed["post"]
    client = _admin_client(app, admin)

    # 1. User listing response
    res = client.get("/api/v1/admin/users")
    assert res.status_code == 200
    user_text = res.text
    for pattern in ["auth_hash", "salt_a", "salt_k", "enc_sk", "enc_pqc_sk"]:
        assert pattern not in user_text

    # 2. Inspect records response
    res = client.get("/api/v1/admin/inspect-records")
    assert res.status_code == 200
    inspect_text = res.text
    assert "raw_intermediate_step_trace" not in inspect_text
    assert "classified_reason_detail_leak" not in inspect_text
    assert "steps" not in inspect_text
    assert "redacted_values" not in inspect_text

    # 3. Destroy drop
    res = client.post(f"/api/v1/admin/drops/{code}/destroy")
    assert res.status_code == 204

    # 4. Flag vote with private reason
    flag_reason = "secret_audit_detection_reason_must_not_leak"
    res = client.post(
        f"/api/v1/admin/votes/{vote.id}/audit-flags",
        json={"reason": flag_reason},
    )
    assert res.status_code == 201

    # 5. Export audit (JSON & CSV)
    res_json = client.get("/api/v1/admin/audit/export?format=json")
    assert res_json.status_code == 200
    export_json_text = res_json.text
    assert flag_reason not in export_json_text

    res_csv = client.get("/api/v1/admin/audit/export?format=csv")
    assert res_csv.status_code == 200
    export_csv_text = res_csv.text
    assert flag_reason not in export_csv_text
