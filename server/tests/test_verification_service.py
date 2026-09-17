import json
import base64
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from app.core.config import Settings, get_settings
from app.db.session import init_database
from app.main import create_app
from app.models.verification import VerificationRecord
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.crypto.mock import MockCryptoEngine
from app.schemas.verification import VerificationResult, VerificationStep
from app.services.verifications import FiveStepVerificationService, parse_seal_sidecar


def test_verification_result_requires_the_fixed_five_steps_in_order() -> None:
    steps = [
        VerificationStep(name="digest", passed=True, message="文件摘要一致"),
        VerificationStep(name="signature", passed=True, message="签名有效"),
        VerificationStep(name="certificate_chain", passed=True, message="证书链可信"),
        VerificationStep(name="timestamp", passed=True, message="签章时间有效"),
        VerificationStep(name="revocation", passed=True, message="证书未吊销"),
    ]

    result = VerificationResult(valid=True, steps=steps, record_digest="a" * 64)

    assert [step.name for step in result.steps] == [
        "digest",
        "signature",
        "certificate_chain",
        "timestamp",
        "revocation",
    ]


def test_verification_result_rejects_missing_or_reordered_steps() -> None:
    steps = [
        VerificationStep(name="signature", passed=False, message="签名无效"),
        VerificationStep(name="digest", passed=False, message="摘要不一致"),
    ]

    try:
        VerificationResult(valid=False, steps=steps, record_digest="a" * 64)
    except ValueError:
        pass
    else:
        raise AssertionError("VerificationResult must reject a non-canonical step sequence")


def test_sidecar_parser_rejects_unknown_or_duplicate_fields() -> None:
    with pytest.raises(Exception):
        parse_seal_sidecar(b'{"id":"x","id":"x"}')
    with pytest.raises(Exception):
        parse_seal_sidecar(json.dumps({"unexpected": True}).encode())


def test_verification_record_never_has_file_or_sidecar_columns(db_engine) -> None:
    init_database(db_engine)
    columns = {column["name"] for column in inspect(db_engine).get_columns("verification_records")}
    assert {"record_digest", "file_digest", "valid"} <= columns
    assert not columns & {"file", "file_bytes", "source_file", "seal", "seal_bytes", "filename", "private_key"}


def test_service_returns_all_steps_and_persists_only_digest_record(db_session) -> None:
    user = User(id=str(uuid.uuid4()), email="verify@example.edu", role="student", status="active", pubkey=b"p" * 65)
    root_user = User(id=str(uuid.uuid4()), email="ca@example.edu", role="system", status="active")
    certificate = b"leaf-certificate"
    db_session.add_all([user, root_user])
    db_session.flush()
    db_session.add_all([
        CertificateRecord(serial="root", subject_user_id=root_user.id, issuer_serial="root", kind="platform_ca", certificate_der=b"root-certificate", key_usage="keyCertSign,cRLSign", not_before=datetime(2020, 1, 1, tzinfo=timezone.utc), not_after=datetime(2030, 1, 1, tzinfo=timezone.utc), status="active"),
        CertificateRecord(serial="leaf", subject_user_id=user.id, issuer_serial="root", kind="user_identity", certificate_der=certificate, key_usage="digitalSignature", not_before=datetime(2026, 1, 1, tzinfo=timezone.utc), not_after=datetime(2027, 1, 1, tzinfo=timezone.utc), status="active"),
    ])
    db_session.commit()
    engine = MockCryptoEngine()
    engine.set_result("sm3_digest", b"d" * 32)
    engine.set_result("constant_time_equal", True)
    engine.set_result("sm2_verify", True)
    engine.set_result("cert_chain_verify", True)
    sidecar = json.dumps({"certificate": base64.b64encode(certificate).decode(), "digest": base64.b64encode(b"d" * 32).decode(), "digest_algorithm": "SM3", "id": str(uuid.uuid4()), "signature": base64.b64encode(b"s" * 64).decode(), "signature_algorithm": "SM3-with-SM2", "timestamp": "2026-09-04T12:00:00Z"}, sort_keys=True, separators=(",", ":")).encode()

    result = FiveStepVerificationService(db_session, engine, 1024).verify(b"file", sidecar)

    assert result.valid is True
    assert [step.name for step in result.steps] == ["digest", "signature", "certificate_chain", "timestamp", "revocation"]
    record = db_session.query(VerificationRecord).one()
    assert record.file_digest == b"d" * 32 and record.valid is True


def test_verifications_rejects_malformed_sidecar_with_422() -> None:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: Settings(seal_and_verify_max_bytes=1024)
    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/verifications",
                files={"file": ("file.bin", b"content", "application/octet-stream"), "seal": ("seal.ccseal", b"{", "application/octet-stream")},
            )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 422
