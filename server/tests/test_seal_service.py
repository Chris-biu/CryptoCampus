import io
import json
import struct
import uuid
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.datastructures import UploadFile

from app.core.errors import ApiError
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import ProviderStatus
from app.db.base import Base
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord
from app.models.seal import Seal
from app.models.user import User
from app.pki.material import UnavailablePlatformCAMaterialProvider
from app.pki.service import PlatformCAService
from app.schemas.seal import SealResponse, SealProfile, OutputFormat
from app.security.auth_dependencies import CurrentUser
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.seals import (
    SealService,
    SealSignerMaterial,
    SealSignerMaterialProvider,
    encode_seal_payload,
    generate_sidecar_bytes,
    validate_and_read_file,
)


class DynamicMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        # Record call
        self._calls.append(("sm3_digest", {"message": len(message)}))
        if "sm3_digest" in self._errors:
            raise self._errors["sm3_digest"]
        if message not in self._digests:
            self._counter += 1
            seed = f"sm3-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


class DummySealSignerMaterialProvider:
    def __init__(self, materials: dict[str, SealSignerMaterial] | None = None) -> None:
        self._materials = materials or {}

    def get_seal_material(self, profile: str) -> SealSignerMaterial | None:
        return self._materials.get(profile)


def _setup_db_and_ca():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    crypto = DynamicMockCryptoEngine()
    ca_service = PlatformCAService(session, crypto, UnavailablePlatformCAMaterialProvider())

    # Create CA root record
    ca_user = User(
        id=str(uuid.uuid4()),
        email="ca@campus.edu.cn",
        role="system",
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    session.add(ca_user)
    ca_cert = CertificateRecord(
        serial="ca-serial-001",
        subject_user_id=ca_user.id,
        issuer_serial="ca-serial-001",
        kind="platform_ca",
        certificate_der=b"CA_CERT_DER_" * 4,
        key_usage="keyCertSign,cRLSign",
        not_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2035, 1, 1, tzinfo=timezone.utc),
        status="active",
    )
    session.add(ca_cert)
    session.commit()
    return session, crypto, ca_service, ca_user, ca_cert


def _create_user_with_cert(
    session: Session,
    role: str = "student",
    email: str = "student@campus.edu.cn",
    cert_status: str = "active",
    ca_serial: str = "ca-serial-001",
):
    user = User(
        id=str(uuid.uuid4()),
        email=email,
        role=role,
        status="active",
        cert_serial=f"cert-{uuid.uuid4().hex[:8]}",
        created_at=datetime.now(timezone.utc),
    )
    session.add(user)
    cert = CertificateRecord(
        serial=user.cert_serial,
        subject_user_id=user.id,
        issuer_serial=ca_serial,
        kind="user_identity",
        certificate_der=b"USER_CERT_DER_" * 4,
        key_usage="digitalSignature,keyEncipherment,keyAgreement",
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        status=cert_status,
    )
    session.add(cert)
    session.commit()
    return user, cert


# ================= Task 1 Tests =================

def test_seal_response_schema_strictly_enforces_seven_fields():
    valid_data = {
        "id": str(uuid.uuid4()),
        "digest_algorithm": "SM3",
        "digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "signature_algorithm": "SM3-with-SM2",
        "signature": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==",
        "certificate": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        "timestamp": "2026-09-04T12:00:00Z",
    }
    response = SealResponse.model_validate(valid_data)
    assert response.id == valid_data["id"]
    assert response.digest_algorithm == "SM3"
    assert response.signature_algorithm == "SM3-with-SM2"

    with pytest.raises(ValidationError):
        SealResponse.model_validate({**valid_data, "source_file": "secret.pdf"})

    with pytest.raises(ValidationError):
        SealResponse.model_validate({**valid_data, "private_key": "raw_sk"})

    for key in valid_data:
        invalid = dict(valid_data)
        del invalid[key]
        with pytest.raises(ValidationError):
            SealResponse.model_validate(invalid)


def test_seal_model_table_structure_and_sensitive_boundaries():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)

    inspector = inspect(engine)
    columns = {col["name"]: col for col in inspector.get_columns("seals")}
    expected_columns = {
        "id", "signer_user_id", "seal_profile", "digest_algorithm", "digest",
        "signature_algorithm", "signature", "certificate_der", "timestamp",
        "output_format", "idempotency_key_digest", "request_fingerprint", "created_at",
    }
    assert expected_columns.issubset(columns.keys())

    forbidden_columns = {
        "source_file", "file_content", "file_path", "filename", "raw_file",
        "private_key", "secret_key", "kek", "password", "token", "idempotency_key",
    }
    assert not any(col in columns for col in forbidden_columns)


# ================= Task 2 Tests =================

def test_validate_and_read_file_success_and_failures():
    # Success PDF
    pdf_bytes = b"%PDF-1.7 valid content for pdf"
    upload = UploadFile(file=io.BytesIO(pdf_bytes), filename="sample.pdf", headers={"content-type": "application/pdf"})
    read = validate_and_read_file(upload, max_bytes=1024)
    assert read == pdf_bytes

    # Success PNG
    png_bytes = b"\x89PNG\r\n\x1a\nvalid png content"
    upload = UploadFile(file=io.BytesIO(png_bytes), filename="sample.png", headers={"content-type": "image/png"})
    read = validate_and_read_file(upload, max_bytes=1024)
    assert read == png_bytes

    # Success JPEG
    jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF"
    upload = UploadFile(file=io.BytesIO(jpeg_bytes), filename="sample.jpg", headers={"content-type": "image/jpeg"})
    read = validate_and_read_file(upload, max_bytes=1024)
    assert read == jpeg_bytes

    # Failure: Empty file (0 bytes) -> 422
    upload = UploadFile(file=io.BytesIO(b""), filename="empty.pdf", headers={"content-type": "application/pdf"})
    with pytest.raises(ApiError) as exc:
        validate_and_read_file(upload, max_bytes=1024)
    assert exc.value.status_code == 422

    # Failure: Exceeds max_bytes -> 413
    upload = UploadFile(file=io.BytesIO(b"%PDF-" + b"0" * 200), filename="big.pdf", headers={"content-type": "application/pdf"})
    with pytest.raises(ApiError) as exc:
        validate_and_read_file(upload, max_bytes=100)
    assert exc.value.status_code == 413

    # Failure: Wrong magic bytes (SVG script pretending to be pdf) -> 422
    upload = UploadFile(file=io.BytesIO(b"<svg onload=alert(1)>"), filename="fake.pdf", headers={"content-type": "application/pdf"})
    with pytest.raises(ApiError) as exc:
        validate_and_read_file(upload, max_bytes=1024)
    assert exc.value.status_code == 422

    # Failure: Disallowed MIME (text/plain) -> 422
    upload = UploadFile(file=io.BytesIO(b"hello world"), filename="test.txt", headers={"content-type": "text/plain"})
    with pytest.raises(ApiError) as exc:
        validate_and_read_file(upload, max_bytes=1024)
    assert exc.value.status_code == 422


# ================= Task 3 Tests =================

def test_encode_seal_payload_deterministic_and_tamper_evident():
    file_digest = b"\x11" * 32
    cert_der = b"\x22" * 64
    ts = 1788523200

    payload = encode_seal_payload(file_digest, cert_der, ts)
    assert payload.startswith(b"CryptoCampus-Seal-v1\x00")

    # Structure check
    prefix = b"CryptoCampus-Seal-v1\x00"
    offset = len(prefix)
    f_len = struct.unpack(">I", payload[offset : offset + 4])[0]
    assert f_len == 32
    offset += 4
    assert payload[offset : offset + 32] == file_digest
    offset += 32
    c_len = struct.unpack(">I", payload[offset : offset + 4])[0]
    assert c_len == 64
    offset += 4
    assert payload[offset : offset + 64] == cert_der
    offset += 64
    unpacked_ts = struct.unpack(">Q", payload[offset : offset + 8])[0]
    assert unpacked_ts == ts

    # Tampering test: 1 byte difference in file_digest changes payload
    payload_tampered_file = encode_seal_payload(b"\x12" + b"\x11" * 31, cert_der, ts)
    assert payload != payload_tampered_file

    # Tampering test: 1 byte difference in cert_der changes payload
    payload_tampered_cert = encode_seal_payload(file_digest, b"\x23" + b"\x22" * 63, ts)
    assert payload != payload_tampered_cert

    # Tampering test: 1 second difference in timestamp changes payload
    payload_tampered_ts = encode_seal_payload(file_digest, cert_der, ts + 1)
    assert payload != payload_tampered_ts


def test_seal_service_call_sequence_and_lengths():
    session, crypto, ca_service, ca_user, ca_cert = _setup_db_and_ca()
    user, cert = _create_user_with_cert(session, role="student")

    key_cache = PrivateKeyUnlockCache()
    private_key = b"k" * 32
    key_cache.put(user.id, private_key, datetime(2030, 1, 1, tzinfo=timezone.utc))

    # Mock SM2 sign and cert chain verify
    crypto.set_result("sm2_sign", b"S" * 64)
    crypto.set_result("cert_chain_verify", True)

    service = SealService(
        session=session,
        crypto_engine=crypto,
        ca_service=ca_service,
        key_cache=key_cache,
        seal_material_provider=DummySealSignerMaterialProvider(),
        max_bytes=1024 * 1024,
    )

    pdf_bytes = b"%PDF-1.7 minimal content"
    current_user = CurrentUser(user_id=user.id, role="student", status="active")

    result = service.create_seal(
        current_user=current_user,
        file_bytes=pdf_bytes,
        mime_type="application/pdf",
        seal_profile="personal",
        pqc_mode=False,
        output_format="sidecar",
        idempotency_key="idemp-key-1234567890",
    )

    assert isinstance(result, SealResponse)
    assert result.digest_algorithm == "SM3"
    assert result.signature_algorithm == "SM3-with-SM2"

    # Verify operation call sequence:
    # sm3_digest(file) -> cert_chain_verify -> sm3_digest(payload) -> sm2_sign
    op_names = [call[0] for call in crypto.calls]
    assert "sm3_digest" in op_names
    assert "cert_chain_verify" in op_names
    assert "sm2_sign" in op_names

    # Assert lengths recorded in engine calls
    sm2_calls = [call for call in crypto.calls if call[0] == "sm2_sign"]
    assert len(sm2_calls) == 1
    assert sm2_calls[0][1]["private_key"] == 32
    assert sm2_calls[0][1]["digest"] == 32


def test_seal_service_role_matrix_enforcement():
    session, crypto, ca_service, ca_user, ca_cert = _setup_db_and_ca()
    student, student_cert = _create_user_with_cert(session, role="student", email="s@campus.edu.cn")
    admin, admin_cert = _create_user_with_cert(session, role="admin", email="a@campus.edu.cn")
    teacher, teacher_cert = _create_user_with_cert(session, role="teacher", email="t@campus.edu.cn")

    key_cache = PrivateKeyUnlockCache()
    key_cache.put(student.id, b"s" * 32, datetime(2030, 1, 1, tzinfo=timezone.utc))
    key_cache.put(admin.id, b"a" * 32, datetime(2030, 1, 1, tzinfo=timezone.utc))
    key_cache.put(teacher.id, b"t" * 32, datetime(2030, 1, 1, tzinfo=timezone.utc))

    # Department and academic system materials
    dept_material = SealSignerMaterial(user_id=ca_user.id, certificate_der=ca_cert.certificate_der, private_key=b"d" * 32)
    acad_material = SealSignerMaterial(user_id=ca_user.id, certificate_der=ca_cert.certificate_der, private_key=b"e" * 32)
    provider = DummySealSignerMaterialProvider({"department": dept_material, "academic": acad_material})

    crypto.set_result("sm2_sign", b"S" * 64)
    crypto.set_result("cert_chain_verify", True)

    service = SealService(
        session=session,
        crypto_engine=crypto,
        ca_service=ca_service,
        key_cache=key_cache,
        seal_material_provider=provider,
        max_bytes=1024 * 1024,
    )

    pdf = b"%PDF-test"

    # 1. Student requesting department seal -> 403
    with pytest.raises(ApiError) as exc:
        service.create_seal(
            current_user=CurrentUser(student.id, "student", "active"),
            file_bytes=pdf,
            mime_type="application/pdf",
            seal_profile="department",
            pqc_mode=False,
            output_format="sidecar",
            idempotency_key="idemp-key-dept-001",
        )
    assert exc.value.status_code == 403

    # 2. Student requesting academic seal -> 403
    with pytest.raises(ApiError) as exc:
        service.create_seal(
            current_user=CurrentUser(student.id, "student", "active"),
            file_bytes=pdf,
            mime_type="application/pdf",
            seal_profile="academic",
            pqc_mode=False,
            output_format="sidecar",
            idempotency_key="idemp-key-acad-001",
        )
    assert exc.value.status_code == 403

    # 3. Admin requesting academic seal -> 403
    with pytest.raises(ApiError) as exc:
        service.create_seal(
            current_user=CurrentUser(admin.id, "admin", "active"),
            file_bytes=pdf,
            mime_type="application/pdf",
            seal_profile="academic",
            pqc_mode=False,
            output_format="sidecar",
            idempotency_key="idemp-key-acad-002",
        )
    assert exc.value.status_code == 403

    # 4. Admin requesting department seal -> 201 Success
    res = service.create_seal(
        current_user=CurrentUser(admin.id, "admin", "active"),
        file_bytes=pdf,
        mime_type="application/pdf",
        seal_profile="department",
        pqc_mode=False,
        output_format="sidecar",
        idempotency_key="idemp-key-dept-002",
    )
    assert res.signature_algorithm == "SM3-with-SM2"

    # 5. Teacher requesting academic seal -> 201 Success
    res = service.create_seal(
        current_user=CurrentUser(teacher.id, "teacher", "active"),
        file_bytes=pdf,
        mime_type="application/pdf",
        seal_profile="academic",
        pqc_mode=False,
        output_format="sidecar",
        idempotency_key="idemp-key-acad-003",
    )
    assert res.signature_algorithm == "SM3-with-SM2"


# ================= Task 4 Tests =================

def test_seal_idempotency_replay_and_conflict():
    session, crypto, ca_service, ca_user, ca_cert = _setup_db_and_ca()
    user, cert = _create_user_with_cert(session, role="student")
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(user.id, b"k" * 32, datetime(2030, 1, 1, tzinfo=timezone.utc))

    crypto.set_result("sm2_sign", b"S" * 64)
    crypto.set_result("cert_chain_verify", True)

    service = SealService(
        session=session,
        crypto_engine=crypto,
        ca_service=ca_service,
        key_cache=key_cache,
        seal_material_provider=DummySealSignerMaterialProvider(),
        max_bytes=1024 * 1024,
    )

    pdf_bytes = b"%PDF-1.7 idemp test"
    current_user = CurrentUser(user_id=user.id, role="student", status="active")
    idemp_key = "idemp-key-replay-test-01"

    # Initial call
    res1 = service.create_seal(
        current_user=current_user,
        file_bytes=pdf_bytes,
        mime_type="application/pdf",
        seal_profile="personal",
        pqc_mode=False,
        output_format="sidecar",
        idempotency_key=idemp_key,
    )

    initial_calls_count = len(crypto.calls)
    initial_audits_count = session.query(AuditLog).count()
    assert initial_audits_count == 1

    # Idempotent replay: identical request
    res2 = service.create_seal(
        current_user=current_user,
        file_bytes=pdf_bytes,
        mime_type="application/pdf",
        seal_profile="personal",
        pqc_mode=False,
        output_format="sidecar",
        idempotency_key=idemp_key,
    )
    assert res1.id == res2.id
    assert res1.signature == res2.signature
    # Should NOT call sm2_sign again
    sm2_count = sum(1 for c in crypto.calls if c[0] == "sm2_sign")
    assert sm2_count == 1
    # Should NOT create duplicate audit log
    assert session.query(AuditLog).count() == initial_audits_count

    # Conflict: same idempotency key, different file
    with pytest.raises(ApiError) as exc:
        service.create_seal(
            current_user=current_user,
            file_bytes=b"%PDF-1.7 different file",
            mime_type="application/pdf",
            seal_profile="personal",
            pqc_mode=False,
            output_format="sidecar",
            idempotency_key=idemp_key,
        )
    assert exc.value.status_code == 409


def test_seal_transaction_rollback_on_failure():
    session, crypto, ca_service, ca_user, ca_cert = _setup_db_and_ca()
    user, cert = _create_user_with_cert(session, role="student")
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(user.id, b"k" * 32, datetime(2030, 1, 1, tzinfo=timezone.utc))

    crypto.set_result("cert_chain_verify", True)
    # Simulate crypto error on sm2_sign
    crypto.set_error("sm2_sign", CryptoBridgeError(BridgeErrorCode.INTEGRITY_FAILED))

    service = SealService(
        session=session,
        crypto_engine=crypto,
        ca_service=ca_service,
        key_cache=key_cache,
        seal_material_provider=DummySealSignerMaterialProvider(),
        max_bytes=1024 * 1024,
    )

    with pytest.raises(ApiError):
        service.create_seal(
            current_user=CurrentUser(user.id, "student", "active"),
            file_bytes=b"%PDF-test",
            mime_type="application/pdf",
            seal_profile="personal",
            pqc_mode=False,
            output_format="sidecar",
            idempotency_key="idemp-key-fail-test",
        )

    # Rollback assertion: NO seals and NO audit logs created
    assert session.query(Seal).count() == 0
    assert session.query(AuditLog).filter(AuditLog.action == "verify.seal.create").count() == 0


# ================= Task 5 Tests =================

def test_generate_sidecar_bytes_canonical_format():
    now = datetime(2026, 9, 4, 12, 0, 0, tzinfo=timezone.utc)
    seal = Seal(
        id="550e8400-e29b-41d4-a716-446655440000",
        signer_user_id=str(uuid.uuid4()),
        seal_profile="personal",
        digest_algorithm="SM3",
        digest=b"\x01" * 32,
        signature_algorithm="SM3-with-SM2",
        signature=b"\x02" * 64,
        certificate_der=b"\x03" * 64,
        timestamp=now,
        output_format="sidecar",
        idempotency_key_digest=b"\x04" * 32,
        request_fingerprint=b"\x05" * 32,
        created_at=now,
    )

    sidecar_bytes = generate_sidecar_bytes(seal)
    # Check UTF-8, no BOM
    assert not sidecar_bytes.startswith(b"\xef\xbb\xbf")
    # No trailing newline
    assert not sidecar_bytes.endswith(b"\n")
    assert not sidecar_bytes.endswith(b"\r")

    # Check parseable json
    parsed = json.loads(sidecar_bytes.decode("utf-8"))
    assert set(parsed.keys()) == {
        "certificate", "digest", "digest_algorithm", "id", "signature",
        "signature_algorithm", "timestamp",
    }
    assert parsed["id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert parsed["digest_algorithm"] == "SM3"
    assert parsed["timestamp"] == "2026-09-04T12:00:00Z"

    # Keys sorted check: certificate < digest < digest_algorithm < id < signature < signature_algorithm < timestamp
    keys = list(parsed.keys())
    assert keys == sorted(keys)


# ================= Task 6 Tests =================

def test_seal_service_pqc_and_pdf_signature_page_gates():
    session, crypto, ca_service, ca_user, ca_cert = _setup_db_and_ca()
    user, cert = _create_user_with_cert(session, role="student")
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(user.id, b"k" * 32, datetime(2030, 1, 1, tzinfo=timezone.utc))

    service = SealService(
        session=session,
        crypto_engine=crypto,
        ca_service=ca_service,
        key_cache=key_cache,
        seal_material_provider=DummySealSignerMaterialProvider(),
        max_bytes=1024 * 1024,
    )

    current_user = CurrentUser(user.id, "student", "active")

    # pqc_mode = True -> 503 CCB_UNSUPPORTED
    with pytest.raises(ApiError) as exc:
        service.create_seal(
            current_user=current_user,
            file_bytes=b"%PDF-test",
            mime_type="application/pdf",
            seal_profile="personal",
            pqc_mode=True,
            output_format="sidecar",
            idempotency_key="idemp-key-pqc-001",
        )
    assert exc.value.status_code == 503
    assert exc.value.code == "CCB_UNSUPPORTED"

    # output_format = pdf_signature_page on non-PDF -> 422
    with pytest.raises(ApiError) as exc:
        service.create_seal(
            current_user=current_user,
            file_bytes=b"\x89PNG\r\n\x1a\nimage",
            mime_type="image/png",
            seal_profile="personal",
            pqc_mode=False,
            output_format="pdf_signature_page",
            idempotency_key="idemp-key-pdf-page-001",
        )
    assert exc.value.status_code == 422

    # output_format = pdf_signature_page on PDF -> 503 CCB_UNSUPPORTED
    with pytest.raises(ApiError) as exc:
        service.create_seal(
            current_user=current_user,
            file_bytes=b"%PDF-valid",
            mime_type="application/pdf",
            seal_profile="personal",
            pqc_mode=False,
            output_format="pdf_signature_page",
            idempotency_key="idemp-key-pdf-page-002",
        )
    assert exc.value.status_code == 503
    assert exc.value.code == "CCB_UNSUPPORTED"
