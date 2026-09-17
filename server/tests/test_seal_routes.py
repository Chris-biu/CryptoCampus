import io
import json
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.auth import get_crypto_engine, get_private_key_cache
from app.core.config import Settings, get_settings
from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.pki.material import UnavailablePlatformCAMaterialProvider
from app.pki.service import PlatformCAService
from app.security.auth_dependencies import CurrentUser, get_current_user
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.seals import (
    SealService,
    SealSignerMaterial,
    get_default_seal_signer_material_provider,
)


class RouteDynamicMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        self._calls.append(("sm3_digest", {"message": len(message)}))
        if "sm3_digest" in self._errors:
            raise self._errors["sm3_digest"]
        if message not in self._digests:
            self._counter += 1
            seed = f"hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


class DummyRouteSealSignerMaterialProvider:
    def __init__(self, materials: dict[str, SealSignerMaterial] | None = None):
        self._materials = materials or {}

    def get_seal_material(self, profile: str) -> SealSignerMaterial | None:
        return self._materials.get(profile)


def _setup_route_environment():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    crypto = RouteDynamicMockCryptoEngine()
    crypto.set_result("sm2_sign", b"S" * 64)
    crypto.set_result("cert_chain_verify", True)

    key_cache = PrivateKeyUnlockCache()

    # Root CA
    ca_user = User(
        id=str(uuid.uuid4()),
        email="ca@campus.edu.cn",
        role="system",
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    session.add(ca_user)
    ca_cert = CertificateRecord(
        serial="ca-serial-route-001",
        subject_user_id=ca_user.id,
        issuer_serial="ca-serial-route-001",
        kind="platform_ca",
        certificate_der=b"CA_DER_" * 8,
        key_usage="keyCertSign,cRLSign",
        not_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2035, 1, 1, tzinfo=timezone.utc),
        status="active",
    )
    session.add(ca_cert)

    # Student user
    student = User(
        id=str(uuid.uuid4()),
        email="student@campus.edu.cn",
        role="student",
        status="active",
        cert_serial="cert-student-001",
        created_at=datetime.now(timezone.utc),
    )
    session.add(student)
    student_cert = CertificateRecord(
        serial="cert-student-001",
        subject_user_id=student.id,
        issuer_serial=ca_cert.serial,
        kind="user_identity",
        certificate_der=b"STUDENT_DER_" * 8,
        key_usage="digitalSignature,keyEncipherment,keyAgreement",
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        status="active",
    )
    session.add(student_cert)
    key_cache.put(student.id, b"s" * 32, datetime(2030, 1, 1, tzinfo=timezone.utc))

    # Admin user
    admin = User(
        id=str(uuid.uuid4()),
        email="admin@campus.edu.cn",
        role="admin",
        status="active",
        cert_serial="cert-admin-001",
        created_at=datetime.now(timezone.utc),
    )
    session.add(admin)
    admin_cert = CertificateRecord(
        serial="cert-admin-001",
        subject_user_id=admin.id,
        issuer_serial=ca_cert.serial,
        kind="user_identity",
        certificate_der=b"ADMIN_DER_" * 8,
        key_usage="digitalSignature,keyEncipherment,keyAgreement",
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        status="active",
    )
    session.add(admin_cert)
    key_cache.put(admin.id, b"a" * 32, datetime(2030, 1, 1, tzinfo=timezone.utc))

    session.commit()

    dept_material = SealSignerMaterial(
        user_id=ca_user.id,
        certificate_der=ca_cert.certificate_der,
        private_key=b"d" * 32,
    )
    seal_provider = DummyRouteSealSignerMaterialProvider({"department": dept_material})

    app = create_app()

    def override_get_db():
        with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_private_key_cache] = lambda: key_cache
    app.dependency_overrides[get_default_seal_signer_material_provider] = lambda: seal_provider
    app.dependency_overrides[get_settings] = lambda: Settings(seal_and_verify_max_bytes=1024 * 1024)

    client = TestClient(app)
    return client, session, student, admin, crypto


def test_post_seals_unauthorized_returns_401():
    client, session, student, admin, crypto = _setup_route_environment()
    # No Auth header
    response = client.post(
        "/api/v1/seals",
        data={"seal_profile": "personal", "pqc_mode": "false", "output_format": "sidecar"},
        files={"file": ("doc.pdf", b"%PDF-content", "application/pdf")},
        headers={"Idempotency-Key": "idemp-test-key-0001"},
    )
    assert response.status_code == 401


def test_post_seals_forbidden_profile_returns_403():
    client, session, student, admin, crypto = _setup_route_environment()

    # Override get_current_user to student
    client.app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id=student.id, role="student", status="active"
    )

    # Student requesting department seal
    response = client.post(
        "/api/v1/seals",
        data={"seal_profile": "department", "pqc_mode": "false", "output_format": "sidecar"},
        files={"file": ("doc.pdf", b"%PDF-content", "application/pdf")},
        headers={"Idempotency-Key": "idemp-test-key-0001"},
    )
    assert response.status_code == 403


def test_post_seals_missing_idempotency_key_returns_422():
    client, session, student, admin, crypto = _setup_route_environment()
    client.app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id=student.id, role="student", status="active"
    )

    # No Idempotency-Key header
    response = client.post(
        "/api/v1/seals",
        data={"seal_profile": "personal", "pqc_mode": "false", "output_format": "sidecar"},
        files={"file": ("doc.pdf", b"%PDF-content", "application/pdf")},
    )
    assert response.status_code == 422


def test_post_seals_short_idempotency_key_returns_422():
    client, session, student, admin, crypto = _setup_route_environment()
    client.app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id=student.id, role="student", status="active"
    )

    # Idempotency-Key too short (< 16)
    response = client.post(
        "/api/v1/seals",
        data={"seal_profile": "personal", "pqc_mode": "false", "output_format": "sidecar"},
        files={"file": ("doc.pdf", b"%PDF-content", "application/pdf")},
        headers={"Idempotency-Key": "short-key"},
    )
    assert response.status_code == 422


def test_post_seals_success_returns_201_seal():
    client, session, student, admin, crypto = _setup_route_environment()
    client.app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id=student.id, role="student", status="active"
    )

    response = client.post(
        "/api/v1/seals",
        data={"seal_profile": "personal", "pqc_mode": "false", "output_format": "sidecar"},
        files={"file": ("doc.pdf", b"%PDF-1.7 hello world test", "application/pdf")},
        headers={"Idempotency-Key": "idemp-test-key-success-01"},
    )
    assert response.status_code == 201
    body = response.json()

    # Strictly 7 fields
    assert set(body.keys()) == {
        "id", "digest_algorithm", "digest", "signature_algorithm",
        "signature", "certificate", "timestamp",
    }
    assert body["digest_algorithm"] == "SM3"
    assert body["signature_algorithm"] == "SM3-with-SM2"
    assert "source_file" not in body
    assert "private_key" not in body
    assert "user_id" not in body

    # Verify GET /api/v1/seals/{seal_id} (public, no JWT)
    seal_id = body["id"]
    get_res = client.get(f"/api/v1/seals/{seal_id}")
    assert get_res.status_code == 200
    assert get_res.json() == body

    # Verify GET /api/v1/seals/{seal_id}/sidecar (public, no JWT)
    sidecar_res = client.get(f"/api/v1/seals/{seal_id}/sidecar")
    assert sidecar_res.status_code == 200
    assert sidecar_res.headers["content-type"].startswith("application/octet-stream")
    assert sidecar_res.headers["content-disposition"] == f'attachment; filename="seal-{seal_id}.ccseal"'

    # Verify sidecar bytes are valid UTF-8 canonical JSON
    raw_sidecar = sidecar_res.content
    assert not raw_sidecar.startswith(b"\xef\xbb\xbf")
    assert not raw_sidecar.endswith(b"\n")
    parsed_sidecar = json.loads(raw_sidecar.decode("utf-8"))
    assert parsed_sidecar == body


def test_get_nonexistent_seal_returns_404():
    client, session, student, admin, crypto = _setup_route_environment()
    random_id = str(uuid.uuid4())

    res1 = client.get(f"/api/v1/seals/{random_id}")
    assert res1.status_code == 404

    res2 = client.get(f"/api/v1/seals/{random_id}/sidecar")
    assert res2.status_code == 404
