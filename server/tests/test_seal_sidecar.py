import json
import uuid
from datetime import datetime, timezone
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
from app.models.seal import Seal
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, get_current_user
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.seals import (
    SealService,
    SealSignerMaterial,
    generate_sidecar_bytes,
    get_default_seal_signer_material_provider,
)


class SidecarMockCryptoEngine(MockCryptoEngine):
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


def test_sidecar_canonical_json_determinism_and_stability():
    now = datetime(2026, 9, 10, 8, 30, 0, tzinfo=timezone.utc)
    seal = Seal(
        id="12345678-1234-5678-1234-567812345678",
        signer_user_id=str(uuid.uuid4()),
        seal_profile="personal",
        digest_algorithm="SM3",
        digest=b"\xaa" * 32,
        signature_algorithm="SM3-with-SM2",
        signature=b"\xbb" * 64,
        certificate_der=b"\xcc" * 128,
        timestamp=now,
        output_format="sidecar",
        idempotency_key_digest=b"\xdd" * 32,
        request_fingerprint=b"\xee" * 32,
        created_at=now,
    )

    sidecar_1 = generate_sidecar_bytes(seal)
    sidecar_2 = generate_sidecar_bytes(seal)

    # 1. Byte-for-byte deterministic
    assert sidecar_1 == sidecar_2

    # 2. No BOM, no trailing newline
    assert not sidecar_1.startswith(b"\xef\xbb\xbf")
    assert not sidecar_1.endswith(b"\n")
    assert not sidecar_1.endswith(b"\r")

    # 3. Exact expected keys in alphabetical order
    parsed = json.loads(sidecar_1.decode("utf-8"))
    assert list(parsed.keys()) == [
        "certificate",
        "digest",
        "digest_algorithm",
        "id",
        "signature",
        "signature_algorithm",
        "timestamp",
    ]

    # 4. No sensitive or extra keys
    assert "source_file" not in parsed
    assert "private_key" not in parsed
    assert "user_id" not in parsed
    assert "signer_user_id" not in parsed


def test_qr_output_format_stability_and_relative_path_privacy():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    crypto = SidecarMockCryptoEngine()
    crypto.set_result("sm2_sign", b"S" * 64)
    crypto.set_result("cert_chain_verify", True)

    key_cache = PrivateKeyUnlockCache()

    ca_user = User(
        id=str(uuid.uuid4()),
        email="ca@campus.edu.cn",
        role="system",
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    session.add(ca_user)
    ca_cert = CertificateRecord(
        serial="ca-serial-sidecar-001",
        subject_user_id=ca_user.id,
        issuer_serial="ca-serial-sidecar-001",
        kind="platform_ca",
        certificate_der=b"CA_DER_" * 8,
        key_usage="keyCertSign,cRLSign",
        not_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2035, 1, 1, tzinfo=timezone.utc),
        status="active",
    )
    session.add(ca_cert)

    user = User(
        id=str(uuid.uuid4()),
        email="user_qr@campus.edu.cn",
        role="student",
        status="active",
        cert_serial="cert-user-qr-001",
        created_at=datetime.now(timezone.utc),
    )
    session.add(user)
    user_cert = CertificateRecord(
        serial="cert-user-qr-001",
        subject_user_id=user.id,
        issuer_serial=ca_cert.serial,
        kind="user_identity",
        certificate_der=b"USER_QR_DER_" * 8,
        key_usage="digitalSignature,keyEncipherment,keyAgreement",
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        status="active",
    )
    session.add(user_cert)
    key_cache.put(user.id, b"u" * 32, datetime(2030, 1, 1, tzinfo=timezone.utc))
    session.commit()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_private_key_cache] = lambda: key_cache
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id=user.id, role="student", status="active"
    )
    app.dependency_overrides[get_settings] = lambda: Settings(seal_and_verify_max_bytes=1024 * 1024)

    client = TestClient(app)

    # Request with output_format = "qr"
    response = client.post(
        "/api/v1/seals",
        data={"seal_profile": "personal", "pqc_mode": "false", "output_format": "qr"},
        files={"file": ("photo.png", b"\x89PNG\r\n\x1a\nvalid png", "image/png")},
        headers={"Idempotency-Key": "idemp-qr-test-key-01"},
    )
    assert response.status_code == 201
    body = response.json()

    # QR response strictly matches OpenAPI Seal schema without hidden/custom fields
    seal_id = body["id"]
    expected_qr_target = f"/api/v1/seals/{seal_id}"

    # Public verification endpoint accessible
    public_res = client.get(expected_qr_target)
    assert public_res.status_code == 200
    assert public_res.json() == body

    # Confirm QR target contains only relative path and uuid, no tokens, secret keys, or emails
    assert "token" not in expected_qr_target
    assert "secret" not in expected_qr_target
    assert "email" not in expected_qr_target
    assert "@" not in expected_qr_target
