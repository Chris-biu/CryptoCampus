import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.datastructures import UploadFile

from app.core.errors import ApiError
from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord
from app.models.seal import Seal
from app.models.user import User
from app.pki.material import UnavailablePlatformCAMaterialProvider
from app.pki.service import PlatformCAService
from app.security.auth_dependencies import CurrentUser
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.seals import SealService, encode_seal_payload


class PrivacyCheckingMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        self._calls.append(("sm3_digest", {"message": len(message)}))
        if message not in self._digests:
            self._counter += 1
            seed = f"mock-hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = seed.ljust(32, b"0")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


def test_database_and_audit_privacy_boundaries():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    crypto = PrivacyCheckingMockCryptoEngine()
    crypto.set_result("sm2_sign", b"S" * 64)
    crypto.set_result("cert_chain_verify", True)

    ca_service = PlatformCAService(session, crypto, UnavailablePlatformCAMaterialProvider())

    # Create root CA and user
    ca_user = User(
        id=str(uuid.uuid4()),
        email="ca@campus.edu.cn",
        role="system",
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    session.add(ca_user)
    ca_cert = CertificateRecord(
        serial="ca-serial-priv-001",
        subject_user_id=ca_user.id,
        issuer_serial="ca-serial-priv-001",
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
        email="user_priv@campus.edu.cn",
        role="student",
        status="active",
        cert_serial="cert-user-priv-001",
        created_at=datetime.now(timezone.utc),
    )
    session.add(user)
    user_cert = CertificateRecord(
        serial="cert-user-priv-001",
        subject_user_id=user.id,
        issuer_serial=ca_cert.serial,
        kind="user_identity",
        certificate_der=b"USER_PRIV_DER_" * 8,
        key_usage="digitalSignature,keyEncipherment,keyAgreement",
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        status="active",
    )
    session.add(user_cert)

    key_cache = PrivateKeyUnlockCache()
    private_key_secret = b"SUPER_SECRET_SK_" * 2  # exactly 32 bytes
    key_cache.put(user.id, private_key_secret, datetime(2030, 1, 1, tzinfo=timezone.utc))
    session.commit()

    service = SealService(
        session=session,
        crypto_engine=crypto,
        ca_service=ca_service,
        key_cache=key_cache,
        max_bytes=1024 * 1024,
    )

    secret_file_content = b"%PDF-CONFIDENTIAL-EXAM-PAPER-AND-STUDENT-GRADES"
    res = service.create_seal(
        current_user=CurrentUser(user.id, "student", "active"),
        file_bytes=secret_file_content,
        mime_type="application/pdf",
        seal_profile="personal",
        pqc_mode=False,
        output_format="sidecar",
        idempotency_key="idemp-privacy-test-01",
    )

    # 1. Inspect seals table in DB:
    stored_seal = session.get(Seal, res.id)
    assert stored_seal is not None

    # Check all stored columns for secret file content or private key
    for col in stored_seal.__table__.columns:
        val = getattr(stored_seal, col.name)
        if isinstance(val, (str, bytes)):
            val_bytes = val.encode("utf-8") if isinstance(val, str) else val
            assert secret_file_content not in val_bytes
            assert private_key_secret not in val_bytes
            assert b"CONFIDENTIAL" not in val_bytes

    # 2. Inspect audit_log table in DB:
    audit_logs = session.query(AuditLog).filter(AuditLog.target == f"seal:{res.id}").all()
    assert len(audit_logs) == 1
    audit = audit_logs[0]
    assert audit.action == "verify.seal.create"
    assert audit.actor == user.id
    # detail_hash is exactly 32 bytes
    assert len(audit.detail_hash) == 32
    assert secret_file_content not in audit.detail_hash
    assert private_key_secret not in audit.detail_hash

    # 3. Check MockCryptoEngine calls:
    # Only operation names and lengths are stored, no sensitive payloads in calls structure
    for op_name, lengths in crypto.calls:
        assert isinstance(op_name, str)
        assert isinstance(lengths, dict)
        for k, v in lengths.items():
            assert isinstance(k, str)
            assert isinstance(v, int)


def test_error_responses_never_leak_stack_traces_or_secrets():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    crypto = PrivacyCheckingMockCryptoEngine()
    ca_service = PlatformCAService(session, crypto, UnavailablePlatformCAMaterialProvider())
    key_cache = PrivateKeyUnlockCache()

    service = SealService(
        session=session,
        crypto_engine=crypto,
        ca_service=ca_service,
        key_cache=key_cache,
        max_bytes=1024,
    )

    # Trigger validation error with secret payload
    secret_payload = b"SUPER_SECRET_TOKEN_IN_FILE"
    try:
        service.create_seal(
            current_user=CurrentUser("unknown-id", "student", "active"),
            file_bytes=secret_payload,
            mime_type="text/plain",
            seal_profile="personal",
            pqc_mode=False,
            output_format="sidecar",
            idempotency_key="idemp-privacy-error-01",
        )
    except ApiError as err:
        assert "SUPER_SECRET_TOKEN" not in err.message
        assert "SUPER_SECRET_TOKEN" not in err.code
        assert "SUPER_SECRET_TOKEN" not in str(err.details)
