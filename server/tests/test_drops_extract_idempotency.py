from datetime import datetime, timedelta, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.drops import get_recipient_private_key_provider
from app.crypto.dependencies import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    SM2_PRIVATE_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
    EnvelopeArtifact,
)
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord
from app.models.drop import Drop, DropExtractIdempotency
from app.models.user import User
from app.services.recipient_provider import MockRecipientPrivateKeyProvider

VALID_NONCE = b"\x01" * GCM_NONCE_SIZE
VALID_TAG = b"\x02" * GCM_TAG_SIZE
VALID_SM2_ENC = b"\x03" * 96
VALID_SIG = b"\x05" * SM2_SIGNATURE_SIZE
VALID_CA_CERT = b"\x30\x82\x01\x00" + b"\xca" * 100
VALID_CERT = b"\x30\x82\x01\x00" + b"\x06" * 100
VALID_SM2_PRIV = b"\x09" * SM2_PRIVATE_KEY_SIZE
VALID_SM2_PUB = b"\x04" + b"\x11" * 64


class IdempotencyMockCryptoEngine(MockCryptoEngine):
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

    def cert_chain_verify(
        self,
        leaf_certificate_der: bytes,
        certificate_chain_der: tuple[bytes, ...],
        trust_root_der: bytes,
        verification_time: int,
        required_key_usage: tuple[str, ...],
    ) -> bool:
        return True

    def crl_verify(
        self, certificate_der: bytes, crl_der: bytes, verification_time: int
    ) -> bool:
        return True

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        return True


def _create_test_db() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


@pytest.fixture
def idemp_setup():
    db_session = _create_test_db()
    crypto = IdempotencyMockCryptoEngine()
    key_provider = MockRecipientPrivateKeyProvider()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_recipient_private_key_provider] = lambda: key_provider

    client = TestClient(app)
    now = datetime.now(timezone.utc)

    system_user = User(
        id=str(uuid.uuid4()),
        email="system@campus.edu.cn",
        role="system",
        status="active",
        created_at=now,
    )
    sender = User(
        id=str(uuid.uuid4()),
        email="sender@campus.edu.cn",
        role="student",
        status="active",
        pubkey=VALID_SM2_PUB,
        created_at=now,
    )
    recipient = User(
        id=str(uuid.uuid4()),
        email="recipient@campus.edu.cn",
        role="student",
        status="active",
        created_at=now,
    )
    ca_cert = CertificateRecord(
        serial="CA-SERIAL-001",
        issuer_serial="CA-ROOT-001",
        kind="platform_ca",
        key_usage="keyCertSign",
        status="active",
        subject_user_id=system_user.id,
        certificate_der=VALID_CA_CERT,
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=365),
    )
    sender_cert = CertificateRecord(
        serial="SENDER-CERT-001",
        issuer_serial=ca_cert.serial,
        kind="user_identity",
        key_usage="digitalSignature",
        status="active",
        subject_user_id=sender.id,
        certificate_der=VALID_CERT,
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=350),
    )
    sender.cert_serial = sender_cert.serial
    db_session.add_all([system_user, sender, recipient, ca_cert, sender_cert])
    db_session.flush()

    yield {
        "client": client,
        "db": db_session,
        "crypto": crypto,
        "key_provider": key_provider,
        "sender": sender,
        "recipient": recipient,
        "now": now,
    }

    app.dependency_overrides.clear()


def _create_drop(db: Session, crypto: IdempotencyMockCryptoEngine, sender: User, recipient: User, now: datetime) -> tuple[str, str, Drop]:
    code = f"IdempDrop{uuid.uuid4().hex[:8]}"
    access_code = f"ACCESS-{uuid.uuid4().hex[:8].upper()}"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=sender.id,
        recipient_user_id=recipient.id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted content payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=None,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=sm2_fp,
        recipient_mlkem_fingerprint=None,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=25,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()
    return code, access_code, drop


def test_extract_idempotency_same_key_returns_identical_result_and_single_audit(idemp_setup):
    client = idemp_setup["client"]
    db = idemp_setup["db"]
    crypto = idemp_setup["crypto"]
    key_provider = idemp_setup["key_provider"]
    sender = idemp_setup["sender"]
    recipient = idemp_setup["recipient"]
    now = idemp_setup["now"]

    code, access_code, drop = _create_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"Identical unsealed content")

    idemp_key = "IDEMP-KEY-1111222233334444"

    # First request
    resp1 = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idemp_key},
        json={"access_code": access_code},
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["content"] == "Identical unsealed content"
    inspect_id_1 = data1["inspect_record_id"]

    # Second request with identical key
    resp2 = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idemp_key},
        json={"access_code": access_code},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["content"] == "Identical unsealed content"
    inspect_id_2 = data2["inspect_record_id"]

    # Inspect record ID must match across idempotent replay
    assert inspect_id_1 == inspect_id_2

    # Exactly ONE audit log entry created
    audit_count = db.query(AuditLog).filter_by(action="drop.extract", target=f"drop:{drop.id}").count()
    assert audit_count == 1

    # Exactly ONE idempotency record created
    idemp_count = db.query(DropExtractIdempotency).filter_by(drop_id=drop.id).count()
    assert idemp_count == 1


def test_extract_idempotency_conflict_returns_409_and_leaves_drop_available(idemp_setup):
    client = idemp_setup["client"]
    db = idemp_setup["db"]
    crypto = idemp_setup["crypto"]
    key_provider = idemp_setup["key_provider"]
    sender = idemp_setup["sender"]
    recipient = idemp_setup["recipient"]
    now = idemp_setup["now"]

    code, access_code, drop = _create_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"Unsealed content")

    idemp_key = "IDEMP-KEY-CONFLICT-12345"

    # First request succeeds
    resp1 = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idemp_key},
        json={"access_code": access_code},
    )
    assert resp1.status_code == 200

    # Second request uses SAME idempotency key but DIFFERENT access_code
    resp2 = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idemp_key},
        json={"access_code": "DIFFERENT-CODE-99"},
    )
    assert resp2.status_code == 409
    assert "CONFLICT" in resp2.json()["code"]

    # Drop status must still be available
    refreshed_drop = db.get(Drop, drop.id)
    assert refreshed_drop.status == "available"


def test_failed_extraction_does_not_store_idempotency_record(idemp_setup):
    client = idemp_setup["client"]
    db = idemp_setup["db"]
    crypto = idemp_setup["crypto"]
    key_provider = idemp_setup["key_provider"]
    sender = idemp_setup["sender"]
    recipient = idemp_setup["recipient"]
    now = idemp_setup["now"]

    code, access_code, drop = _create_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    idemp_key = "IDEMP-KEY-FAILED-TRY-1234"

    # Extraction fails due to wrong access code
    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idemp_key},
        json={"access_code": "WRONG-ACCESS-CODE-9"},
    )
    assert resp.status_code == 404

    # No idempotency record should be saved for failed request
    idemp_count = db.query(DropExtractIdempotency).filter_by(drop_id=drop.id).count()
    assert idemp_count == 0

    # No audit record written
    audit_count = db.query(AuditLog).filter_by(target=f"drop:{drop.id}").count()
    assert audit_count == 0

    # Retrying with CORRECT access code and same idempotency key succeeds
    crypto.set_result("envelope_open", b"Recovered unsealed content")
    resp_success = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idemp_key},
        json={"access_code": access_code},
    )
    assert resp_success.status_code == 200
    assert resp_success.json()["content"] == "Recovered unsealed content"
