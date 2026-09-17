from datetime import datetime, timedelta, timezone
import re
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.drops import get_recipient_private_key_provider
from app.crypto.dependencies import get_crypto_engine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    MLKEM_ENC_KEY_SIZE,
    SM2_PRIVATE_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
    EnvelopeArtifact,
)
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.certificate import CertificateRecord
from app.models.drop import Drop
from app.models.user import User
from app.services.recipient_provider import MockRecipientPrivateKeyProvider

VALID_NONCE = b"\x01" * GCM_NONCE_SIZE
VALID_TAG = b"\x02" * GCM_TAG_SIZE
VALID_SM2_ENC = b"\x03" * 96
VALID_MLKEM_ENC = b"\x04" * MLKEM_ENC_KEY_SIZE
VALID_SIG = b"\x05" * SM2_SIGNATURE_SIZE
VALID_CA_CERT = b"\x30\x82\x01\x00" + b"\xca" * 100
VALID_CERT = b"\x30\x82\x01\x00" + b"\x06" * 100
VALID_SM2_PRIV = b"\x09" * SM2_PRIVATE_KEY_SIZE
VALID_MLKEM_PRIV = b"\x0a" * 2400


class ExtractMockCryptoEngine(MockCryptoEngine):
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

    def hkdf_sm3(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        return b"\x55" * length

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
def extract_setup():
    db_session = _create_test_db()
    crypto = ExtractMockCryptoEngine()
    key_provider = MockRecipientPrivateKeyProvider()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_recipient_private_key_provider] = lambda: key_provider

    client = TestClient(app)
    now = datetime.now(timezone.utc)

    # Sender and recipient users
    sender = User(
        id=str(uuid.uuid4()),
        email="sender@campus.edu.cn",
        role="student",
        status="active",
        pubkey=b"\x04" + b"\x11" * 64,
        created_at=now,
    )
    recipient = User(
        id=str(uuid.uuid4()),
        email="recipient@campus.edu.cn",
        role="student",
        status="active",
        created_at=now,
    )
    system_user = User(
        id=str(uuid.uuid4()),
        email="system@campus.edu.cn",
        role="system",
        status="active",
        created_at=now,
    )
    # Active platform CA certificate record
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
    # Sender active user certificate
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


def test_extract_text_drop_success(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    key_provider = extract_setup["key_provider"]
    now = extract_setup["now"]

    code = "TextExtractCode123"
    access_code = "SECRET-CODE-8888"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fingerprint = b"\x33" * 32

    # Set up recipient unlocked key
    key_provider.set_key(extract_setup["recipient"].id, sm2_fingerprint, VALID_SM2_PRIV)

    # Set up mock envelope_open return
    expected_plaintext = b"This is confidential drop content."
    crypto.set_result("envelope_open", expected_plaintext)

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=None,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=sm2_fingerprint,
        recipient_mlkem_fingerprint=None,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=len(expected_plaintext),
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    idempotency_key = "1234567890123456"
    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idempotency_key},
        json={"access_code": access_code},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["kind"] == "text"
    assert data["content"] == "This is confidential drop content."
    assert data["signature_valid"] is True
    assert data["certificate_valid"] is True
    assert "inspect_record_id" in data
    assert uuid.UUID(data["inspect_record_id"])  # must be valid UUID


def test_extract_text_drop_with_access_password_success(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    key_provider = extract_setup["key_provider"]
    now = extract_setup["now"]

    code = "PassExtractCode123"
    access_code = "SECRET-CODE-PASS"
    access_password = "ExtraSecretPassword123"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    salt = b"\x77" * 16
    sm2_fingerprint = b"\x33" * 32

    key_provider.set_key(extract_setup["recipient"].id, sm2_fingerprint, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"Protected with password")

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=None,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=sm2_fingerprint,
        recipient_mlkem_fingerprint=None,
        access_code_hash=access_code_hash,
        access_factor_salt=salt,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=23,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code, "access_password": access_password},
    )
    assert resp.status_code == 200
    assert resp.json()["content"] == "Protected with password"


def test_extract_missing_password_when_required_fails(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    now = extract_setup["now"]

    code = "MustPassCode123"
    access_code = "SECRET-MUST-PASS"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=None,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=b"\x33" * 32,
        recipient_mlkem_fingerprint=None,
        access_code_hash=access_code_hash,
        access_factor_salt=b"\x77" * 16,  # requires password!
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=23,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    # Omit access_password in request
    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code in (404, 422)
    # envelope_open must NOT be called
    assert not any(op == "envelope_open" for op, _ in crypto.calls)


def test_extract_wrong_access_code_fails(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    now = extract_setup["now"]

    code = "WrongCodeTest123"
    real_access_code = "CORRECT-CODE-1234"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(real_access_code.encode("utf-8"))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=None,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=b"\x33" * 32,
        recipient_mlkem_fingerprint=None,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=23,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": "WRONG-CODE-9999"},
    )
    assert resp.status_code == 404
    assert not any(op == "envelope_open" for op, _ in crypto.calls)


def test_extract_recipient_key_unauthorized_fails_closed(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    now = extract_setup["now"]

    code = "UnauthKeyExtract123"
    access_code = "SECRET-CODE-UNAUTH"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fingerprint = b"\x33" * 32

    # Notice: key_provider has NO key registered for this recipient!

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=None,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=sm2_fingerprint,
        recipient_mlkem_fingerprint=None,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=23,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code in (401, 404)
    assert not any(op == "envelope_open" for op, _ in crypto.calls)


def test_extract_file_drop_octet_stream(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    key_provider = extract_setup["key_provider"]
    now = extract_setup["now"]

    code = "FileExtractCode123"
    access_code = "SECRET-FILE-8888"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fingerprint = b"\x33" * 32

    key_provider.set_key(extract_setup["recipient"].id, sm2_fingerprint, VALID_SM2_PRIV)
    expected_file_bytes = b"%PDF-1.4 binary file content for test"
    crypto.set_result("envelope_open", expected_file_bytes)

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="file",
        envelope_version=1,
        ciphertext=b"encrypted file payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=None,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=sm2_fingerprint,
        recipient_mlkem_fingerprint=None,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename="report.pdf",
        content_size=len(expected_file_bytes),
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={
            "Idempotency-Key": "1234567890123456",
            "Accept": "application/octet-stream",
        },
        json={"access_code": access_code},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/octet-stream"
    assert resp.content == expected_file_bytes
    assert resp.headers.get("x-signature-valid") == "true"
    assert resp.headers.get("x-certificate-valid") == "true"
    assert "x-inspect-record-id" in resp.headers
    assert resp.headers.get("content-disposition") == 'attachment; filename="report.pdf"'


def test_extract_pqc_hybrid_drop_success(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    key_provider = extract_setup["key_provider"]
    now = extract_setup["now"]

    code = "PqcExtractCode123"
    access_code = "SECRET-PQC-8888"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32
    mlkem_fp = b"\x44" * 32

    # Provide both SM2 and ML-KEM unlocked private keys
    key_provider.set_key(extract_setup["recipient"].id, sm2_fp, VALID_SM2_PRIV)
    key_provider.set_key(extract_setup["recipient"].id, mlkem_fp, VALID_MLKEM_PRIV)

    expected_content = b"PQC protected hybrid message"
    crypto.set_result("envelope_open", expected_content)

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted pqc text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=VALID_MLKEM_ENC,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=sm2_fp,
        recipient_mlkem_fingerprint=mlkem_fp,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=len(expected_content),
        pqc_mode=True,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["content"] == "PQC protected hybrid message"
    assert data["signature_valid"] is True
    assert data["certificate_valid"] is True

    # Assert envelope_open was called with pqc_mode=True
    open_calls = [c for c in crypto.calls if c[0] == "envelope_open"]
    assert len(open_calls) == 1
    _, lengths = open_calls[0]
    assert lengths["recipient_mlkem_private_key"] == 2400


def test_extract_pqc_missing_mlkem_private_key_fails_closed_no_downgrade(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    key_provider = extract_setup["key_provider"]
    now = extract_setup["now"]

    code = "PqcNoKeyExtract123"
    access_code = "SECRET-PQC-NOKEY"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32
    mlkem_fp = b"\x44" * 32

    # Only SM2 is available, ML-KEM private key is missing
    key_provider.set_key(extract_setup["recipient"].id, sm2_fp, VALID_SM2_PRIV)

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted pqc text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=VALID_MLKEM_ENC,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=sm2_fp,
        recipient_mlkem_fingerprint=mlkem_fp,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=32,
        pqc_mode=True,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code in (401, 404)
    # Strictly ensure envelope_open was NEVER called with pqc_mode=False
    assert not any(c[0] == "envelope_open" for c in crypto.calls)


def test_extract_pqc_missing_enc_mlkem_fails_closed(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    key_provider = extract_setup["key_provider"]
    now = extract_setup["now"]

    code = "PqcNoEncMlkem123"
    access_code = "SECRET-NO-ENC-ML"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted pqc text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=None,  # missing ML-KEM enc key in pqc_mode!
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=b"\x33" * 32,
        recipient_mlkem_fingerprint=b"\x44" * 32,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=32,
        pqc_mode=True,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code in (404, 422)
    assert not any(c[0] == "envelope_open" for c in crypto.calls)


def test_extract_pqc_invalid_mlkem_enc_length_fails_closed(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    now = extract_setup["now"]

    code = "PqcBadLenMlkem12"
    access_code = "SECRET-BAD-LEN-M"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted pqc text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=b"\x04" * 500,  # Invalid length (must be 1088)
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=b"\x33" * 32,
        recipient_mlkem_fingerprint=b"\x44" * 32,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=32,
        pqc_mode=True,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code in (404, 422)
    assert not any(c[0] == "envelope_open" for c in crypto.calls)


def test_extract_non_pqc_with_mlkem_fails_closed(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    now = extract_setup["now"]

    code = "NonPqcWithMl1234"
    access_code = "SECRET-NON-PQC-M"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=VALID_MLKEM_ENC,  # Invalid: non-pqc must not have ML-KEM
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=b"\x33" * 32,
        recipient_mlkem_fingerprint=None,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=32,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code in (404, 422)
    assert not any(c[0] == "envelope_open" for c in crypto.calls)


def test_extract_pqc_unseal_failure_does_not_downgrade(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    key_provider = extract_setup["key_provider"]
    now = extract_setup["now"]

    code = "PqcFailNoDown123"
    access_code = "SECRET-PQC-FAIL"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32
    mlkem_fp = b"\x44" * 32

    key_provider.set_key(extract_setup["recipient"].id, sm2_fp, VALID_SM2_PRIV)
    key_provider.set_key(extract_setup["recipient"].id, mlkem_fp, VALID_MLKEM_PRIV)

    # envelope_open fails
    crypto.set_error("envelope_open", CryptoBridgeError(BridgeErrorCode.INTEGRITY_FAILED))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=extract_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted pqc text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=VALID_MLKEM_ENC,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=sm2_fp,
        recipient_mlkem_fingerprint=mlkem_fp,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=32,
        pqc_mode=True,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code == 404
    # Ensure envelope_open was called exactly once with ML-KEM key present, never retried without ML-KEM
    open_calls = [c for c in crypto.calls if c[0] == "envelope_open"]
    assert len(open_calls) == 1
    _, lengths = open_calls[0]
    assert lengths["recipient_mlkem_private_key"] == 2400


def test_extract_recipient_frozen_status_fails_closed(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    key_provider = extract_setup["key_provider"]
    recipient = extract_setup["recipient"]
    now = extract_setup["now"]

    recipient.status = "frozen"
    db.commit()

    code = "FrozenRecipient1"
    access_code = "SECRET-FROZEN-01"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32
    key_provider.set_key(recipient.id, sm2_fp, VALID_SM2_PRIV)

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=recipient.id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted text payload",
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
        content_size=32,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code in (401, 404)
    assert not any(c[0] == "envelope_open" for c in crypto.calls)


def test_extract_recipient_pending_deletion_status_fails_closed(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    key_provider = extract_setup["key_provider"]
    recipient = extract_setup["recipient"]
    now = extract_setup["now"]

    recipient.status = "pending_deletion"
    db.commit()

    code = "PendingDelRecip1"
    access_code = "SECRET-PENDING-0"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32
    key_provider.set_key(recipient.id, sm2_fp, VALID_SM2_PRIV)

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=recipient.id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted text payload",
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
        content_size=32,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code in (401, 404)
    assert not any(c[0] == "envelope_open" for c in crypto.calls)


def test_extract_recipient_key_fingerprint_mismatch_fails_closed(extract_setup):
    client = extract_setup["client"]
    db = extract_setup["db"]
    crypto = extract_setup["crypto"]
    key_provider = extract_setup["key_provider"]
    recipient = extract_setup["recipient"]
    now = extract_setup["now"]

    code = "KeyFpMismatch123"
    access_code = "SECRET-MISMATCH1"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))

    # Register under different fingerprint
    key_provider.set_key(recipient.id, b"\x99" * 32, VALID_SM2_PRIV)

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=extract_setup["sender"].id,
        recipient_user_id=recipient.id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted text payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=None,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=b"\x33" * 32,  # mismatch!
        recipient_mlkem_fingerprint=None,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=32,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code in (401, 404)
    assert not any(c[0] == "envelope_open" for c in crypto.calls)

