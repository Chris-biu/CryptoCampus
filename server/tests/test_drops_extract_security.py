from datetime import datetime, timedelta, timezone
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
from app.models.certificate import CertificateRecord, CrlSnapshot
from app.models.drop import Drop
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


class ObservableCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.operation_log: list[str] = []
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        self.operation_log.append("sm3_digest")
        if message not in self._digests:
            self._counter += 1
            seed = f"hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        self.operation_log.append("constant_time_equal")
        return left == right

    def hkdf_sm3(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        self.operation_log.append("hkdf_sm3")
        return b"\x55" * length

    def cert_chain_verify(
        self,
        leaf_certificate_der: bytes,
        certificate_chain_der: tuple[bytes, ...],
        trust_root_der: bytes,
        verification_time: int,
        required_key_usage: tuple[str, ...],
    ) -> bool:
        self.operation_log.append("cert_chain_verify")
        return self._results.get("cert_chain_verify", True)

    def crl_verify(
        self, certificate_der: bytes, crl_der: bytes, verification_time: int
    ) -> bool:
        self.operation_log.append("crl_verify")
        return self._results.get("crl_verify", True)

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        self.operation_log.append("sm2_verify")
        return self._results.get("sm2_verify", True)

    def envelope_open(
        self,
        *,
        envelope: EnvelopeArtifact,
        recipient_sm2_private_key: bytes,
        pqc_mode: bool,
        recipient_mlkem_private_key: bytes | None,
        access_factor: bytes | None,
    ) -> bytes:
        self.operation_log.append("envelope_open")
        if "envelope_open" in self._errors:
            raise self._errors["envelope_open"]
        return self._results.get("envelope_open", b"Decrypted mock content")


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
def security_setup():
    db_session = _create_test_db()
    crypto = ObservableCryptoEngine()
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
        "ca_cert": ca_cert,
        "sender_cert": sender_cert,
        "now": now,
    }

    app.dependency_overrides.clear()


def _create_drop(db: Session, crypto: ObservableCryptoEngine, sender: User, recipient: User, now: datetime, **kwargs) -> tuple[str, str, Drop]:
    code = f"SecCode{uuid.uuid4().hex[:8]}"
    access_code = f"ACCESS-{uuid.uuid4().hex[:8].upper()}"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32

    drop_kwargs = {
        "id": str(uuid.uuid4()),
        "owner_user_id": sender.id,
        "recipient_user_id": recipient.id,
        "link_code_hash": code_hash,
        "kind": "text",
        "envelope_version": 1,
        "ciphertext": b"encrypted secret message content",
        "nonce": VALID_NONCE,
        "tag": VALID_TAG,
        "enc_key_sm2": VALID_SM2_ENC,
        "enc_key_mlkem": None,
        "sender_signature": VALID_SIG,
        "sender_certificate_der": VALID_CERT,
        "sender_cert_serial": "SENDER-CERT-001",
        "recipient_sm2_fingerprint": sm2_fp,
        "recipient_mlkem_fingerprint": None,
        "access_code_hash": access_code_hash,
        "access_factor_salt": None,
        "ttl_policy": "hours_24",
        "burn_after_read": False,
        "expires_at": now + timedelta(hours=24),
        "filename": None,
        "content_size": 32,
        "pqc_mode": False,
        "status": "available",
        "created_at": now,
    }
    drop_kwargs.update(kwargs)
    drop = Drop(**drop_kwargs)
    db.add(drop)
    db.commit()
    return code, access_code, drop


def test_verification_order_in_success_flow(security_setup):
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code, access_code, drop = _create_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"Verified secret content")

    crypto.operation_log.clear()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code == 200, resp.text

    # Assert operation sequence strictly adheres to:
    # digest/equality -> cert_chain_verify -> sm2_verify -> envelope_open
    log = crypto.operation_log
    assert "constant_time_equal" in log
    assert "cert_chain_verify" in log
    assert "sm2_verify" in log
    assert "envelope_open" in log

    idx_equal = log.index("constant_time_equal")
    idx_cert = log.index("cert_chain_verify")
    idx_sig = log.index("sm2_verify")
    idx_open = log.index("envelope_open")

    assert idx_equal < idx_cert < idx_sig < idx_open


def test_tag_tamper_fails_closed_without_leaking_plaintext(security_setup):
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code, access_code, drop = _create_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    # Simulate Tag tamper causing INTEGRITY_FAILED in envelope_open
    crypto.set_error("envelope_open", CryptoBridgeError(BridgeErrorCode.INTEGRITY_FAILED))

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code == 404
    data = resp.json()
    assert "content" not in data
    assert "download_url" not in data
    assert "secret" not in resp.text
    assert "INTEGRITY_FAILED" not in resp.text


def test_cert_expired_fails_closed_without_calling_signature_or_open(security_setup):
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    sender_cert = security_setup["sender_cert"]
    now = security_setup["now"]

    # Expire sender certificate in DB
    sender_cert.not_after = now - timedelta(days=1)
    db.commit()

    code, access_code, drop = _create_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    crypto.operation_log.clear()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code == 404
    data = resp.json()
    assert "content" not in data
    assert "download_url" not in data

    # sm2_verify and envelope_open must NEVER be reached
    assert "sm2_verify" not in crypto.operation_log
    assert "envelope_open" not in crypto.operation_log


def test_cert_revoked_fails_closed_without_calling_signature_or_open(security_setup):
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    sender_cert = security_setup["sender_cert"]
    now = security_setup["now"]

    # Mark sender certificate as revoked in DB
    sender_cert.status = "revoked"
    sender_cert.revoked_at = now - timedelta(days=1)
    sender_cert.revocation_reason = "keyCompromise"
    db.commit()

    code, access_code, drop = _create_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    crypto.operation_log.clear()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code == 404
    data = resp.json()
    assert "content" not in data
    assert "download_url" not in data

    assert "sm2_verify" not in crypto.operation_log
    assert "envelope_open" not in crypto.operation_log


def test_cert_key_usage_invalid_fails_closed(security_setup):
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code, access_code, drop = _create_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    # cert_chain_verify fails due to key usage mismatch (e.g. keyEncipherment instead of digitalSignature)
    crypto.set_result("cert_chain_verify", False)
    crypto.operation_log.clear()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code == 404
    data = resp.json()
    assert "content" not in data
    assert "download_url" not in data

    assert "sm2_verify" not in crypto.operation_log
    assert "envelope_open" not in crypto.operation_log


def test_signature_forged_fails_closed_without_calling_envelope_open(security_setup):
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code, access_code, drop = _create_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    # sm2_verify returns False (tampered signature)
    crypto.set_result("sm2_verify", False)
    crypto.operation_log.clear()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code == 404
    data = resp.json()
    assert "content" not in data
    assert "download_url" not in data

    assert "cert_chain_verify" in crypto.operation_log
    assert "sm2_verify" in crypto.operation_log
    assert "envelope_open" not in crypto.operation_log


def test_unknown_envelope_version_fails_closed(security_setup):
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code, access_code, drop = _create_drop(
        db, crypto, sender, recipient, now, envelope_version=99
    )
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    crypto.operation_log.clear()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code in (404, 422)
    data = resp.json()
    assert "content" not in data
    assert "download_url" not in data

    # None of crypto operations should be called for invalid structure
    assert "cert_chain_verify" not in crypto.operation_log
    assert "sm2_verify" not in crypto.operation_log
    assert "envelope_open" not in crypto.operation_log


def test_tampered_tag_length_fails_closed_in_structure_check(security_setup):
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code, access_code, drop = _create_drop(
        db, crypto, sender, recipient, now, tag=b"\x00" * 8  # invalid tag length (should be 16)
    )
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    crypto.operation_log.clear()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code in (404, 422)
    data = resp.json()
    assert "content" not in data
    assert "download_url" not in data

    assert "cert_chain_verify" not in crypto.operation_log
    assert "sm2_verify" not in crypto.operation_log
    assert "envelope_open" not in crypto.operation_log
