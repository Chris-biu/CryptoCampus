from datetime import datetime, timedelta, timezone
import logging
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
    SM2_PRIVATE_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
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


class RollbackMockCryptoEngine(MockCryptoEngine):
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
def rollback_setup():
    db_session = _create_test_db()
    crypto = RollbackMockCryptoEngine()
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


def _create_drop(db: Session, crypto: RollbackMockCryptoEngine, sender: User, recipient: User, now: datetime, **kwargs) -> tuple[str, str, Drop]:
    code = f"RollbackDrop{uuid.uuid4().hex[:8]}"
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
        "ciphertext": b"encrypted payload data",
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
        "content_size": 22,
        "pqc_mode": False,
        "status": "available",
        "created_at": now,
    }
    drop_kwargs.update(kwargs)
    drop = Drop(**drop_kwargs)
    db.add(drop)
    db.commit()
    return code, access_code, drop


def test_extract_unseal_failure_rolls_back_and_preserves_drop_status(rollback_setup):
    client = rollback_setup["client"]
    db = rollback_setup["db"]
    crypto = rollback_setup["crypto"]
    key_provider = rollback_setup["key_provider"]
    sender = rollback_setup["sender"]
    recipient = rollback_setup["recipient"]
    now = rollback_setup["now"]

    code, access_code, drop = _create_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    # Force envelope_open to fail
    crypto.set_error("envelope_open", CryptoBridgeError(BridgeErrorCode.INTEGRITY_FAILED))

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "1234567890123456"},
        json={"access_code": access_code},
    )
    assert resp.status_code == 404

    # Assert no audit log or idempotency record was persisted
    assert db.query(AuditLog).filter_by(target=f"drop:{drop.id}").count() == 0
    assert db.query(DropExtractIdempotency).filter_by(drop_id=drop.id).count() == 0

    # Drop status is still available
    refreshed_drop = db.get(Drop, drop.id)
    assert refreshed_drop.status == "available"


def test_zero_sensitive_data_leaked_in_logs_and_exceptions(rollback_setup, caplog):
    client = rollback_setup["client"]
    db = rollback_setup["db"]
    crypto = rollback_setup["crypto"]
    key_provider = rollback_setup["key_provider"]
    sender = rollback_setup["sender"]
    recipient = rollback_setup["recipient"]
    now = rollback_setup["now"]

    secret_access_code = "SECRET-SUPER-SENSITIVE-CODE"
    secret_password = "SecretPassword!999"
    secret_plaintext = "TOP-SECRET-CONFIDENTIAL-PLAINTEXT"

    salt = b"\x88" * 16
    code = "ZeroLeakCode1234"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(secret_access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32

    key_provider.set_key(recipient.id, sm2_fp, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", secret_plaintext.encode("utf-8"))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=sender.id,
        recipient_user_id=recipient.id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted payload data",
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
        access_factor_salt=salt,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=len(secret_plaintext),
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()

    with caplog.at_level(logging.DEBUG):
        # 1. Successful extraction
        resp_ok = client.post(
            f"/api/v1/drops/{code}/extract",
            headers={"Idempotency-Key": "1234567890123456"},
            json={"access_code": secret_access_code, "access_password": secret_password},
        )
        assert resp_ok.status_code == 200

        # 2. Failed extraction (wrong code)
        resp_fail = client.post(
            f"/api/v1/drops/{code}/extract",
            headers={"Idempotency-Key": "1234567890123457"},
            json={"access_code": "WRONG-ACCESS-CODE-9"},
        )
        assert resp_fail.status_code in (404, 422)

    # Check logs: NEVER contain access_code, access_password, plaintext, private_key
    log_text = caplog.text
    assert secret_access_code not in log_text
    assert secret_password not in log_text
    assert secret_plaintext not in log_text
    assert "VALID_SM2_PRIV" not in log_text
    assert VALID_SM2_PRIV.hex() not in log_text

    # Check audit log in DB: NEVER contain plaintext or credentials
    audit = db.query(AuditLog).filter_by(target=f"drop:{drop.id}").first()
    assert audit is not None
    # detail_hash is 32-byte SM3 digest, no plaintext
    assert len(audit.detail_hash) == 32
    assert secret_access_code.encode("utf-8") not in audit.detail_hash

    # Check error response: NEVER contains sensitive tokens or raw exceptions
    fail_text = resp_fail.text
    assert secret_access_code not in fail_text
    assert secret_password not in fail_text
    assert "Traceback" not in fail_text
    assert "Exception" not in fail_text
