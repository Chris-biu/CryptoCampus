from datetime import datetime, timedelta, timezone
import inspect
import re
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.drops import get_recipient_private_key_provider
from app.crypto.dependencies import get_crypto_engine
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


class CooldownSecurityMockCrypto(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            # Produce 32 bytes pseudo-digest without reflecting input plaintext
            self._digests[message] = f"sm3digest-{self._counter:012d}".encode("ascii").ljust(32, b"\xaa")
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


@pytest.fixture
def security_setup():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    db_session = session_factory()

    crypto = CooldownSecurityMockCrypto()
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


def _create_drop_helper(db, crypto, sender, recipient, now, code_prefix: str) -> tuple[str, str, Drop]:
    code = f"{code_prefix}{uuid.uuid4().hex[:8]}"
    access_code = f"ACC-{code_prefix.upper()}-{uuid.uuid4().hex[:6].upper()}"
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
        failed_attempts=0,
        cooldown_until=None,
        created_at=now,
    )
    db.add(drop)
    db.commit()
    return code, access_code, drop


def test_cross_drop_failure_isolation(security_setup):
    """
    Ensure failed access attempts on Drop A are strictly isolated to Drop A,
    and have zero impact on Drop B.
    """
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code_a, access_code_a, drop_a = _create_drop_helper(db, crypto, sender, recipient, now, "DropA")
    code_b, access_code_b, drop_b = _create_drop_helper(db, crypto, sender, recipient, now, "DropB")

    # 4 failed attempts on Drop A
    for i in range(4):
        resp = client.post(
            f"/api/v1/drops/{code_a}/extract",
            headers={"Idempotency-Key": f"IDEMP-A-KEY-1000{i}"},
            json={"access_code": "WRONG-CODE-A"},
        )
        assert resp.status_code == 404

    # Refresh and verify counts
    db.refresh(drop_a)
    db.refresh(drop_b)
    assert drop_a.failed_attempts == 4
    assert drop_a.status == "available"
    assert drop_b.failed_attempts == 0
    assert drop_b.status == "available"

    # 5th failed attempt on Drop A puts Drop A into cooling_down
    resp_5 = client.post(
        f"/api/v1/drops/{code_a}/extract",
        headers={"Idempotency-Key": "IDEMP-A-KEY-10005"},
        json={"access_code": "WRONG-CODE-A"},
    )
    assert resp_5.status_code == 404

    db.refresh(drop_a)
    db.refresh(drop_b)
    assert drop_a.status == "cooling_down"
    assert drop_a.failed_attempts == 5
    assert drop_a.cooldown_until is not None

    # Drop B is completely unaffected
    assert drop_b.status == "available"
    assert drop_b.failed_attempts == 0
    assert drop_b.cooldown_until is None

    # Drop B can be extracted successfully even with same Idempotency-Key prefix
    key_provider.set_key(recipient.id, drop_b.recipient_sm2_fingerprint, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"Drop B Content")

    resp_b = client.post(
        f"/api/v1/drops/{code_b}/extract",
        headers={"Idempotency-Key": "IDEMP-SAME-KEY-1234"},
        json={"access_code": access_code_b},
    )
    assert resp_b.status_code == 200
    assert resp_b.json()["content"] == "Drop B Content"

    # Drop A remains in cooling_down, rejecting requests even if the same key is reused
    resp_a_locked = client.post(
        f"/api/v1/drops/{code_a}/extract",
        headers={"Idempotency-Key": "IDEMP-SAME-KEY-1234"},
        json={"access_code": access_code_a},
    )
    assert resp_a_locked.status_code == 404


def test_uniform_error_responses_zero_information_disclosure(security_setup):
    """
    Ensure all error responses during access failure (attempts 1..4) and cooldown (attempt 5 and cooling_down state)
    return a uniform 404 NOT_FOUND response without leaking:
    - Attempt counts or remaining attempts
    - Cooldown deadline or duration
    - User identity or recipient information
    - Input access code or link code
    - Whether the drop exists vs doesn't exist
    """
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code, access_code, drop = _create_drop_helper(db, crypto, sender, recipient, now, "LeakTest")

    sensitive_tokens = [
        access_code,
        "WRONG-SECRET-CODE",
        "failed_attempts",
        "cooldown_until",
        "attempts_remaining",
        sender.id,
        recipient.id,
        "cooling_down",
        "drop_id",
    ]

    # Attempts 1 to 5
    for attempt in range(1, 6):
        resp = client.post(
            f"/api/v1/drops/{code}/extract",
            headers={"Idempotency-Key": f"IDEMP-LEAK-KEY-1000{attempt}"},
            json={"access_code": "WRONG-SECRET-CODE"},
        )
        assert resp.status_code == 404
        data = resp.json()
        assert data.get("code") == "NOT_FOUND"
        assert data.get("message") in ("密信不存在或链接已失效", "密信不存在或提取码错误")

        text = resp.text
        for token in sensitive_tokens:
            assert token not in text, f"Token {token} leaked in response: {text}"

    # Query metadata during cooldown
    resp_meta = client.get(f"/api/v1/drops/{code}")
    assert resp_meta.status_code == 404
    meta_text = resp_meta.text
    for token in sensitive_tokens:
        assert token not in meta_text, f"Token {token} leaked in metadata response: {meta_text}"


def test_zero_leakage_in_database_tables(security_setup):
    """
    Ensure database tables do not store raw access codes, passwords, or plain link codes in plaintext.
    """
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code, access_code, drop = _create_drop_helper(db, crypto, sender, recipient, now, "DbZeroLeak")
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"SecretCleartextPayload123")

    # 1 failure
    client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "IDEMP-DB-1"},
        json={"access_code": "WRONG-ACCESS-SEC"},
    )

    # 1 success
    client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "IDEMP-DB-2"},
        json={"access_code": access_code},
    )

    # Check Drop table columns
    drop_record = db.get(Drop, drop.id)
    assert drop_record is not None

    raw_secrets = [
        code,
        access_code,
        "WRONG-ACCESS-SEC",
        "SecretCleartextPayload123",
    ]

    # Convert drop record to string of all attributes
    drop_dict_str = str({c.name: getattr(drop_record, c.name) for c in Drop.__table__.columns})
    for secret in raw_secrets:
        assert secret not in drop_dict_str, f"Secret {secret} found in Drop record: {drop_dict_str}"

    # Check AuditLog records
    audit_logs = db.query(AuditLog).all()
    for log in audit_logs:
        log_str = f"{log.action} {log.target} {log.details}"
        for secret in raw_secrets:
            assert secret not in log_str, f"Secret {secret} found in AuditLog: {log_str}"

    # Check DropExtractIdempotency records
    idemp_records = db.query(DropExtractIdempotency).all()
    for rec in idemp_records:
        rec_str = f"{rec.idempotency_key} {rec.drop_id} {rec.recipient_user_id} {rec.inspect_record_id}"
        for secret in raw_secrets:
            assert secret not in rec_str, f"Secret {secret} found in Idempotency record: {rec_str}"


def test_no_prohibited_crypto_libraries_imported():
    """
    Security check: verify that extract_cooldown, drop service, drop model, and drop routes
    never import hashlib, cryptography, or openssl.
    All cryptography MUST use CryptoEngine.
    """
    import app.services.extract_cooldown as m_cooldown
    import app.services.drop as m_drop_service
    import app.models.drop as m_drop_model
    import app.api.routes.drops as m_drop_routes

    prohibited = ["hashlib", "cryptography", "OpenSSL", "openssl"]

    for mod in [m_cooldown, m_drop_service, m_drop_model, m_drop_routes]:
        source = inspect.getsource(mod)
        for p in prohibited:
            pattern = rf"(import\s+{p}|from\s+{p}\s+import)"
            match = re.search(pattern, source)
            assert match is None, f"Prohibited module {p} imported in {mod.__name__}: {match.group(0)}"
