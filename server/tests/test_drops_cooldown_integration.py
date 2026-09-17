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
)
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
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


class CooldownMockCryptoEngine(MockCryptoEngine):
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
def cooldown_setup():
    db_session = _create_test_db()
    crypto = CooldownMockCryptoEngine()
    key_provider = MockRecipientPrivateKeyProvider()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_recipient_private_key_provider] = lambda: key_provider

    client = TestClient(app)
    # 路由层使用真实 UTC 时钟。固定到某个当天时刻会在该时刻过去后
    # 让“仍在冷却中”的场景自行过期，造成与运行时间相关的假失败。
    now = datetime.now(timezone.utc).replace(microsecond=0)

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


def test_wrong_access_code_triggers_cooldown_at_fifth_attempt(cooldown_setup):
    client = cooldown_setup["client"]
    db = cooldown_setup["db"]
    crypto = cooldown_setup["crypto"]
    now = cooldown_setup["now"]

    code = "CooldownTestLink01"
    correct_access_code = "CORRECT-CODE-1111"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(correct_access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=cooldown_setup["sender"].id,
        recipient_user_id=cooldown_setup["recipient"].id,
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
        content_size=22,
        pqc_mode=False,
        status="available",
        failed_attempts=0,
        cooldown_until=None,
        created_at=now,
    )
    db.add(drop)
    db.commit()

    # 1st through 4th failures
    for i in range(1, 5):
        resp = client.post(
            f"/api/v1/drops/{code}/extract",
            headers={"Idempotency-Key": f"idemp-key-attempt-{i:02d}"},
            json={"access_code": f"WRONG-CODE-{i:04d}"},
        )
        assert resp.status_code == 404
        data = resp.json()
        # Verify no attempt count leaked
        assert "remaining" not in data.get("message", "").lower()
        assert "attempt" not in data.get("message", "").lower()
        assert "cooldown" not in data.get("message", "").lower()
        assert "failed_attempts" not in str(data.get("details", {})).lower()

        db.expire_all()
        refreshed = db.get(Drop, drop.id)
        assert refreshed.status == "available"
        assert refreshed.failed_attempts == i
        assert refreshed.cooldown_until is None

    # 5th failure: enters cooling_down
    resp5 = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "idemp-key-attempt-05"},
        json={"access_code": "WRONG-CODE-0005"},
    )
    assert resp5.status_code == 404
    db.expire_all()
    refreshed = db.get(Drop, drop.id)
    assert refreshed.status == "cooling_down"
    assert refreshed.failed_attempts == 5
    assert refreshed.cooldown_until is not None


def test_cooldown_fails_closed_before_any_crypto_or_provider_calls(cooldown_setup):
    client = cooldown_setup["client"]
    db = cooldown_setup["db"]
    crypto = cooldown_setup["crypto"]
    now = cooldown_setup["now"]
    key_provider = cooldown_setup["key_provider"]

    code = "CooldownFailClosed"
    correct_access_code = "CORRECT-CODE-2222"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(correct_access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32

    # Provide valid key and setup return
    key_provider.set_key(cooldown_setup["recipient"].id, sm2_fp, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"secret")

    # Drop is already in cooling_down
    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=cooldown_setup["sender"].id,
        recipient_user_id=cooldown_setup["recipient"].id,
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
        content_size=6,
        pqc_mode=False,
        status="cooling_down",
        failed_attempts=5,
        cooldown_until=now + timedelta(minutes=10),
        created_at=now,
    )
    db.add(drop)
    db.commit()

    crypto._calls.clear()

    # Attempt extract during cooldown even with correct access_code
    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "idemp-key-during-cooldown"},
        json={"access_code": correct_access_code},
    )
    assert resp.status_code == 404
    # Fail-closed verification: NO crypto operations performed
    assert not any(op == "envelope_open" for op, _ in crypto.calls)
    assert not any(op == "sm2_verify" for op, _ in crypto.calls)
    assert not any(op == "hkdf_sm3" for op, _ in crypto.calls)
    # No idempotency record written
    idemp_count = db.query(DropExtractIdempotency).filter_by(drop_id=drop.id).count()
    assert idemp_count == 0


def test_metadata_returns_404_during_cooldown(cooldown_setup):
    client = cooldown_setup["client"]
    db = cooldown_setup["db"]
    crypto = cooldown_setup["crypto"]
    now = cooldown_setup["now"]

    code = "MetaCooldownTest"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=cooldown_setup["sender"].id,
        recipient_user_id=cooldown_setup["recipient"].id,
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
        access_code_hash=b"\x44" * 32,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        filename=None,
        content_size=10,
        pqc_mode=False,
        status="cooling_down",
        failed_attempts=5,
        cooldown_until=now + timedelta(minutes=10),
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.get(f"/api/v1/drops/{code}")
    assert resp.status_code == 404
    # Ensure error does not leak internal cooldown details
    meta_err = resp.json()
    assert "cooling" not in meta_err.get("message", "").lower()
    assert "attempt" not in meta_err.get("message", "").lower()
    assert "remaining" not in meta_err.get("message", "").lower()


def test_wrong_password_does_not_increment_access_code_failures(cooldown_setup):
    client = cooldown_setup["client"]
    db = cooldown_setup["db"]
    crypto = cooldown_setup["crypto"]
    now = cooldown_setup["now"]

    code = "WrongPassLink001"
    correct_access_code = "SECRET-CODE-PASS"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(correct_access_code.encode("utf-8"))
    salt = b"\x77" * 16

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=cooldown_setup["sender"].id,
        recipient_user_id=cooldown_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=b"\x33" * 32,
        access_code_hash=access_code_hash,
        access_factor_salt=salt,  # requires password!
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        content_size=20,
        pqc_mode=False,
        status="available",
        failed_attempts=0,
        created_at=now,
    )
    db.add(drop)
    db.commit()

    # Request with correct access_code, but missing or empty access_password
    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "idemp-missing-pass-1"},
        json={"access_code": correct_access_code},
    )
    assert resp.status_code in (404, 422)

    db.expire_all()
    refreshed = db.get(Drop, drop.id)
    # Password error MUST NOT increment access code failure count!
    assert refreshed.failed_attempts == 0
    assert refreshed.status == "available"


def test_successful_extraction_resets_failure_count(cooldown_setup):
    client = cooldown_setup["client"]
    db = cooldown_setup["db"]
    crypto = cooldown_setup["crypto"]
    now = cooldown_setup["now"]
    key_provider = cooldown_setup["key_provider"]

    code = "SuccessResetCount"
    access_code = "SECRET-CORRECT-1"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32

    key_provider.set_key(cooldown_setup["recipient"].id, sm2_fp, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"Decrypted message")

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=cooldown_setup["sender"].id,
        recipient_user_id=cooldown_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=sm2_fp,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        content_size=17,
        pqc_mode=False,
        status="available",
        failed_attempts=3,  # Previously failed 3 times
        created_at=now,
    )
    db.add(drop)
    db.commit()

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "idemp-success-reset-1"},
        json={"access_code": access_code},
    )
    assert resp.status_code == 200

    db.expire_all()
    refreshed = db.get(Drop, drop.id)
    assert refreshed.failed_attempts == 0
    assert refreshed.cooldown_until is None


def test_cooldown_recovery_after_expiry(cooldown_setup):
    client = cooldown_setup["client"]
    db = cooldown_setup["db"]
    crypto = cooldown_setup["crypto"]
    now = cooldown_setup["now"]
    key_provider = cooldown_setup["key_provider"]

    code = "RecoveryLink1234"
    access_code = "SECRET-RECOVERY1"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fp = b"\x33" * 32

    key_provider.set_key(cooldown_setup["recipient"].id, sm2_fp, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"Recovered drop content")

    # In cooldown with cooldown_until = now + 10 mins
    cooldown_until = now + timedelta(minutes=10)
    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=cooldown_setup["sender"].id,
        recipient_user_id=cooldown_setup["recipient"].id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        sender_signature=VALID_SIG,
        sender_certificate_der=VALID_CERT,
        sender_cert_serial="SENDER-CERT-001",
        recipient_sm2_fingerprint=sm2_fp,
        access_code_hash=access_code_hash,
        access_factor_salt=None,
        ttl_policy="hours_24",
        burn_after_read=False,
        expires_at=now + timedelta(hours=24),
        content_size=21,
        pqc_mode=False,
        status="cooling_down",
        failed_attempts=5,
        cooldown_until=cooldown_until,
        created_at=now,
    )
    db.add(drop)
    db.commit()

    # Time moves forward 11 minutes (after cooldown_until)
    # Metadata query should now succeed with 200
    from app.services.drop import DropService
    # In API route now defaults to current UTC, so we can test via service or simulate time:
    drop_service = DropService(
        session=db,
        crypto_engine=crypto,
        key_cache=None,
        quota_service=None,
        recipient_resolver=None,
        recipient_provider=key_provider,
    )
    future_now = now + timedelta(minutes=11)
    meta = drop_service.get_drop_metadata(code, now=future_now)
    assert meta.status == "available"

    # Extract should now succeed
    res, _ = drop_service.extract_drop(
        code=code,
        access_code=access_code,
        idempotency_key="1234567890123456",
        now=future_now,
    )
    assert res.content == "Recovered drop content"
    db.expire_all()
    refreshed = db.get(Drop, drop.id)
    assert refreshed.status == "available"
    assert refreshed.failed_attempts == 0
    assert refreshed.cooldown_until is None

