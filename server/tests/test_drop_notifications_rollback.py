from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.errors import DropServiceError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    SM2_PRIVATE_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
    EnvelopeArtifact,
)
from app.db.base import Base
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord
from app.models.drop import Drop, DropExtractIdempotency
from app.models.notification import Notification
from app.models.user import User
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.drop import DropService
from app.services.notification import NotificationService
from app.services.quota import QuotaService
from app.services.recipient_provider import MockRecipientPrivateKeyProvider
from app.services.recipient_resolver import DefaultRecipientKeyResolver

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

    def envelope_open(
        self,
        *,
        envelope: EnvelopeArtifact,
        recipient_sm2_private_key: bytes,
        pqc_mode: bool,
        recipient_mlkem_private_key: bytes | None,
        access_factor: bytes | None,
    ) -> bytes:
        return b"Secret payload intended for extract"


@pytest.fixture
def rollback_env():
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)

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
        created_at=now,
        pubkey=VALID_SM2_PUB,
    )
    recipient = User(
        id=str(uuid.uuid4()),
        email="recipient@campus.edu.cn",
        role="student",
        status="active",
        created_at=now,
        pubkey=VALID_SM2_PUB,
    )
    session.add_all([system_user, sender, recipient])
    session.flush()

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
    recipient_cert = CertificateRecord(
        serial="RECV-CERT-001",
        issuer_serial=ca_cert.serial,
        kind="user_identity",
        key_usage="digitalSignature",
        status="active",
        subject_user_id=recipient.id,
        certificate_der=b"\x30\x82\x01\x00" + b"\x07" * 100,
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=350),
    )
    session.add_all([ca_cert, sender_cert, recipient_cert])
    session.commit()

    crypto = RollbackMockCryptoEngine()
    key_provider = MockRecipientPrivateKeyProvider()
    key_provider.set_key(recipient.id, crypto.sm3_digest(VALID_SM2_PUB), VALID_SM2_PRIV)

    def create_drop(burn_after_read=True, expires_at=None, status="available"):
        code = f"CODE{uuid.uuid4().hex[:8].upper()}"
        access_code = "ACCESSPASS123"
        drop_id = str(uuid.uuid4())
        drop = Drop(
            id=drop_id,
            owner_user_id=sender.id,
            recipient_user_id=recipient.id,
            link_code_hash=crypto.sm3_digest(code.encode("utf-8")),
            kind="text",
            envelope_version=1,
            ciphertext=b"encrypted-data",
            nonce=VALID_NONCE,
            tag=VALID_TAG,
            enc_key_sm2=VALID_SM2_ENC,
            enc_key_mlkem=None,
            sender_signature=VALID_SIG,
            sender_certificate_der=VALID_CERT,
            sender_cert_serial="SENDER-CERT-001",
            recipient_sm2_fingerprint=crypto.sm3_digest(VALID_SM2_PUB),
            recipient_mlkem_fingerprint=None,
            access_code_hash=crypto.sm3_digest(access_code.encode("utf-8")),
            access_factor_salt=None,
            ttl_policy="burn_after_read" if burn_after_read else "hours_24",
            burn_after_read=burn_after_read,
            expires_at=expires_at,
            filename=None,
            content_size=32,
            pqc_mode=False,
            status=status,
        )
        session.add(drop)
        session.commit()
        return code, access_code, drop

    return {
        "session": session,
        "crypto": crypto,
        "key_provider": key_provider,
        "sender": sender,
        "recipient": recipient,
        "now": now,
        "create_drop": create_drop,
    }


def test_notification_creation_failure_rolls_back_entire_transaction(rollback_env):
    session = rollback_env["session"]
    crypto = rollback_env["crypto"]
    key_provider = rollback_env["key_provider"]
    now = rollback_env["now"]
    code, access_code, drop = rollback_env["create_drop"](burn_after_read=True)

    mock_notif_service = MagicMock(spec=NotificationService)
    mock_notif_service.create_drop_extracted.side_effect = RuntimeError("simulated notification db failure")

    drop_service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=PrivateKeyUnlockCache(),
        quota_service=QuotaService(session, crypto.sm3_digest),
        recipient_resolver=DefaultRecipientKeyResolver(),
        recipient_provider=key_provider,
        notification_service=mock_notif_service,
    )

    with pytest.raises(RuntimeError, match="simulated notification db failure"):
        drop_service.extract_drop(
            code=code,
            access_code=access_code,
            idempotency_key="idemp-rollback-key-001",
            now=now,
        )

    # Verify transaction rolled back completely:
    session.expire_all()
    reloaded_drop = session.get(Drop, drop.id)
    # 1. Drop must NOT be burned or altered
    assert reloaded_drop.status == "available"
    assert reloaded_drop.ciphertext == b"encrypted-data"
    assert reloaded_drop.nonce == VALID_NONCE

    # 2. No idempotency record created
    idemp_count = session.query(DropExtractIdempotency).filter_by(drop_id=drop.id).count()
    assert idemp_count == 0

    # 3. No audit record created
    audit_count = session.query(AuditLog).filter_by(target=f"drop:{drop.id}").count()
    assert audit_count == 0

    # 4. No notification record created
    notif_count = session.query(Notification).filter_by(related_resource_id=drop.id).count()
    assert notif_count == 0


def test_failed_access_code_does_not_create_notification(rollback_env):
    session = rollback_env["session"]
    crypto = rollback_env["crypto"]
    key_provider = rollback_env["key_provider"]
    now = rollback_env["now"]
    code, _, drop = rollback_env["create_drop"](burn_after_read=False)

    drop_service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=PrivateKeyUnlockCache(),
        quota_service=QuotaService(session, crypto.sm3_digest),
        recipient_resolver=DefaultRecipientKeyResolver(),
        recipient_provider=key_provider,
    )

    with pytest.raises(DropServiceError) as exc_info:
        drop_service.extract_drop(
            code=code,
            access_code="WRONGACCESSCODE1",
            idempotency_key="idemp-wrong-access-001",
            now=now,
        )
    assert exc_info.value.code == "not_found"

    notif_count = session.query(Notification).filter_by(related_resource_id=drop.id).count()
    assert notif_count == 0


def test_expired_drop_does_not_create_notification(rollback_env):
    session = rollback_env["session"]
    crypto = rollback_env["crypto"]
    key_provider = rollback_env["key_provider"]
    now = rollback_env["now"]
    expired_at = now - timedelta(hours=1)
    code, access_code, drop = rollback_env["create_drop"](burn_after_read=False, expires_at=expired_at)

    drop_service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=PrivateKeyUnlockCache(),
        quota_service=QuotaService(session, crypto.sm3_digest),
        recipient_resolver=DefaultRecipientKeyResolver(),
        recipient_provider=key_provider,
    )

    with pytest.raises(DropServiceError) as exc_info:
        drop_service.extract_drop(
            code=code,
            access_code=access_code,
            idempotency_key="idemp-expired-001",
            now=now,
        )
    assert exc_info.value.code == "not_found"

    notif_count = session.query(Notification).filter_by(related_resource_id=drop.id).count()
    assert notif_count == 0


def test_cooling_down_drop_does_not_create_notification(rollback_env):
    session = rollback_env["session"]
    crypto = rollback_env["crypto"]
    key_provider = rollback_env["key_provider"]
    now = rollback_env["now"]
    code, access_code, drop = rollback_env["create_drop"](burn_after_read=False, status="cooling_down")
    # set cooldown until future
    drop.cooldown_until = now + timedelta(minutes=10)
    drop.failed_attempts = 5
    session.commit()

    drop_service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=PrivateKeyUnlockCache(),
        quota_service=QuotaService(session, crypto.sm3_digest),
        recipient_resolver=DefaultRecipientKeyResolver(),
        recipient_provider=key_provider,
    )

    with pytest.raises(DropServiceError) as exc_info:
        drop_service.extract_drop(
            code=code,
            access_code=access_code,
            idempotency_key="idemp-cooldown-001",
            now=now,
        )
    assert exc_info.value.code == "cooling_down"

    notif_count = session.query(Notification).filter_by(related_resource_id=drop.id).count()
    assert notif_count == 0


def test_already_consumed_drop_does_not_create_notification(rollback_env):
    session = rollback_env["session"]
    crypto = rollback_env["crypto"]
    key_provider = rollback_env["key_provider"]
    now = rollback_env["now"]
    code, access_code, drop = rollback_env["create_drop"](burn_after_read=False, status="consumed")

    drop_service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=PrivateKeyUnlockCache(),
        quota_service=QuotaService(session, crypto.sm3_digest),
        recipient_resolver=DefaultRecipientKeyResolver(),
        recipient_provider=key_provider,
    )

    with pytest.raises(DropServiceError) as exc_info:
        drop_service.extract_drop(
            code=code,
            access_code=access_code,
            idempotency_key="idemp-consumed-001",
            now=now,
        )
    assert exc_info.value.code == "not_found"

    notif_count = session.query(Notification).filter_by(related_resource_id=drop.id).count()
    assert notif_count == 0
