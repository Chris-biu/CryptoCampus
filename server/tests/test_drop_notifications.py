from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    MLKEM_ENC_KEY_SIZE,
    SM2_PRIVATE_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
)
from app.db.base import Base
from app.models.certificate import CertificateRecord
from app.models.drop import Drop, DropExtractIdempotency
from app.models.notification import Notification
from app.models.user import User
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.drop import DropService
from app.services.quota import QuotaService
from app.services.recipient_provider import MockRecipientPrivateKeyProvider
from app.services.recipient_resolver import DefaultRecipientKeyResolver

VALID_NONCE = b"\x01" * GCM_NONCE_SIZE
VALID_TAG = b"\x02" * GCM_TAG_SIZE
VALID_SM2_ENC = b"\x03" * 96
VALID_SIG = b"\x05" * SM2_SIGNATURE_SIZE
VALID_CERT = b"\x30\x82\x01\x00" + b"\x06" * 100
VALID_SM2_PRIV = b"\x09" * SM2_PRIVATE_KEY_SIZE


class NotificationTestCryptoEngine(MockCryptoEngine):
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

    def sm2_verify(self, pubkey, digest, signature):
        return True

    def envelope_open(self, envelope, recipient_sm2_private_key, pqc_mode, recipient_mlkem_private_key, access_factor):
        return b"hello decrypted message"


@pytest.fixture
def env():
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    owner = User(
        id=str(uuid.uuid4()),
        email="owner@stu.edu.cn",
        role="student",
        status="active",
        pubkey=b"\x04" + b"\x11" * 64,
        cert_serial="SERIAL-OWNER",
    )
    recipient = User(
        id=str(uuid.uuid4()),
        email="recipient@stu.edu.cn",
        role="student",
        status="active",
        pubkey=b"\x04" + b"\x22" * 64,
        cert_serial="SERIAL-RECV",
    )
    session.add_all([owner, recipient])
    session.commit()

    crypto = NotificationTestCryptoEngine()
    key_cache = PrivateKeyUnlockCache()
    quota_service = QuotaService(session, crypto.sm3_digest)
    resolver = DefaultRecipientKeyResolver()
    recipient_provider = MockRecipientPrivateKeyProvider()
    recipient_provider.set_key(recipient.id, crypto.sm3_digest(recipient.pubkey), VALID_SM2_PRIV)

    drop_service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=quota_service,
        recipient_resolver=resolver,
        recipient_provider=recipient_provider,
    )

    system_user = User(
        id=str(uuid.uuid4()),
        email="system@campus.edu.cn",
        role="system",
        status="active",
        pubkey=b"\x04" + b"\x33" * 64,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    session.add(system_user)
    session.flush()

    ca_cert = CertificateRecord(
        serial="CA-SERIAL-001",
        issuer_serial="CA-ROOT-001",
        kind="platform_ca",
        key_usage="keyCertSign",
        status="active",
        subject_user_id=system_user.id,
        certificate_der=b"\x30\x82\x01\x00" + b"\xca" * 100,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    cert_owner = CertificateRecord(
        serial="SERIAL-OWNER",
        issuer_serial="CA-SERIAL-001",
        kind="user_identity",
        key_usage="digitalSignature",
        status="active",
        subject_user_id=owner.id,
        certificate_der=VALID_CERT,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    cert_recv = CertificateRecord(
        serial="SERIAL-RECV",
        issuer_serial="CA-SERIAL-001",
        kind="user_identity",
        key_usage="digitalSignature",
        status="active",
        subject_user_id=recipient.id,
        certificate_der=b"\x30\x82\x01\x00" + b"\x07" * 100,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )
    session.add_all([ca_cert, cert_owner, cert_recv])
    session.commit()

    def create_drop(kind="text", burn_after_read=False, filename=None):
        code = "ABCD1234EFG"
        code_hash = crypto.sm3_digest(code.encode("utf-8"))
        access_code = "SECRETACCESS"
        access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
        drop_id = str(uuid.uuid4())
        drop = Drop(
            id=drop_id,
            owner_user_id=owner.id,
            recipient_user_id=recipient.id,
            link_code_hash=code_hash,
            kind=kind,
            envelope_version=1,
            ciphertext=b"encrypted-bytes",
            nonce=VALID_NONCE,
            tag=VALID_TAG,
            enc_key_sm2=VALID_SM2_ENC,
            enc_key_mlkem=None,
            sender_signature=VALID_SIG,
            sender_certificate_der=VALID_CERT,
            sender_cert_serial="SERIAL-OWNER",
            recipient_sm2_fingerprint=crypto.sm3_digest(recipient.pubkey),
            recipient_mlkem_fingerprint=None,
            access_code_hash=access_code_hash,
            access_factor_salt=None,
            ttl_policy="burn_after_read" if burn_after_read else "hours_24",
            burn_after_read=burn_after_read,
            expires_at=None,
            filename=filename,
            content_size=23,
            pqc_mode=False,
            status="available",
        )
        session.add(drop)
        session.commit()
        return drop, code, access_code

    return {
        "session": session,
        "crypto": crypto,
        "owner": owner,
        "recipient": recipient,
        "drop_service": drop_service,
        "create_drop": create_drop,
    }


def test_successful_text_extract_creates_notification_for_owner(env):
    drop, code, access_code = env["create_drop"](kind="text")
    service: DropService = env["drop_service"]
    session = env["session"]

    resp, _ = service.extract_drop(
        code=code,
        access_code=access_code,
        idempotency_key="key-test-1234567890",
        now=datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc),
    )
    assert resp.content == "hello decrypted message"

    # Notification must be sent to drop.owner_user_id
    notifs_owner = (
        session.query(Notification)
        .filter_by(user_id=env["owner"].id)
        .all()
    )
    assert len(notifs_owner) == 1
    n = notifs_owner[0]
    assert n.type == "drop_extracted"
    assert n.title == "你的密信已被成功提取"
    assert n.related_resource_id == drop.id
    assert n.read is False

    # Recipient must NOT have notifications
    notifs_recv = (
        session.query(Notification)
        .filter_by(user_id=env["recipient"].id)
        .all()
    )
    assert len(notifs_recv) == 0


def test_successful_file_extract_creates_notification_for_owner(env):
    drop, code, access_code = env["create_drop"](kind="file", filename="test.pdf")
    service: DropService = env["drop_service"]
    session = env["session"]

    resp, payload = service.extract_drop(
        code=code,
        access_code=access_code,
        idempotency_key="key-file-1234567890",
        now=datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc),
    )
    assert resp.kind == "file"
    assert payload == b"hello decrypted message"

    notifs = (
        session.query(Notification)
        .filter_by(user_id=env["owner"].id, related_resource_id=drop.id)
        .all()
    )
    assert len(notifs) == 1
    assert notifs[0].type == "drop_extracted"


def test_idempotent_replay_does_not_duplicate_notification(env):
    drop, code, access_code = env["create_drop"](kind="text")
    service: DropService = env["drop_service"]
    session = env["session"]

    # First attempt
    service.extract_drop(
        code=code,
        access_code=access_code,
        idempotency_key="same-idempotency-key-16",
        now=datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc),
    )
    count1 = session.query(Notification).filter_by(user_id=env["owner"].id).count()
    assert count1 == 1

    # Replay attempt with same key
    service.extract_drop(
        code=code,
        access_code=access_code,
        idempotency_key="same-idempotency-key-16",
        now=datetime(2026, 9, 9, 12, 5, 0, tzinfo=timezone.utc),
    )
    count2 = session.query(Notification).filter_by(user_id=env["owner"].id).count()
    assert count2 == 1


def test_different_idempotency_keys_create_distinct_notifications(env):
    drop, code, access_code = env["create_drop"](kind="text", burn_after_read=False)
    service: DropService = env["drop_service"]
    session = env["session"]

    # First attempt
    service.extract_drop(
        code=code,
        access_code=access_code,
        idempotency_key="key-first-attempt-16",
        now=datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc),
    )
    assert session.query(Notification).filter_by(user_id=env["owner"].id).count() == 1

    # Second valid extraction with different key
    service.extract_drop(
        code=code,
        access_code=access_code,
        idempotency_key="key-second-attempt-16",
        now=datetime(2026, 9, 9, 12, 10, 0, tzinfo=timezone.utc),
    )
    assert session.query(Notification).filter_by(user_id=env["owner"].id).count() == 2


def test_burn_after_read_drop_extract_creates_single_notification(env):
    drop, code, access_code = env["create_drop"](kind="text", burn_after_read=True)
    service: DropService = env["drop_service"]
    session = env["session"]

    # First extract succeeds
    service.extract_drop(
        code=code,
        access_code=access_code,
        idempotency_key="key-burn-attempt-16",
        now=datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc),
    )
    assert session.query(Notification).filter_by(user_id=env["owner"].id).count() == 1

    # Second attempt with different key fails (drop already consumed/destroyed)
    with pytest.raises(Exception):
        service.extract_drop(
            code=code,
            access_code=access_code,
            idempotency_key="key-burn-attempt-22",
            now=datetime(2026, 9, 9, 12, 1, 0, tzinfo=timezone.utc),
        )
    # Still only 1 notification
    assert session.query(Notification).filter_by(user_id=env["owner"].id).count() == 1
