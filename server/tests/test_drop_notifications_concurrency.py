from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
import tempfile
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

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


class ConcurrencyMockCryptoEngine(MockCryptoEngine):
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
        return b"Concurrent test decrypted secret"


@pytest.fixture
def concurrency_env():
    db_file = os.path.join(tempfile.gettempdir(), f"notif_conc_{uuid.uuid4().hex}.db")
    engine = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"check_same_thread": False, "timeout": 30.0},
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    SessionMaker = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    crypto = ConcurrencyMockCryptoEngine()
    now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)

    with SessionMaker() as session:
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

        sender_id = sender.id
        recipient_id = recipient.id

    key_provider = MockRecipientPrivateKeyProvider()

    yield {
        "SessionMaker": SessionMaker,
        "crypto": crypto,
        "key_provider": key_provider,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "now": now,
        "db_file": db_file,
    }

    try:
        os.remove(db_file)
    except OSError:
        pass


def _create_drop(SessionMaker, crypto, sender_id, recipient_id, burn_after_read=False):
    code = f"CODE{uuid.uuid4().hex[:8].upper()}"
    access_code = "ACCESSPASS123"
    drop_id = str(uuid.uuid4())

    with SessionMaker() as session:
        drop = Drop(
            id=drop_id,
            owner_user_id=sender_id,
            recipient_user_id=recipient_id,
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
            expires_at=None,
            filename=None,
            content_size=32,
            pqc_mode=False,
            status="available",
        )
        session.add(drop)
        session.commit()

    return code, access_code, drop_id


def test_concurrent_extract_with_same_idempotency_key_creates_single_notification(concurrency_env):
    SessionMaker = concurrency_env["SessionMaker"]
    crypto = concurrency_env["crypto"]
    key_provider = concurrency_env["key_provider"]
    sender_id = concurrency_env["sender_id"]
    recipient_id = concurrency_env["recipient_id"]
    now = concurrency_env["now"]

    code, access_code, drop_id = _create_drop(SessionMaker, crypto, sender_id, recipient_id, burn_after_read=False)
    sm2_fp = crypto.sm3_digest(VALID_SM2_PUB)
    key_provider.set_key(recipient_id, sm2_fp, VALID_SM2_PRIV)

    shared_idempotency_key = f"IDEMP-SHARED-{uuid.uuid4().hex[:12]}"
    thread_count = 8
    successes = []
    failures = []

    def worker(idx: int):
        with SessionMaker() as session:
            service = DropService(
                session=session,
                crypto_engine=crypto,
                key_cache=PrivateKeyUnlockCache(),
                quota_service=QuotaService(session, crypto.sm3_digest),
                recipient_resolver=DefaultRecipientKeyResolver(),
                recipient_provider=key_provider,
            )
            try:
                resp, _ = service.extract_drop(
                    code=code,
                    access_code=access_code,
                    idempotency_key=shared_idempotency_key,
                    now=now,
                )
                successes.append((idx, resp.content))
            except Exception as e:
                failures.append((idx, e))

    with ThreadPoolExecutor(max_workers=thread_count) as pool:
        futures = [pool.submit(worker, i) for i in range(thread_count)]
        for f in futures:
            f.result()

    # At least 1 succeeded
    assert len(successes) >= 1

    with SessionMaker() as session:
        # Crucial requirement: only ONE notification created
        notifs = session.query(Notification).filter_by(user_id=sender_id, related_resource_id=drop_id).all()
        assert len(notifs) == 1
        assert notifs[0].type == "drop_extracted"
        assert notifs[0].title == "你的密信已被成功提取"

        # Exactly 1 idempotency record
        idemps = session.query(DropExtractIdempotency).filter_by(drop_id=drop_id).count()
        assert idemps == 1

    # Sequential replay with the same idempotency key succeeds and still leaves 1 notification
    with SessionMaker() as session:
        service = DropService(
            session=session,
            crypto_engine=crypto,
            key_cache=PrivateKeyUnlockCache(),
            quota_service=QuotaService(session, crypto.sm3_digest),
            recipient_resolver=DefaultRecipientKeyResolver(),
            recipient_provider=key_provider,
        )
        replay_resp, _ = service.extract_drop(
            code=code,
            access_code=access_code,
            idempotency_key=shared_idempotency_key,
            now=now,
        )
        assert replay_resp.content == "Concurrent test decrypted secret"

        notif_count = session.query(Notification).filter_by(user_id=sender_id, related_resource_id=drop_id).count()
        assert notif_count == 1


def test_concurrent_extract_burn_after_read_creates_single_notification(concurrency_env):
    SessionMaker = concurrency_env["SessionMaker"]
    crypto = concurrency_env["crypto"]
    key_provider = concurrency_env["key_provider"]
    sender_id = concurrency_env["sender_id"]
    recipient_id = concurrency_env["recipient_id"]
    now = concurrency_env["now"]

    code, access_code, drop_id = _create_drop(SessionMaker, crypto, sender_id, recipient_id, burn_after_read=True)
    sm2_fp = crypto.sm3_digest(VALID_SM2_PUB)
    key_provider.set_key(recipient_id, sm2_fp, VALID_SM2_PRIV)

    thread_count = 8
    successes = []
    failures = []

    def worker(idx: int):
        with SessionMaker() as session:
            service = DropService(
                session=session,
                crypto_engine=crypto,
                key_cache=PrivateKeyUnlockCache(),
                quota_service=QuotaService(session, crypto.sm3_digest),
                recipient_resolver=DefaultRecipientKeyResolver(),
                recipient_provider=key_provider,
            )
            try:
                resp, _ = service.extract_drop(
                    code=code,
                    access_code=access_code,
                    idempotency_key=f"IDEMP-BURN-{idx:04d}-{uuid.uuid4().hex[:8]}",
                    now=now,
                )
                successes.append((idx, resp.content))
            except Exception as e:
                failures.append((idx, e))

    with ThreadPoolExecutor(max_workers=thread_count) as pool:
        futures = [pool.submit(worker, i) for i in range(thread_count)]
        for f in futures:
            f.result()

    # Exactly 1 succeeds, 7 fail because the drop is burned
    assert len(successes) == 1
    assert len(failures) == thread_count - 1

    with SessionMaker() as session:
        # Crucial requirement: only ONE notification created
        notifs = session.query(Notification).filter_by(user_id=sender_id, related_resource_id=drop_id).all()
        assert len(notifs) == 1
        assert notifs[0].type == "drop_extracted"
        assert notifs[0].title == "你的密信已被成功提取"
