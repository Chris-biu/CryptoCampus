from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
import tempfile
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
from app.models.user import User
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.drop import DropService
from app.services.drop_destruction import DropDestructionService
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
        return b"Concurrent burn secret payload"


@pytest.fixture
def concurrency_env():
    db_file = os.path.join(tempfile.gettempdir(), f"drop_concurrency_{uuid.uuid4().hex}.db")
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
        session.add_all([ca_cert, sender_cert])
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


def _create_concurrent_drop(
    SessionMaker,
    crypto: ConcurrencyMockCryptoEngine,
    sender_id: str,
    recipient_id: str,
    now: datetime,
    *,
    burn_after_read: bool = True,
    expires_at: datetime | None = None,
) -> tuple[str, str, str]:
    code = f"ConcDrop{uuid.uuid4().hex[:8]}"
    access_code = f"AC-{uuid.uuid4().hex[:8].upper()}"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fp = b"\x44" * 32
    drop_id = str(uuid.uuid4())

    with SessionMaker() as session:
        drop = Drop(
            id=drop_id,
            owner_user_id=sender_id,
            recipient_user_id=recipient_id,
            link_code_hash=code_hash,
            kind="text",
            envelope_version=1,
            ciphertext=b"encrypted content for concurrency test",
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
            ttl_policy="burn_after_read" if burn_after_read else "hours_24",
            burn_after_read=burn_after_read,
            expires_at=expires_at,
            filename=None,
            content_size=38,
            pqc_mode=False,
            status="available",
            created_at=now,
        )
        session.add(drop)
        session.commit()

    return code, access_code, drop_id


def test_concurrent_extract_burn_after_read_drop_exactly_one_succeeds(concurrency_env):
    """多线程并发提取同一阅后即焚密信，通过条件更新与事务控制，确保最多且恰好 1 次成功。"""
    SessionMaker = concurrency_env["SessionMaker"]
    crypto = concurrency_env["crypto"]
    key_provider = concurrency_env["key_provider"]
    sender_id = concurrency_env["sender_id"]
    recipient_id = concurrency_env["recipient_id"]
    now = concurrency_env["now"]

    code, access_code, drop_id = _create_concurrent_drop(
        SessionMaker, crypto, sender_id, recipient_id, now, burn_after_read=True
    )
    sm2_fp = b"\x44" * 32
    key_provider.set_key(recipient_id, sm2_fp, VALID_SM2_PRIV)

    thread_count = 10
    successes = []
    failures = []

    def extract_worker(idx: int):
        with SessionMaker() as session:
            key_cache = PrivateKeyUnlockCache()
            service = DropService(
                session=session,
                crypto_engine=crypto,
                key_cache=key_cache,
                quota_service=QuotaService(session, crypto.sm3_digest),
                recipient_resolver=DefaultRecipientKeyResolver(),
                recipient_provider=key_provider,
            )
            try:
                result, _ = service.extract_drop(
                    code=code,
                    access_code=access_code,
                    idempotency_key=f"IDEMP-CONC-THREAD-{idx:04d}-{uuid.uuid4().hex[:8]}",
                    now=now,
                )
                successes.append((idx, result.content))
            except Exception as e:
                failures.append((idx, type(e).__name__))

    with ThreadPoolExecutor(max_workers=thread_count) as pool:
        futures = [pool.submit(extract_worker, i) for i in range(thread_count)]
        for f in futures:
            f.result()

    # 断言：恰好 1 次成功，9 次失败
    assert len(successes) == 1, f"Expected 1 success, got {len(successes)}"
    assert len(failures) == thread_count - 1
    assert successes[0][1] == "Concurrent burn secret payload"

    # 最终状态断言
    with SessionMaker() as session:
        drop = session.get(Drop, drop_id)
        assert drop.status == "consumed"
        assert drop.ciphertext is None
        assert drop.nonce is None
        assert drop.tag is None
        assert drop.enc_key_sm2 is None

        # 验证全局仅有 1 条提取审计与 1 条销毁审计
        extract_audits = session.query(AuditLog).filter_by(target=f"drop:{drop_id}", action="drop.extract").count()
        destroy_audits = session.query(AuditLog).filter_by(target=f"drop:{drop_id}", action="drop.destroy").count()
        assert extract_audits == 1
        assert destroy_audits == 1

        # 验证仅有 1 条幂等提取记录
        idemp_records = session.query(DropExtractIdempotency).filter_by(drop_id=drop_id).count()
        assert idemp_records == 1


def test_concurrent_destroy_expired_batch_consistency(concurrency_env):
    """多个并发线程同时执行 destroy_expired，各密信仅被销毁一次，数量合计一致。"""
    SessionMaker = concurrency_env["SessionMaker"]
    crypto = concurrency_env["crypto"]
    sender_id = concurrency_env["sender_id"]
    recipient_id = concurrency_env["recipient_id"]
    now = concurrency_env["now"]

    drop_ids = []
    for i in range(10):
        exp = now - timedelta(hours=i + 1)
        _, _, d_id = _create_concurrent_drop(
            SessionMaker, crypto, sender_id, recipient_id, now - timedelta(days=2),
            burn_after_read=False, expires_at=exp
        )
        drop_ids.append(d_id)

    destroyed_counts = []

    def sweep_worker():
        with SessionMaker() as session:
            svc = DropDestructionService(session, crypto)
            count = svc.destroy_expired(now=now, limit=10)
            session.commit()
            destroyed_counts.append(count)

    thread_count = 5
    with ThreadPoolExecutor(max_workers=thread_count) as pool:
        futures = [pool.submit(sweep_worker) for _ in range(thread_count)]
        for f in futures:
            f.result()

    total_cleaned = sum(destroyed_counts)
    assert total_cleaned == 10, f"Expected 10 total cleaned, got {total_cleaned}"

    with SessionMaker() as session:
        for d_id in drop_ids:
            drop = session.get(Drop, d_id)
            assert drop.status == "expired"
            assert drop.ciphertext is None
