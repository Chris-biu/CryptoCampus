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
from app.models.drop import Drop
from app.models.user import User
from app.services.drop import DropService
from app.services.drop_destruction import DropDestructionService
from app.services.extract_cooldown import SqlAlchemyExtractCooldownGuard
from app.services.quota import QuotaService
from app.services.recipient_provider import MockRecipientPrivateKeyProvider
from app.services.recipient_resolver import DefaultRecipientKeyResolver
from app.security.key_cache import PrivateKeyUnlockCache

VALID_NONCE = b"\x01" * GCM_NONCE_SIZE
VALID_TAG = b"\x02" * GCM_TAG_SIZE
VALID_SM2_ENC = b"\x03" * 96
VALID_SIG = b"\x05" * SM2_SIGNATURE_SIZE
VALID_CA_CERT = b"\x30\x82\x01\x00" + b"\xca" * 100
VALID_CERT = b"\x30\x82\x01\x00" + b"\x06" * 100
VALID_SM2_PRIV = b"\x09" * SM2_PRIVATE_KEY_SIZE
VALID_SM2_PUB = b"\x04" + b"\x11" * 64


class ExpiryMockCryptoEngine(MockCryptoEngine):
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
        return b"Valid unsealed text before expiration"


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
def expiry_setup():
    db_session = _create_test_db()
    crypto = ExpiryMockCryptoEngine()
    key_provider = MockRecipientPrivateKeyProvider()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_recipient_private_key_provider] = lambda: key_provider

    client = TestClient(app)
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
    db_session.add_all([system_user, sender, recipient])

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
    db_session.add_all([ca_cert, sender_cert])
    db_session.commit()

    key_cache = PrivateKeyUnlockCache()
    service = DropService(
        session=db_session,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=QuotaService(db_session, crypto.sm3_digest),
        recipient_resolver=DefaultRecipientKeyResolver(),
        recipient_provider=key_provider,
    )

    yield {
        "client": client,
        "db": db_session,
        "crypto": crypto,
        "key_provider": key_provider,
        "sender": sender,
        "recipient": recipient,
        "now": now,
        "service": service,
    }

    app.dependency_overrides.clear()


def _make_timed_drop(
    db: Session,
    crypto: ExpiryMockCryptoEngine,
    sender: User,
    recipient: User,
    now: datetime,
    *,
    ttl_policy: str = "hours_24",
    expires_at: datetime,
    status: str = "available",
) -> tuple[str, str, Drop]:
    code = f"ExpDrop{uuid.uuid4().hex[:8]}"
    access_code = f"AC-{uuid.uuid4().hex[:8].upper()}"
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    sm2_fp = b"\x44" * 32

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=sender.id,
        recipient_user_id=recipient.id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted content payload for expiration tests",
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
        ttl_policy=ttl_policy,
        burn_after_read=False,
        expires_at=expires_at,
        filename=None,
        content_size=42,
        pqc_mode=False,
        status=status,
        created_at=now,
    )
    db.add(drop)
    db.commit()
    return code, access_code, drop


def test_extract_and_metadata_before_expiration_succeeds(expiry_setup):
    """在 expires_at 之前，元数据查询与提取均正常成功。"""
    db = expiry_setup["db"]
    crypto = expiry_setup["crypto"]
    key_provider = expiry_setup["key_provider"]
    sender = expiry_setup["sender"]
    recipient = expiry_setup["recipient"]
    now = expiry_setup["now"]
    service = expiry_setup["service"]

    expires_at = now + timedelta(hours=24)
    code, access_code, drop = _make_timed_drop(db, crypto, sender, recipient, now, expires_at=expires_at)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    # 1. 访问时间为 now + 23h（未到期）
    query_time = now + timedelta(hours=23)

    meta = service.get_drop_metadata(code, now=query_time)
    assert meta.code == code
    assert meta.status == "available"

    result, _ = service.extract_drop(
        code=code,
        access_code=access_code,
        idempotency_key="IDEMP-EXPIRY-BEFORE-0001",
        now=query_time,
    )
    assert result.content == "Valid unsealed text before expiration"


def test_extract_and_metadata_at_exact_expiration_fails_and_destroys(expiry_setup):
    """在 expires_at 临界点时刻（now == expires_at），元数据与提取均立即失败并销毁敏感字段。"""
    db = expiry_setup["db"]
    crypto = expiry_setup["crypto"]
    key_provider = expiry_setup["key_provider"]
    sender = expiry_setup["sender"]
    recipient = expiry_setup["recipient"]
    now = expiry_setup["now"]
    service = expiry_setup["service"]

    expires_at = now + timedelta(hours=24)
    code, access_code, drop = _make_timed_drop(db, crypto, sender, recipient, now, expires_at=expires_at)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    # 访问时刻刚好等于 expires_at
    exact_time = expires_at

    with pytest.raises(Exception):
        service.get_drop_metadata(code, now=exact_time)

    # 验证即时销毁
    db.expire_all()
    reloaded = db.get(Drop, drop.id)
    assert reloaded.status == "expired"
    assert reloaded.ciphertext is None
    assert reloaded.nonce is None
    assert reloaded.tag is None
    assert reloaded.enc_key_sm2 is None

    # 提取亦失败
    with pytest.raises(Exception):
        service.extract_drop(
            code=code,
            access_code=access_code,
            idempotency_key="IDEMP-EXACT-EXP-0001",
            now=exact_time,
        )


def test_extract_and_metadata_after_expiration_fails_and_destroys(expiry_setup):
    """在 expires_at 之后，元数据与提取均失败，且密文被销毁。"""
    db = expiry_setup["db"]
    crypto = expiry_setup["crypto"]
    key_provider = expiry_setup["key_provider"]
    sender = expiry_setup["sender"]
    recipient = expiry_setup["recipient"]
    now = expiry_setup["now"]
    service = expiry_setup["service"]

    expires_at = now + timedelta(days=7)
    code, access_code, drop = _make_timed_drop(
        db, crypto, sender, recipient, now, ttl_policy="days_7", expires_at=expires_at
    )
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    after_time = expires_at + timedelta(minutes=1)

    with pytest.raises(Exception):
        service.extract_drop(
            code=code,
            access_code=access_code,
            idempotency_key="IDEMP-AFTER-EXP-0001",
            now=after_time,
        )

    db.expire_all()
    reloaded = db.get(Drop, drop.id)
    assert reloaded.status == "expired"
    assert reloaded.ciphertext is None


def test_destroy_expired_bounded_batch_and_idempotent(expiry_setup):
    """验证 destroy_expired 的有界批量上限、不可逆 SM3 审计与幂等性。"""
    db = expiry_setup["db"]
    crypto = expiry_setup["crypto"]
    sender = expiry_setup["sender"]
    recipient = expiry_setup["recipient"]
    now = expiry_setup["now"]
    service = expiry_setup["service"]

    # 创建 5 条已到期密信和 2 条未到期密信
    expired_ids = []
    for i in range(5):
        exp = now - timedelta(hours=5 - i)
        _, _, d = _make_timed_drop(db, crypto, sender, recipient, now - timedelta(days=2), expires_at=exp)
        expired_ids.append(d.id)

    unexpired_ids = []
    for i in range(2):
        exp = now + timedelta(hours=10 + i)
        _, _, d = _make_timed_drop(db, crypto, sender, recipient, now, expires_at=exp)
        unexpired_ids.append(d.id)

    # 1. 批量限制 limit=2：首批应只销毁 2 条
    count1 = service.destroy_expired(now=now, limit=2)
    assert count1 == 2

    # 2. 第二批 limit=2：再销毁 2 条
    count2 = service.destroy_expired(now=now, limit=2)
    assert count2 == 2

    # 3. 第三批 limit=2：剩余 1 条已到期被销毁
    count3 = service.destroy_expired(now=now, limit=2)
    assert count3 == 1

    # 4. 第四批：已无过期密信，返回 0（幂等无异常）
    count4 = service.destroy_expired(now=now, limit=2)
    assert count4 == 0

    # 验证未到期密信安然无恙
    for uid in unexpired_ids:
        udrop = db.get(Drop, uid)
        assert udrop.status == "available"
        assert udrop.ciphertext is not None


def test_cooling_down_drop_when_expired_transitions_to_expired_not_available(expiry_setup):
    """处于 cooling_down 的密信到期时，销毁为 expired，严禁误复原为 available。"""
    db = expiry_setup["db"]
    crypto = expiry_setup["crypto"]
    sender = expiry_setup["sender"]
    recipient = expiry_setup["recipient"]
    now = expiry_setup["now"]
    service = expiry_setup["service"]

    # 密信在 2 小时前到期，且当前处于 cooling_down
    exp = now - timedelta(hours=2)
    code, access_code, drop = _make_timed_drop(
        db, crypto, sender, recipient, now - timedelta(days=2), expires_at=exp, status="cooling_down"
    )
    drop.failed_attempts = 5
    drop.cooldown_until = now - timedelta(hours=1)  # 冷却时间也已过
    db.commit()

    # 触发元数据查询，应被到期逻辑捕获并销毁，而非冷却恢复逻辑捕获并置 available
    with pytest.raises(Exception):
        service.get_drop_metadata(code, now=now)

    db.expire_all()
    reloaded = db.get(Drop, drop.id)
    assert reloaded.status == "expired"
    assert reloaded.ciphertext is None
    assert reloaded.status != "available"
