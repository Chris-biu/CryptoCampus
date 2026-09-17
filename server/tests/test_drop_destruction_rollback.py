from datetime import datetime, timedelta, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.drops import get_recipient_private_key_provider
from app.core.errors import DropServiceError
from app.crypto.dependencies import get_crypto_engine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
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
from app.models.drop import Drop, DropExtractIdempotency
from app.models.user import User
from app.services.drop import DropService
from app.services.drop_destruction import DropDestructionService
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

    def envelope_open(
        self,
        *,
        envelope: EnvelopeArtifact,
        recipient_sm2_private_key: bytes,
        pqc_mode: bool,
        recipient_mlkem_private_key: bytes | None,
        access_factor: bytes | None,
    ) -> bytes:
        if "envelope_open" in self._errors:
            raise self._errors["envelope_open"]
        return self._results.get("envelope_open", b"Mock unsealed secret payload")


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

    yield {
        "client": client,
        "db": db_session,
        "crypto": crypto,
        "key_provider": key_provider,
        "sender": sender,
        "recipient": recipient,
        "now": now,
        "app": app,
    }

    app.dependency_overrides.clear()


def _make_burn_drop(
    db: Session,
    crypto: RollbackMockCryptoEngine,
    sender: User,
    recipient: User,
    now: datetime,
) -> tuple[str, str, Drop]:
    code = f"RollbackDrop{uuid.uuid4().hex[:8]}"
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
        ciphertext=b"encrypted secret payload for rollback test",
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
        ttl_policy="burn_after_read",
        burn_after_read=True,
        expires_at=None,
        filename=None,
        content_size=42,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()
    return code, access_code, drop


def test_destruction_failure_triggers_full_rollback(rollback_setup):
    """当 destroy_after_success 抛出异常时，外层事务完整回滚：密信不被标记 consumed，敏感材料不丢失。"""
    db = rollback_setup["db"]
    crypto = rollback_setup["crypto"]
    key_provider = rollback_setup["key_provider"]
    sender = rollback_setup["sender"]
    recipient = rollback_setup["recipient"]
    now = rollback_setup["now"]

    code, access_code, drop = _make_burn_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    def failing_destroy(drop_id, now, actor_id=None):
        raise RuntimeError("Simulated destruction service DB failure")

    from app.services.quota import QuotaService
    from app.services.recipient_resolver import DefaultRecipientKeyResolver
    from app.security.key_cache import PrivateKeyUnlockCache

    key_cache = PrivateKeyUnlockCache()
    service = DropService(
        session=db,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=QuotaService(db, crypto.sm3_digest),
        recipient_resolver=DefaultRecipientKeyResolver(),
        recipient_provider=key_provider,
    )
    service.destruction_service.destroy_after_success = failing_destroy

    with pytest.raises(RuntimeError) as exc_info:
        service.extract_drop(
            code=code,
            access_code=access_code,
            idempotency_key="IDEMP-ROLLBACK-111122223333",
            now=now,
        )
    assert "Simulated destruction service DB failure" in str(exc_info.value)

    # 验证数据库完整回滚
    db.expire_all()
    reloaded = db.get(Drop, drop.id)
    assert reloaded.status == "available"
    assert reloaded.ciphertext == b"encrypted secret payload for rollback test"
    assert reloaded.nonce == VALID_NONCE
    assert reloaded.tag == VALID_TAG
    assert reloaded.enc_key_sm2 == VALID_SM2_ENC

    # 无审计或幂等记录泄漏
    assert db.query(AuditLog).filter(AuditLog.target == f"drop:{drop.id}").count() == 0
    assert db.query(DropExtractIdempotency).filter(DropExtractIdempotency.drop_id == drop.id).count() == 0


def test_audit_log_failure_triggers_full_rollback(rollback_setup):
    """当审计写入失败时，整个事务回滚，密信保持 available 且密文保留。"""
    db = rollback_setup["db"]
    crypto = rollback_setup["crypto"]
    key_provider = rollback_setup["key_provider"]
    sender = rollback_setup["sender"]
    recipient = rollback_setup["recipient"]
    now = rollback_setup["now"]

    code, access_code, drop = _make_burn_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    from app.services.quota import QuotaService
    from app.services.recipient_resolver import DefaultRecipientKeyResolver
    from app.security.key_cache import PrivateKeyUnlockCache

    key_cache = PrivateKeyUnlockCache()
    service = DropService(
        session=db,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=QuotaService(db, crypto.sm3_digest),
        recipient_resolver=DefaultRecipientKeyResolver(),
        recipient_provider=key_provider,
    )

    # 模拟 session.add 在 AuditLog 时抛出异常
    real_add = db.add
    def failing_add(instance):
        if isinstance(instance, AuditLog) and instance.action == "drop.extract":
            raise RuntimeError("Simulated AuditLog database failure")
        return real_add(instance)

    db.add = failing_add

    with pytest.raises(RuntimeError) as exc_info:
        service.extract_drop(
            code=code,
            access_code=access_code,
            idempotency_key="IDEMP-ROLLBACK-AUDIT-FAIL",
            now=now,
        )
    assert "Simulated AuditLog database failure" in str(exc_info.value)

    db.add = real_add

    db.expire_all()
    reloaded = db.get(Drop, drop.id)
    assert reloaded.status == "available"
    assert reloaded.ciphertext is not None
    assert db.query(DropExtractIdempotency).filter(DropExtractIdempotency.drop_id == drop.id).count() == 0


def test_unseal_failure_does_not_destroy_drop(rollback_setup):
    """当数字信封解封失败（如 CryptoBridgeError）时，密信不被销毁，保持原样。"""
    client = rollback_setup["client"]
    db = rollback_setup["db"]
    crypto = rollback_setup["crypto"]
    key_provider = rollback_setup["key_provider"]
    sender = rollback_setup["sender"]
    recipient = rollback_setup["recipient"]
    now = rollback_setup["now"]

    code, access_code, drop = _make_burn_drop(db, crypto, sender, recipient, now)
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    # 注入解封错误
    crypto.set_error(
        "envelope_open",
        CryptoBridgeError(BridgeErrorCode.INTEGRITY_FAILED),
    )

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "IDEMP-FAIL-UNSEAL-1111"},
        json={"access_code": access_code},
    )
    assert resp.status_code == 404

    # 密信依然处于 available 状态，密文完好
    db.expire_all()
    reloaded = db.get(Drop, drop.id)
    assert reloaded.status == "available"
    assert reloaded.ciphertext == b"encrypted secret payload for rollback test"
    assert db.query(AuditLog).filter(AuditLog.target == f"drop:{drop.id}").count() == 0
