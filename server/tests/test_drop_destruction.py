from datetime import datetime, timedelta, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
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
from app.services.recipient_provider import MockRecipientPrivateKeyProvider

VALID_NONCE = b"\x01" * GCM_NONCE_SIZE
VALID_TAG = b"\x02" * GCM_TAG_SIZE
VALID_SM2_ENC = b"\x03" * 96
VALID_SIG = b"\x05" * SM2_SIGNATURE_SIZE
VALID_CA_CERT = b"\x30\x82\x01\x00" + b"\xca" * 100
VALID_CERT = b"\x30\x82\x01\x00" + b"\x06" * 100
VALID_SM2_PRIV = b"\x09" * SM2_PRIVATE_KEY_SIZE
VALID_SM2_PUB = b"\x04" + b"\x11" * 64


class DestructionMockCryptoEngine(MockCryptoEngine):
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
        return True

    def crl_verify(
        self, certificate_der: bytes, crl_der: bytes, verification_time: int
    ) -> bool:
        self.operation_log.append("crl_verify")
        return True

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        self.operation_log.append("sm2_verify")
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
        self.operation_log.append("envelope_open")
        if "envelope_open" in self._errors:
            raise self._errors["envelope_open"]
        return self._results.get("envelope_open", b"Burn after reading secret text")


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
def destruction_setup():
    db_session = _create_test_db()
    crypto = DestructionMockCryptoEngine()
    key_provider = MockRecipientPrivateKeyProvider()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_recipient_private_key_provider] = lambda: key_provider

    client = TestClient(app)
    # Keep route-level expiry checks independent from the wall-clock date on
    # which CI happens to run. Several tests call the HTTP route, whose service
    # intentionally uses the current UTC time rather than this fixture value.
    now = datetime.now(timezone.utc).replace(microsecond=0)

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
        "sender_cert": sender_cert,
        "now": now,
    }

    app.dependency_overrides.clear()


def _make_test_drop(
    db: Session,
    crypto: DestructionMockCryptoEngine,
    sender: User,
    recipient: User,
    now: datetime,
    *,
    burn_after_read: bool = True,
    ttl_policy: str = "burn_after_read",
    expires_at: datetime | None = None,
    status: str = "available",
) -> tuple[str, str, Drop]:
    code = f"Code{uuid.uuid4().hex[:10]}"
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
        ciphertext=b"encrypted burn secret",
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
        burn_after_read=burn_after_read,
        expires_at=expires_at,
        filename=None,
        content_size=25,
        pqc_mode=False,
        status=status,
        created_at=now,
    )
    db.add(drop)
    db.commit()
    return code, access_code, drop


# ==============================================================================
# Task 1: Model & Status constraints
# ==============================================================================

def test_drop_model_allows_null_sensitive_fields_upon_destruction(destruction_setup):
    """验证 Drop 模型允许敏感字段置空，以支持销毁后仅保留墓碑与审计摘要。"""
    db = destruction_setup["db"]
    crypto = destruction_setup["crypto"]
    sender = destruction_setup["sender"]
    recipient = destruction_setup["recipient"]
    now = destruction_setup["now"]

    code, access_code, drop = _make_test_drop(db, crypto, sender, recipient, now)

    # 模拟销毁清空
    drop.status = "consumed"
    drop.ciphertext = None
    drop.nonce = None
    drop.tag = None
    drop.enc_key_sm2 = None
    drop.enc_key_mlkem = None
    drop.sender_signature = None
    drop.sender_certificate_der = None
    drop.access_factor_salt = None

    db.commit()

    refreshed = db.get(Drop, drop.id)
    assert refreshed.status == "consumed"
    assert refreshed.ciphertext is None
    assert refreshed.nonce is None
    assert refreshed.tag is None
    assert refreshed.enc_key_sm2 is None
    assert refreshed.enc_key_mlkem is None
    assert refreshed.sender_signature is None
    assert refreshed.sender_certificate_der is None
    assert refreshed.access_factor_salt is None

    # 墓碑关键字段必须保留
    assert refreshed.id == drop.id
    assert refreshed.owner_user_id == sender.id
    assert refreshed.recipient_user_id == recipient.id
    assert refreshed.burn_after_read is True
    assert refreshed.ttl_policy == "burn_after_read"


@pytest.mark.parametrize("valid_status", ["available", "cooling_down", "consumed", "expired", "destroyed"])
def test_drop_model_valid_statuses(destruction_setup, valid_status):
    """验证所有合法状态均符合数据库约束。"""
    db = destruction_setup["db"]
    crypto = destruction_setup["crypto"]
    sender = destruction_setup["sender"]
    recipient = destruction_setup["recipient"]
    now = destruction_setup["now"]

    _, _, drop = _make_test_drop(db, crypto, sender, recipient, now, status=valid_status)
    assert drop.status == valid_status


def test_drop_model_invalid_status_rejected(destruction_setup):
    """验证非法状态被 CheckConstraint 拒绝。"""
    db = destruction_setup["db"]
    crypto = destruction_setup["crypto"]
    sender = destruction_setup["sender"]
    recipient = destruction_setup["recipient"]
    now = destruction_setup["now"]

    with pytest.raises(IntegrityError):
        _make_test_drop(db, crypto, sender, recipient, now, status="unknown_status")


@pytest.mark.parametrize("valid_ttl", ["burn_after_read", "hours_24", "days_7"])
def test_drop_model_valid_ttl_policies(destruction_setup, valid_ttl):
    """验证合法的 TTL policies。"""
    db = destruction_setup["db"]
    crypto = destruction_setup["crypto"]
    sender = destruction_setup["sender"]
    recipient = destruction_setup["recipient"]
    now = destruction_setup["now"]

    _, _, drop = _make_test_drop(db, crypto, sender, recipient, now, ttl_policy=valid_ttl)
    assert drop.ttl_policy == valid_ttl


def test_drop_model_invalid_ttl_policy_rejected(destruction_setup):
    """验证非法 TTL policy 被拒绝。"""
    db = destruction_setup["db"]
    crypto = destruction_setup["crypto"]
    sender = destruction_setup["sender"]
    recipient = destruction_setup["recipient"]
    now = destruction_setup["now"]

    with pytest.raises(IntegrityError):
        _make_test_drop(db, crypto, sender, recipient, now, ttl_policy="hours_48")


# ==============================================================================
# Task 2: Burn-after-reading atomic destruction
# ==============================================================================

def test_burn_after_read_first_extract_succeeds_and_destroys(destruction_setup):
    """阅后即焚密信首次提取成功后，原子置为 consumed 并清空敏感信封材料。"""
    client = destruction_setup["client"]
    db = destruction_setup["db"]
    crypto = destruction_setup["crypto"]
    key_provider = destruction_setup["key_provider"]
    sender = destruction_setup["sender"]
    recipient = destruction_setup["recipient"]
    now = destruction_setup["now"]

    code, access_code, drop = _make_test_drop(
        db, crypto, sender, recipient, now, burn_after_read=True, ttl_policy="burn_after_read"
    )
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"Top secret burn-after-reading text")

    idemp_key = "IDEMP-BURN-1111222233334444"

    # 1. 首次提取：必须成功返回明文
    resp1 = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idemp_key},
        json={"access_code": access_code},
    )
    assert resp1.status_code == 200, resp1.text
    data1 = resp1.json()
    assert data1["content"] == "Top secret burn-after-reading text"
    assert data1["signature_valid"] is True
    assert data1["certificate_valid"] is True

    # 2. 检查数据库中密信状态与字段清理
    db.expire_all()
    consumed_drop = db.get(Drop, drop.id)
    assert consumed_drop.status == "consumed"
    assert consumed_drop.ciphertext is None
    assert consumed_drop.nonce is None
    assert consumed_drop.tag is None
    assert consumed_drop.enc_key_sm2 is None
    assert consumed_drop.enc_key_mlkem is None
    assert consumed_drop.sender_signature is None
    assert consumed_drop.sender_certificate_der is None
    assert consumed_drop.access_factor_salt is None

    # 3. 验证审计日志记录销毁动作
    audit_destroy = (
        db.query(AuditLog)
        .filter(AuditLog.target == f"drop:{drop.id}", AuditLog.action == "drop.destroy")
        .first()
    )
    assert audit_destroy is not None
    assert audit_destroy.actor == recipient.id
    assert len(audit_destroy.detail_hash) == 32


def test_burn_after_read_second_extract_fails_with_same_or_diff_idempotency_key(destruction_setup):
    """已消费的阅后即焚密信，第二次提取（相同或不同幂等键）均返回 404，且不调用密码运算。"""
    client = destruction_setup["client"]
    db = destruction_setup["db"]
    crypto = destruction_setup["crypto"]
    key_provider = destruction_setup["key_provider"]
    sender = destruction_setup["sender"]
    recipient = destruction_setup["recipient"]
    now = destruction_setup["now"]

    code, access_code, drop = _make_test_drop(
        db, crypto, sender, recipient, now, burn_after_read=True, ttl_policy="burn_after_read"
    )
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"Top secret burn-after-reading text")

    idemp_key_1 = "IDEMP-BURN-KEY-AAAA11112222"
    idemp_key_2 = "IDEMP-BURN-KEY-BBBB33334444"

    # 首次提取成功
    resp1 = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idemp_key_1},
        json={"access_code": access_code},
    )
    assert resp1.status_code == 200

    # 清空调用日志，准备观察后续调用
    crypto.operation_log.clear()

    # 第二次提取（使用相同幂等键）必须失败 404
    resp2 = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idemp_key_1},
        json={"access_code": access_code},
    )
    assert resp2.status_code == 404
    assert resp2.json()["code"] == "NOT_FOUND"

    # 严禁调用解密相关操作
    forbidden_ops = {"envelope_open", "cert_chain_verify", "sm2_verify", "hkdf_sm3"}
    assert not (set(crypto.operation_log) & forbidden_ops)

    # 第三次提取（使用不同幂等键）亦必须失败 404
    resp3 = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idemp_key_2},
        json={"access_code": access_code},
    )
    assert resp3.status_code == 404
    assert resp3.json()["code"] == "NOT_FOUND"
    assert not (set(crypto.operation_log) & forbidden_ops)


def test_non_burn_after_read_drop_remains_available_after_extract(destruction_setup):
    """非阅后即焚密信（例如 hours_24）在首次提取后保持 available，敏感信封材料不被清理。"""
    client = destruction_setup["client"]
    db = destruction_setup["db"]
    crypto = destruction_setup["crypto"]
    key_provider = destruction_setup["key_provider"]
    sender = destruction_setup["sender"]
    recipient = destruction_setup["recipient"]
    now = destruction_setup["now"]

    code, access_code, drop = _make_test_drop(
        db,
        crypto,
        sender,
        recipient,
        now,
        burn_after_read=False,
        ttl_policy="hours_24",
        expires_at=now + timedelta(hours=24),
    )
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)
    crypto.set_result("envelope_open", b"Reusable secret content")

    idemp_key = "IDEMP-HOURS24-111122223333"

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": idemp_key},
        json={"access_code": access_code},
    )
    assert resp.status_code == 200

    db.expire_all()
    reloaded = db.get(Drop, drop.id)
    assert reloaded.status == "available"
    assert reloaded.ciphertext is not None
    assert reloaded.nonce is not None
    assert reloaded.tag is not None
    assert reloaded.enc_key_sm2 is not None
    assert reloaded.sender_signature is not None
    assert reloaded.sender_certificate_der is not None
