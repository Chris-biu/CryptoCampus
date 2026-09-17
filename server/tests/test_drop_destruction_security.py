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
from app.services.recipient_provider import MockRecipientPrivateKeyProvider

VALID_NONCE = b"\x01" * GCM_NONCE_SIZE
VALID_TAG = b"\x02" * GCM_TAG_SIZE
VALID_SM2_ENC = b"\x03" * 96
VALID_SIG = b"\x05" * SM2_SIGNATURE_SIZE
VALID_CA_CERT = b"\x30\x82\x01\x00" + b"\xca" * 100
VALID_CERT = b"\x30\x82\x01\x00" + b"\x06" * 100
VALID_SM2_PRIV = b"\x09" * SM2_PRIVATE_KEY_SIZE
VALID_SM2_PUB = b"\x04" + b"\x11" * 64


class SecurityAuditingCryptoEngine(MockCryptoEngine):
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
        return b"Highly confidential message plaintext"


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
def security_setup():
    db_session = _create_test_db()
    crypto = SecurityAuditingCryptoEngine()
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
    }

    app.dependency_overrides.clear()


def _make_security_drop(
    db: Session,
    crypto: SecurityAuditingCryptoEngine,
    sender: User,
    recipient: User,
    now: datetime,
    *,
    burn_after_read: bool = True,
    expires_at: datetime | None = None,
    with_password: bool = True,
) -> tuple[str, str, str | None, Drop]:
    code = f"SecCode{uuid.uuid4().hex[:8]}"
    access_code = f"AC-{uuid.uuid4().hex[:8].upper()}"
    password = "SensitiveUserPass123!" if with_password else None
    code_hash = crypto.sm3_digest(code.encode("utf-8"))
    access_code_hash = crypto.sm3_digest(access_code.encode("utf-8"))
    salt = b"\x77" * 16 if with_password else None
    sm2_fp = b"\x44" * 32

    drop = Drop(
        id=str(uuid.uuid4()),
        owner_user_id=sender.id,
        recipient_user_id=recipient.id,
        link_code_hash=code_hash,
        kind="text",
        envelope_version=1,
        ciphertext=b"encrypted payload with secret data",
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
        ttl_policy="burn_after_read" if burn_after_read else "hours_24",
        burn_after_read=burn_after_read,
        expires_at=expires_at,
        filename=None,
        content_size=34,
        pqc_mode=False,
        status="available",
        created_at=now,
    )
    db.add(drop)
    db.commit()
    return code, access_code, password, drop


def test_destroyed_drop_sanitizes_all_sensitive_database_columns(security_setup):
    """验证密信销毁后，数据库中所有敏感信封材料与口令因子盐彻底置为 NULL。"""
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code, access_code, password, drop = _make_security_drop(
        db, crypto, sender, recipient, now, burn_after_read=True, with_password=True
    )
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    resp = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "IDEMP-SEC-CHECK-0001"},
        json={"access_code": access_code, "access_password": password},
    )
    assert resp.status_code == 200

    db.expire_all()
    destroyed = db.get(Drop, drop.id)
    assert destroyed.status == "consumed"

    # 严密断言：所有敏感字段均为 None
    assert destroyed.ciphertext is None
    assert destroyed.nonce is None
    assert destroyed.tag is None
    assert destroyed.enc_key_sm2 is None
    assert destroyed.enc_key_mlkem is None
    assert destroyed.sender_signature is None
    assert destroyed.sender_certificate_der is None
    assert destroyed.access_factor_salt is None


def test_audit_logs_contain_no_plaintext_keys_passwords_or_tokens(security_setup):
    """验证审计日志中仅保留不可逆 SM3 摘要与动作类型，绝不包含明文、提取码、口令、密钥或 Token。"""
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code, access_code, password, drop = _make_security_drop(
        db, crypto, sender, recipient, now, burn_after_read=True, with_password=True
    )
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "IDEMP-SEC-AUDIT-0001"},
        json={"access_code": access_code, "access_password": password},
    )

    audits = db.query(AuditLog).filter(AuditLog.target == f"drop:{drop.id}").all()
    assert len(audits) >= 2  # drop.extract & drop.destroy

    sensitive_strings = [
        "Highly confidential message plaintext",
        access_code,
        password,
        code,
    ]

    for a in audits:
        assert len(a.detail_hash) == 32  # 必须是 32 字节 SM3 摘要
        for secret in sensitive_strings:
            assert secret not in a.action
            assert secret not in a.target
            # detail_hash 是 bytes，不能直接包含纯文本字符串
            assert secret.encode("utf-8") not in a.detail_hash


def test_consumed_drop_repeat_extract_never_invokes_kdf_or_crypto(security_setup):
    """验证已消费密信再次尝试提取时，Fail-Closed 立即拒绝，绝对不调用 KDF、CA 验证或解封。"""
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    key_provider = security_setup["key_provider"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    code, access_code, password, drop = _make_security_drop(
        db, crypto, sender, recipient, now, burn_after_read=True, with_password=True
    )
    key_provider.set_key(recipient.id, drop.recipient_sm2_fingerprint, VALID_SM2_PRIV)

    # 首次解封
    client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "IDEMP-SEC-KDF-0001"},
        json={"access_code": access_code, "access_password": password},
    )

    crypto.operation_log.clear()

    # 二次提取（带合法提取码和口令）
    resp2 = client.post(
        f"/api/v1/drops/{code}/extract",
        headers={"Idempotency-Key": "IDEMP-SEC-KDF-0002"},
        json={"access_code": access_code, "access_password": password},
    )
    assert resp2.status_code == 404
    assert resp2.json()["code"] == "NOT_FOUND"

    # 严禁任何密码运算发生
    forbidden_crypto = {
        "hkdf_sm3",
        "envelope_open",
        "cert_chain_verify",
        "crl_verify",
        "sm2_verify",
    }
    assert not (set(crypto.operation_log) & forbidden_crypto)


def test_uniform_404_error_leaks_zero_existence_or_destruction_state(security_setup):
    """验证已消费、已到期、已销毁及不存在密信统一返回相同的 404，不泄露密信状态。"""
    client = security_setup["client"]
    db = security_setup["db"]
    crypto = security_setup["crypto"]
    sender = security_setup["sender"]
    recipient = security_setup["recipient"]
    now = security_setup["now"]

    statuses = ["consumed", "expired", "destroyed"]
    for st in statuses:
        code, access_code, _, _ = _make_security_drop(
            db, crypto, sender, recipient, now, burn_after_read=False, with_password=False
        )
        drop = db.query(Drop).filter_by(link_code_hash=crypto.sm3_digest(code.encode("utf-8"))).first()
        drop.status = st
        db.commit()

        # 1. 元数据查询
        m_resp = client.get(f"/api/v1/drops/{code}")
        assert m_resp.status_code == 404
        assert m_resp.json()["code"] == "NOT_FOUND"
        assert m_resp.json()["message"] == "密信不存在或链接已失效"

        # 2. 提取接口
        e_resp = client.post(
            f"/api/v1/drops/{code}/extract",
            headers={"Idempotency-Key": f"IDEMP-UNI-{st[:4]}-0001"},
            json={"access_code": access_code},
        )
        assert e_resp.status_code == 404
        assert e_resp.json()["code"] == "NOT_FOUND"
        assert e_resp.json()["message"] == "密信不存在或链接已失效"

    # 不存在的密信
    non_existent = "NonExistentLink12345"
    resp_ne = client.get(f"/api/v1/drops/{non_existent}")
    assert resp_ne.status_code == 404
    assert resp_ne.json()["code"] == "NOT_FOUND"
    assert resp_ne.json()["message"] == "密信不存在或链接已失效"
