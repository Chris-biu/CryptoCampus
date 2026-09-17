from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    SM2_PRIVATE_KEY_SIZE,
    SM2_PUBLIC_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
    EnvelopeArtifact,
)
from app.db.base import Base
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord
from app.models.credential import CredentialLedger
from app.models.drop import Drop, DropIdempotency
from app.models.user import User
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.quota import QuotaService
from app.services.recipient_resolver import ConfiguredRecipientKeyResolver, DefaultRecipientKeyResolver


def _create_sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def _setup_users_and_cert(session: Session) -> tuple[User, User, CertificateRecord]:
    sender_id = str(uuid.uuid4())
    recipient_id = str(uuid.uuid4())

    sender = User(
        id=sender_id,
        email="sender@stu.edu.cn",
        role="student",
        status="active",
        pubkey=b"\x04" + b"\x11" * 64,
        cert_serial="CERT-SENDER-001",
    )
    recipient = User(
        id=recipient_id,
        email="recipient@stu.edu.cn",
        role="student",
        status="active",
        pubkey=b"\x04" + b"\x22" * 64,
    )
    session.add_all([sender, recipient])

    cert = CertificateRecord(
        serial="CERT-SENDER-001",
        subject_user_id=sender_id,
        issuer_serial="CA-ROOT-001",
        kind="user_identity",
        certificate_der=b"\x30\x82\x01\x00" + b"\x55" * 100,
        key_usage="digitalSignature",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=365),
        status="active",
    )
    session.add(cert)
    session.commit()
    return sender, recipient, cert


def _setup_mock_crypto() -> MockCryptoEngine:
    crypto = MockCryptoEngine()
    crypto.set_result("sm3_digest", b"\xaa" * 32)
    crypto.set_result("hkdf_sm3", b"\xbb" * 32)
    artifact = EnvelopeArtifact(
        ciphertext=b"encrypted_ciphertext",
        nonce=b"\x01" * GCM_NONCE_SIZE,
        tag=b"\x02" * GCM_TAG_SIZE,
        enc_key_sm2=b"\x03" * 96,
        enc_key_mlkem=None,
        sender_signature=b"\x04" * SM2_SIGNATURE_SIZE,
        sender_certificate=b"\x30\x82\x01\x00" + b"\x55" * 100,
    )
    crypto.set_result("envelope_seal", artifact)
    return crypto


def test_create_text_drop_success_and_atomic_persistence() -> None:
    from app.services.drop import DropService

    session = _create_sqlite_session()
    sender, recipient, cert = _setup_users_and_cert(session)
    crypto = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, b"\x77" * SM2_PRIVATE_KEY_SIZE, datetime.now(timezone.utc) + timedelta(minutes=15))

    quota_service = QuotaService(session, digest=crypto.sm3_digest)
    resolver = ConfiguredRecipientKeyResolver(recipient.id, crypto)
    service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=quota_service,
        recipient_resolver=resolver,
    )

    now = datetime.now(timezone.utc)
    resp = service.create_text_drop(
        sender_id=sender.id,
        content="Confidential course material",
        ttl_policy="hours_24",
        pqc_mode=False,
        access_password="SecretPassword123",
        idempotency_key="idemp-key-0000000001",
        now=now,
    )

    # Response validations
    assert resp.id
    assert len(resp.code) == 16
    assert len(resp.access_code) == 16
    assert resp.url == f"/d/{resp.code}"
    assert resp.expires_at is not None
    assert resp.pqc_mode is False

    # DB persistence validations
    drop = session.get(Drop, resp.id)
    assert drop is not None
    assert drop.owner_user_id == sender.id
    assert drop.recipient_user_id == recipient.id
    assert drop.kind == "text"
    assert drop.ciphertext == b"encrypted_ciphertext"
    assert drop.sender_cert_serial == cert.serial
    assert drop.burn_after_read is False

    # Verify idempotency record
    idemp = session.query(DropIdempotency).filter_by(owner_user_id=sender.id, operation="create_text").first()
    assert idemp is not None
    assert idemp.drop_id == resp.id

    # Verify audit log
    audit = session.query(AuditLog).filter_by(actor=sender.id, action="drop.create").first()
    assert audit is not None
    assert audit.target == f"drop:{resp.id}"

    # Verify quota incremented
    period = now.date().isoformat()
    ledger = session.query(CredentialLedger).filter_by(user_id=sender.id, service="drop", period=period).first()
    assert ledger is not None
    assert ledger.issued_count == 1


def test_create_drop_idempotency_replay_conflict() -> None:
    from app.services.drop import DropService, DropServiceError

    session = _create_sqlite_session()
    sender, recipient, _ = _setup_users_and_cert(session)
    crypto = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, b"\x77" * SM2_PRIVATE_KEY_SIZE, datetime.now(timezone.utc) + timedelta(minutes=15))

    quota_service = QuotaService(session, digest=crypto.sm3_digest)
    resolver = ConfiguredRecipientKeyResolver(recipient.id, crypto)
    service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=quota_service,
        recipient_resolver=resolver,
    )

    now = datetime.now(timezone.utc)
    service.create_text_drop(
        sender_id=sender.id,
        content="First message",
        ttl_policy="hours_24",
        pqc_mode=False,
        access_password=None,
        idempotency_key="duplicate-idemp-key-12345",
        now=now,
    )

    # Replay with same key must raise idempotency conflict
    with pytest.raises(DropServiceError) as exc:
        service.create_text_drop(
            sender_id=sender.id,
            content="First message",
            ttl_policy="hours_24",
            pqc_mode=False,
            access_password=None,
            idempotency_key="duplicate-idemp-key-12345",
            now=now,
        )
    assert exc.value.code == "idempotency_conflict"

    # Verify only 1 drop was created and quota is 1
    assert session.query(Drop).count() == 1
    period = now.date().isoformat()
    ledger = session.query(CredentialLedger).filter_by(user_id=sender.id, service="drop", period=period).one()
    assert ledger.issued_count == 1


def test_create_drop_fails_closed_when_recipient_unresolved() -> None:
    from app.services.drop import DropService, DropServiceError

    session = _create_sqlite_session()
    sender, _, _ = _setup_users_and_cert(session)
    crypto = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, b"\x77" * SM2_PRIVATE_KEY_SIZE, datetime.now(timezone.utc) + timedelta(minutes=15))

    quota_service = QuotaService(session, digest=crypto.sm3_digest)
    # Use default resolver which returns None
    service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=quota_service,
        recipient_resolver=DefaultRecipientKeyResolver(),
    )

    now = datetime.now(timezone.utc)
    with pytest.raises(DropServiceError) as exc:
        service.create_text_drop(
            sender_id=sender.id,
            content="Message to nowhere",
            ttl_policy="hours_24",
            pqc_mode=False,
            access_password=None,
            idempotency_key="idemp-key-0000000002",
            now=now,
        )
    assert exc.value.code == "recipient_resolution_failed"
    assert session.query(Drop).count() == 0


def test_create_drop_fails_when_private_key_locked() -> None:
    from app.services.drop import DropService, DropServiceError

    session = _create_sqlite_session()
    sender, recipient, _ = _setup_users_and_cert(session)
    crypto = _setup_mock_crypto()
    empty_key_cache = PrivateKeyUnlockCache()  # not unlocked

    quota_service = QuotaService(session, digest=crypto.sm3_digest)
    resolver = ConfiguredRecipientKeyResolver(recipient.id, crypto)
    service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=empty_key_cache,
        quota_service=quota_service,
        recipient_resolver=resolver,
    )

    now = datetime.now(timezone.utc)
    with pytest.raises(DropServiceError) as exc:
        service.create_text_drop(
            sender_id=sender.id,
            content="Message without private key",
            ttl_policy="hours_24",
            pqc_mode=False,
            access_password=None,
            idempotency_key="idemp-key-0000000003",
            now=now,
        )
    assert exc.value.code == "key_not_unlocked"
    assert session.query(Drop).count() == 0


def test_create_drop_rolls_back_atomically_on_engine_failure() -> None:
    from app.services.drop import DropService

    session = _create_sqlite_session()
    sender, recipient, _ = _setup_users_and_cert(session)
    crypto = _setup_mock_crypto()
    # Force engine failure
    crypto.set_error("envelope_seal", CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))

    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, b"\x77" * SM2_PRIVATE_KEY_SIZE, datetime.now(timezone.utc) + timedelta(minutes=15))

    quota_service = QuotaService(session, digest=crypto.sm3_digest)
    resolver = ConfiguredRecipientKeyResolver(recipient.id, crypto)
    service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=quota_service,
        recipient_resolver=resolver,
    )

    now = datetime.now(timezone.utc)
    with pytest.raises(CryptoBridgeError):
        service.create_text_drop(
            sender_id=sender.id,
            content="Will fail in engine",
            ttl_policy="hours_24",
            pqc_mode=False,
            access_password=None,
            idempotency_key="idemp-key-0000000004",
            now=now,
        )

    # Everything must have rolled back!
    assert session.query(Drop).count() == 0
    assert session.query(DropIdempotency).count() == 0
    period = now.date().isoformat()
    ledger = session.query(CredentialLedger).filter_by(user_id=sender.id, service="drop", period=period).first()
    # No quota deduced or issued_count == 0
    assert ledger is None or ledger.issued_count == 0


def test_create_file_drop_success() -> None:
    from app.services.drop import DropService

    session = _create_sqlite_session()
    sender, recipient, _ = _setup_users_and_cert(session)
    crypto = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, b"\x77" * SM2_PRIVATE_KEY_SIZE, datetime.now(timezone.utc) + timedelta(minutes=15))

    quota_service = QuotaService(session, digest=crypto.sm3_digest)
    resolver = ConfiguredRecipientKeyResolver(recipient.id, crypto)
    service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=quota_service,
        recipient_resolver=resolver,
    )

    now = datetime.now(timezone.utc)
    file_bytes = b"%PDF-1.4 test document binary content"
    resp = service.create_file_drop(
        sender_id=sender.id,
        file_bytes=file_bytes,
        filename="sub/dir/secret_report.pdf",
        ttl_policy="days_7",
        pqc_mode=False,
        access_password="Password123",
        idempotency_key="idemp-key-file-00001",
        now=now,
    )

    assert resp.id
    drop = session.get(Drop, resp.id)
    assert drop is not None
    assert drop.kind == "file"
    assert drop.filename == "secret_report.pdf"  # sanitized basename
    assert drop.content_size == len(file_bytes)
    assert drop.ttl_policy == "days_7"
    assert drop.expires_at is not None


def test_create_drop_quota_exhausted() -> None:
    from app.services.drop import DropService, DropServiceError

    session = _create_sqlite_session()
    sender, recipient, _ = _setup_users_and_cert(session)
    crypto = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, b"\x77" * SM2_PRIVATE_KEY_SIZE, datetime.now(timezone.utc) + timedelta(minutes=15))

    quota_service = QuotaService(session, digest=crypto.sm3_digest)
    resolver = ConfiguredRecipientKeyResolver(recipient.id, crypto)
    service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=quota_service,
        recipient_resolver=resolver,
    )

    now = datetime.now(timezone.utc)
    # Simulate already 20 drops used today
    period = now.date().isoformat()
    session.add(CredentialLedger(user_id=sender.id, service="drop", period=period, issued_count=20))
    session.commit()

    with pytest.raises(DropServiceError) as exc:
        service.create_text_drop(
            sender_id=sender.id,
            content="Message exceeding quota",
            ttl_policy="hours_24",
            pqc_mode=False,
            access_password=None,
            idempotency_key="idemp-key-exhaust-01",
            now=now,
        )
    assert exc.value.code == "quota_exhausted"
    assert session.query(Drop).count() == 0


def test_create_drop_burn_after_read_ttl() -> None:
    from app.services.drop import DropService

    session = _create_sqlite_session()
    sender, recipient, _ = _setup_users_and_cert(session)
    crypto = _setup_mock_crypto()
    key_cache = PrivateKeyUnlockCache()
    key_cache.put(sender.id, b"\x77" * SM2_PRIVATE_KEY_SIZE, datetime.now(timezone.utc) + timedelta(minutes=15))

    quota_service = QuotaService(session, digest=crypto.sm3_digest)
    resolver = ConfiguredRecipientKeyResolver(recipient.id, crypto)
    service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=quota_service,
        recipient_resolver=resolver,
    )

    now = datetime.now(timezone.utc)
    resp = service.create_text_drop(
        sender_id=sender.id,
        content="Burn after read message",
        ttl_policy="burn_after_read",
        pqc_mode=False,
        access_password=None,
        idempotency_key="idemp-key-burn-00001",
        now=now,
    )

    assert resp.expires_at is None
    drop = session.get(Drop, resp.id)
    assert drop is not None
    assert drop.burn_after_read is True
    assert drop.expires_at is None
