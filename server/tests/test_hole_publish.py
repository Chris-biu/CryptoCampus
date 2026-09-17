import base64
from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE, SM2_SIGNATURE_SIZE
from app.db.base import Base
from app.models.audit import RevocationLog
from app.models.credential import ConsumedSN
from app.models.hole import HolePost, HolePostIdempotency
from app.models.user import User
from app.schemas.credential import CredentialProof
from app.services.hole_posts import HolePostService, HolePostServiceError


class DynamicMockCryptoEngine(MockCryptoEngine):
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


class MockVerificationKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x04" + b"\x33" * (SM2_PUBLIC_KEY_SIZE - 1))

    def get_signer_public_key(self, service: str) -> bytes | None:
        return self.key


def _setup_publish_env():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()

    crypto_engine = DynamicMockCryptoEngine()
    crypto_engine.set_result("blind_verify", True)
    key_provider = MockVerificationKeyProvider()

    service = HolePostService(
        session=session,
        crypto_engine=crypto_engine,
        signer_verification_key_provider=key_provider,
    )
    now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    return session, crypto_engine, key_provider, service, now


def test_publish_success_creates_post_consumed_sn_and_idempotency():
    session, crypto_engine, key_provider, service, now = _setup_publish_env()

    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    post = service.publish(
        content="First anonymous post!",
        credential=proof,
        idempotency_key="idemp-key-1234567890",
        now=now,
    )

    assert post.id is not None
    assert post.content == "First anonymous post!"
    assert post.credential_prefix == "00112233"
    assert post.credential_valid is True
    assert post.status == "published"

    # Check ConsumedSN in DB
    sn_bytes = bytes.fromhex(sn_hex)
    consumed = session.get(ConsumedSN, (sn_bytes, "hole_post"))
    assert consumed is not None
    assert consumed.consumed_at.replace(tzinfo=timezone.utc) == now

    # Check HolePostIdempotency in DB
    idemp = session.query(HolePostIdempotency).filter_by(post_id=post.id).first()
    assert idemp is not None


def test_publish_rejects_invalid_signature_writes_no_records():
    session, crypto_engine, key_provider, service, now = _setup_publish_env()
    crypto_engine.set_result("blind_verify", False)

    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x00" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    with pytest.raises(HolePostServiceError) as exc_info:
        service.publish(
            content="Invalid signature post",
            credential=proof,
            idempotency_key="idemp-key-1234567890",
            now=now,
        )
    assert exc_info.value.code == "invalid_signature"

    # Verify no records written
    assert session.query(HolePost).count() == 0
    assert session.query(ConsumedSN).count() == 0
    assert session.query(HolePostIdempotency).count() == 0


def test_publish_rejects_wrong_service_writes_no_records():
    session, crypto_engine, key_provider, service, now = _setup_publish_env()

    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_comment",  # Not hole_post!
        period="2026-09-09",
        signature=sig_b64,
    )

    with pytest.raises(HolePostServiceError) as exc_info:
        service.publish(
            content="Wrong service post",
            credential=proof,
            idempotency_key="idemp-key-1234567890",
            now=now,
        )
    assert exc_info.value.code == "invalid_service"

    assert session.query(HolePost).count() == 0
    assert session.query(ConsumedSN).count() == 0


def test_publish_rejects_wrong_period_writes_no_records():
    session, crypto_engine, key_provider, service, now = _setup_publish_env()

    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-08",  # Yesterday!
        signature=sig_b64,
    )

    with pytest.raises(HolePostServiceError) as exc_info:
        service.publish(
            content="Wrong period post",
            credential=proof,
            idempotency_key="idemp-key-1234567890",
            now=now,
        )
    assert exc_info.value.code == "invalid_period"

    assert session.query(HolePost).count() == 0
    assert session.query(ConsumedSN).count() == 0


def test_publish_rejects_revoked_credential_writes_no_records():
    session, crypto_engine, key_provider, service, now = _setup_publish_env()

    sn_bytes = bytes.fromhex("00112233445566778899aabbccddeeff")
    operator = User(id="op-1", email="op@test.edu.cn", role="admin", status="active")
    session.add(operator)
    session.commit()

    revocation = RevocationLog(
        hash_curr=b"\x55" * 32,
        sn=sn_bytes,
        reason="Compromised key",
        operator="op-1",
        ts=now,
    )
    session.add(revocation)
    session.commit()

    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_bytes.hex(),
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    with pytest.raises(HolePostServiceError) as exc_info:
        service.publish(
            content="Revoked credential post",
            credential=proof,
            idempotency_key="idemp-key-1234567890",
            now=now,
        )
    assert exc_info.value.code == "credential_revoked"

    assert session.query(HolePost).count() == 0
    assert session.query(ConsumedSN).count() == 0


def test_publish_rejects_already_consumed_sn():
    session, crypto_engine, key_provider, service, now = _setup_publish_env()

    sn_bytes = bytes.fromhex("00112233445566778899aabbccddeeff")
    session.add(ConsumedSN(sn=sn_bytes, service="hole_post", consumed_at=now))
    session.commit()

    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_bytes.hex(),
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    with pytest.raises(HolePostServiceError) as exc_info:
        service.publish(
            content="Duplicate SN post",
            credential=proof,
            idempotency_key="idemp-key-1234567890",
            now=now,
        )
    assert exc_info.value.code == "credential_consumed"


def test_publish_provider_unavailable_fails_safely():
    session, crypto_engine, key_provider, service, now = _setup_publish_env()
    key_provider.key = None  # Missing public key

    proof = CredentialProof(
        sn="00112233445566778899aabbccddeeff",
        service="hole_post",
        period="2026-09-09",
        signature=base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii"),
    )

    with pytest.raises(HolePostServiceError) as exc_info:
        service.publish(
            content="Test post",
            credential=proof,
            idempotency_key="idemp-key-1234567890",
            now=now,
        )
    assert exc_info.value.code == "engine_unavailable"
    assert session.query(HolePost).count() == 0
    assert session.query(ConsumedSN).count() == 0
