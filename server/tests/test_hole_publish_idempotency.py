import base64
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE, SM2_SIGNATURE_SIZE
from app.db.base import Base
from app.models.credential import ConsumedSN
from app.models.hole import HolePost, HolePostIdempotency
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


def _setup_idempotency_env():
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


def test_idempotent_replay_returns_same_post_without_duplicate_consumption():
    session, crypto_engine, key_provider, service, now = _setup_idempotency_env()

    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    # First request
    post1 = service.publish(
        content="Idempotent publish test",
        credential=proof,
        idempotency_key="idemp-key-repeat-12345",
        now=now,
    )

    # Replay identical request with identical Idempotency-Key
    post2 = service.publish(
        content="Idempotent publish test",
        credential=proof,
        idempotency_key="idemp-key-repeat-12345",
        now=now,
    )

    assert post1.id == post2.id
    assert post1.content == post2.content
    assert session.query(ConsumedSN).count() == 1
    assert session.query(HolePost).count() == 1
    assert session.query(HolePostIdempotency).count() == 1


def test_same_idempotency_key_different_content_raises_conflict():
    session, crypto_engine, key_provider, service, now = _setup_idempotency_env()

    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    service.publish(
        content="Original content",
        credential=proof,
        idempotency_key="idemp-key-conflict-12345",
        now=now,
    )

    # Different content with same Idempotency-Key
    with pytest.raises(HolePostServiceError) as exc_info:
        service.publish(
            content="Modified content",
            credential=proof,
            idempotency_key="idemp-key-conflict-12345",
            now=now,
        )
    assert exc_info.value.code == "idempotency_conflict"


def test_same_idempotency_key_different_credential_raises_conflict():
    session, crypto_engine, key_provider, service, now = _setup_idempotency_env()

    sn_hex1 = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof1 = CredentialProof(
        sn=sn_hex1,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    service.publish(
        content="Same content",
        credential=proof1,
        idempotency_key="idemp-key-diff-cred-123",
        now=now,
    )

    # Different SN with same Idempotency-Key
    sn_hex2 = "aabbccddeeff00112233445566778899"
    proof2 = CredentialProof(
        sn=sn_hex2,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    with pytest.raises(HolePostServiceError) as exc_info:
        service.publish(
            content="Same content",
            credential=proof2,
            idempotency_key="idemp-key-diff-cred-123",
            now=now,
        )
    assert exc_info.value.code == "idempotency_conflict"


def test_same_sn_different_idempotency_key_or_content_rejected():
    session, crypto_engine, key_provider, service, now = _setup_idempotency_env()

    sn_hex = "1234567890abcdef1234567890abcdef"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    service.publish(
        content="Post 1",
        credential=proof,
        idempotency_key="idemp-key-first-123456",
        now=now,
    )

    # Try same SN with different Idempotency-Key
    with pytest.raises(HolePostServiceError) as exc_info:
        service.publish(
            content="Post 2 trying to reuse SN",
            credential=proof,
            idempotency_key="idemp-key-second-123456",
            now=now,
        )
    assert exc_info.value.code == "credential_consumed"
    assert session.query(ConsumedSN).count() == 1
    assert session.query(HolePost).count() == 1
