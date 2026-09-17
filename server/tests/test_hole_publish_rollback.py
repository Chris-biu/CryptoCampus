import base64
from datetime import datetime, timezone
from unittest.mock import patch
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE, SM2_SIGNATURE_SIZE
from app.db.base import Base
from app.models.credential import ConsumedSN
from app.models.hole import HolePost, HolePostIdempotency
from app.schemas.credential import CredentialProof
from app.services.hole_posts import HolePostService


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


def _setup_rollback_env():
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


def test_rollback_on_flush_failure():
    session, crypto_engine, key_provider, service, now = _setup_rollback_env()

    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    # Force flush to fail
    with patch.object(session, "flush", side_effect=OperationalError("mock flush error", {}, None)):
        with pytest.raises(OperationalError):
            service.publish(
                content="Post during failing flush",
                credential=proof,
                idempotency_key="idemp-key-1234567890",
                now=now,
            )

    # Check nothing remains in DB
    assert session.query(ConsumedSN).count() == 0
    assert session.query(HolePost).count() == 0
    assert session.query(HolePostIdempotency).count() == 0

    # The same SN can be published again without conflict
    post = service.publish(
        content="Retry post after failure",
        credential=proof,
        idempotency_key="idemp-key-1234567890",
        now=now,
    )
    assert post.id is not None
    assert session.query(ConsumedSN).count() == 1
    assert session.query(HolePost).count() == 1


def test_rollback_on_commit_failure():
    session, crypto_engine, key_provider, service, now = _setup_rollback_env()

    sn_hex = "112233445566778899aabbccddeeff00"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    # Force commit to fail via SQLAlchemy before_commit event
    @event.listens_for(session, "before_commit", once=True)
    def fail_commit(s):
        raise OperationalError("mock commit error", {}, None)

    with pytest.raises(OperationalError):
        service.publish(
            content="Post during failing commit",
            credential=proof,
            idempotency_key="idemp-key-1234567890",
            now=now,
        )

    # Check nothing remains in DB
    assert session.query(ConsumedSN).count() == 0
    assert session.query(HolePost).count() == 0
    assert session.query(HolePostIdempotency).count() == 0


def test_rollback_on_post_insertion_failure():
    session, crypto_engine, key_provider, service, now = _setup_rollback_env()

    sn_hex = "2233445566778899aabbccddeeff0011"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    orig_add = session.add

    def failing_add(instance, *args, **kwargs):
        if isinstance(instance, HolePost):
            raise OperationalError("mock hole post insert failure", {}, None)
        return orig_add(instance, *args, **kwargs)

    with patch.object(session, "add", side_effect=failing_add):
        with pytest.raises(OperationalError):
            service.publish(
                content="Post during hole post add failure",
                credential=proof,
                idempotency_key="idemp-key-1234567890",
                now=now,
            )

    assert session.query(ConsumedSN).count() == 0
    assert session.query(HolePost).count() == 0
    assert session.query(HolePostIdempotency).count() == 0


def test_rollback_on_idempotency_insertion_failure():
    session, crypto_engine, key_provider, service, now = _setup_rollback_env()

    sn_hex = "33445566778899aabbccddeeff001122"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    orig_add = session.add

    def failing_add(instance, *args, **kwargs):
        if isinstance(instance, HolePostIdempotency):
            raise OperationalError("mock idempotency add failure", {}, None)
        return orig_add(instance, *args, **kwargs)

    with patch.object(session, "add", side_effect=failing_add):
        with pytest.raises(OperationalError):
            service.publish(
                content="Post during idempotency add failure",
                credential=proof,
                idempotency_key="idemp-key-1234567890",
                now=now,
            )

    assert session.query(ConsumedSN).count() == 0
    assert session.query(HolePost).count() == 0
    assert session.query(HolePostIdempotency).count() == 0
