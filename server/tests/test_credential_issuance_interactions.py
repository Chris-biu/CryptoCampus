import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
import uuid
import pytest
from sqlalchemy.orm import sessionmaker

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.db.session import create_db_engine, create_session_factory, init_database
from app.models.audit import AuditLog
from app.models.credential import CredentialIssueIdempotency, CredentialLedger
from app.models.user import User
from app.services.credential_issuance import (
    CredentialIssuanceError,
    CredentialIssuanceService,
)


class MockServerSignerKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x77" * SM2_PRIVATE_KEY_SIZE)
        self.requested_services: list[str] = []

    def get_signer_private_key(self, service: str) -> bytes | None:
        self.requested_services.append(service)
        return self.key


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


def _setup_issuance_env():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    crypto_engine = DynamicMockCryptoEngine()
    crypto_engine.set_result("blind_sign", b"\x88" * 64)

    signer_key_provider = MockServerSignerKeyProvider()
    service = CredentialIssuanceService(
        session=session,
        crypto_engine=crypto_engine,
        signer_key_provider=signer_key_provider,
    )

    now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    today_period = "2026-09-09"

    user = User(
        id=str(uuid.uuid4()),
        email="test_student@campus.edu.cn",
        role="student",
        status="active",
    )
    session.add(user)
    session.commit()

    return session, crypto_engine, signer_key_provider, service, user, now, today_period


def test_issue_hole_comment_and_hole_like_success():
    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    blinded_b64 = base64.b64encode(b"my-blinded-comment").decode("ascii")
    res_comment = service.issue(
        user_id=user.id,
        service="hole_comment",
        period=today_period,
        blinded_message_b64=blinded_b64,
        idempotency_key="idemp-key-comment-001",
        now=now,
    )
    assert res_comment.blind_signature == b"\x88" * 64
    assert res_comment.algorithm == "SM2-BLIND-PROTOCOL-V1"
    assert "hole_comment" in signer_key_provider.requested_services

    blinded_like_b64 = base64.b64encode(b"my-blinded-like").decode("ascii")
    res_like = service.issue(
        user_id=user.id,
        service="hole_like",
        period=today_period,
        blinded_message_b64=blinded_like_b64,
        idempotency_key="idemp-key-like-001",
        now=now,
    )
    assert res_like.blind_signature == b"\x88" * 64
    assert "hole_like" in signer_key_provider.requested_services

    # Quota ledger must show interaction_credential with issued_count = 2
    ledger = (
        session.query(CredentialLedger)
        .filter_by(user_id=user.id, service="interaction_credential", period=today_period)
        .first()
    )
    assert ledger is not None
    assert ledger.issued_count == 2


def test_shared_quota_exhaustion_12_comments_plus_8_likes():
    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    # Issue 12 comments
    for i in range(12):
        blinded_b64 = base64.b64encode(f"comment-{i}".encode("utf-8")).decode("ascii")
        service.issue(
            user_id=user.id,
            service="hole_comment",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=f"idemp-key-c-{i:04d}-xxxx",
            now=now,
        )

    # Issue 8 likes
    for i in range(8):
        blinded_b64 = base64.b64encode(f"like-{i}".encode("utf-8")).decode("ascii")
        service.issue(
            user_id=user.id,
            service="hole_like",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=f"idemp-key-l-{i:04d}-xxxx",
            now=now,
        )

    # Total 20 issued. 21st must fail for both hole_comment and hole_like
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_comment",
            period=today_period,
            blinded_message_b64=base64.b64encode(b"extra-comment").decode("ascii"),
            idempotency_key="idemp-key-extra-comment",
            now=now,
        )
    assert exc_info.value.code == "quota_exhausted"

    with pytest.raises(CredentialIssuanceError) as exc_info2:
        service.issue(
            user_id=user.id,
            service="hole_like",
            period=today_period,
            blinded_message_b64=base64.b64encode(b"extra-like").decode("ascii"),
            idempotency_key="idemp-key-extra-like",
            now=now,
        )
    assert exc_info2.value.code == "quota_exhausted"


def test_shared_quota_exhaustion_7_likes_plus_13_comments():
    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    for i in range(7):
        blinded_b64 = base64.b64encode(f"like-{i}".encode("utf-8")).decode("ascii")
        service.issue(
            user_id=user.id,
            service="hole_like",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=f"idemp-key-l7-{i:04d}-xx",
            now=now,
        )

    for i in range(13):
        blinded_b64 = base64.b64encode(f"comment-{i}".encode("utf-8")).decode("ascii")
        service.issue(
            user_id=user.id,
            service="hole_comment",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=f"idemp-key-c13-{i:04d}-x",
            now=now,
        )

    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_comment",
            period=today_period,
            blinded_message_b64=base64.b64encode(b"comment-21").decode("ascii"),
            idempotency_key="idemp-key-c-21-xxxx",
            now=now,
        )
    assert exc_info.value.code == "quota_exhausted"


def test_idempotent_replay_does_not_increment_shared_quota():
    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    blinded_b64 = base64.b64encode(b"replay-comment").decode("ascii")
    key = "idemp-key-replay-12345"

    res1 = service.issue(
        user_id=user.id,
        service="hole_comment",
        period=today_period,
        blinded_message_b64=blinded_b64,
        idempotency_key=key,
        now=now,
    )

    res2 = service.issue(
        user_id=user.id,
        service="hole_comment",
        period=today_period,
        blinded_message_b64=blinded_b64,
        idempotency_key=key,
        now=now,
    )
    assert res1.blind_signature == res2.blind_signature

    ledger = (
        session.query(CredentialLedger)
        .filter_by(user_id=user.id, service="interaction_credential", period=today_period)
        .first()
    )
    assert ledger.issued_count == 1


def test_idempotent_conflict_does_not_increment_quota():
    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    key = "idemp-key-conflict-1234"
    service.issue(
        user_id=user.id,
        service="hole_comment",
        period=today_period,
        blinded_message_b64=base64.b64encode(b"content-a").decode("ascii"),
        idempotency_key=key,
        now=now,
    )

    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_comment",
            period=today_period,
            blinded_message_b64=base64.b64encode(b"content-b").decode("ascii"),
            idempotency_key=key,
            now=now,
        )
    assert exc_info.value.code == "idempotency_conflict"

    ledger = (
        session.query(CredentialLedger)
        .filter_by(user_id=user.id, service="interaction_credential", period=today_period)
        .first()
    )
    assert ledger.issued_count == 1


def test_hole_post_quota_remains_independent_of_interaction():
    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    # Exhaust interaction quota (20)
    for i in range(20):
        service.issue(
            user_id=user.id,
            service="hole_comment",
            period=today_period,
            blinded_message_b64=base64.b64encode(f"c-{i}".encode("utf-8")).decode("ascii"),
            idempotency_key=f"idemp-key-c20-{i:04d}-x",
            now=now,
        )

    # hole_post quota is still available (5)
    for i in range(5):
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64=base64.b64encode(f"p-{i}".encode("utf-8")).decode("ascii"),
            idempotency_key=f"idemp-key-p5-{i:04d}-xx",
            now=now,
        )

    # 6th hole_post fails
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64=base64.b64encode(b"extra-p").decode("ascii"),
            idempotency_key="idemp-key-p-extra",
            now=now,
        )
    assert exc_info.value.code == "quota_exhausted"


def test_vote_ballot_remains_rejected():
    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="vote_ballot",
            period=today_period,
            blinded_message_b64=base64.b64encode(b"ballot").decode("ascii"),
            idempotency_key="idemp-key-vote-1234",
            now=now,
        )
    assert exc_info.value.code == "invalid_service"


def test_quota_resets_on_next_utc_day():
    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    # Exhaust today
    for i in range(20):
        service.issue(
            user_id=user.id,
            service="hole_comment",
            period=today_period,
            blinded_message_b64=base64.b64encode(f"c-{i}".encode("utf-8")).decode("ascii"),
            idempotency_key=f"idemp-key-c-{i:04d}-xxxx",
            now=now,
        )

    # Next day
    tomorrow = now + timedelta(days=1)
    tomorrow_period = tomorrow.date().isoformat()

    res = service.issue(
        user_id=user.id,
        service="hole_like",
        period=tomorrow_period,
        blinded_message_b64=base64.b64encode(b"tomorrow-like").decode("ascii"),
        idempotency_key="idemp-key-tomorrow-like",
        now=tomorrow,
    )
    assert res.blind_signature == b"\x88" * 64


def test_failure_rolls_back_quota_and_audit():
    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    crypto_engine.set_error("blind_sign", CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))

    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_comment",
            period=today_period,
            blinded_message_b64=base64.b64encode(b"test").decode("ascii"),
            idempotency_key="idemp-key-fail-1234",
            now=now,
        )
    assert exc_info.value.code == "engine_unavailable"

    ledger = (
        session.query(CredentialLedger)
        .filter_by(user_id=user.id, service="interaction_credential", period=today_period)
        .first()
    )
    assert ledger is None

    audit = session.query(AuditLog).filter_by(actor=user.id, action="credential.issue").first()
    assert audit is None
