import base64
from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy.orm import sessionmaker

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.db.session import create_db_engine, init_database
from app.models.audit import AuditLog
from app.models.credential import CredentialIssueIdempotency, CredentialLedger
from app.models.user import User


class MockServerSignerKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x77" * SM2_PRIVATE_KEY_SIZE)

    def get_signer_private_key(self, service: str) -> bytes | None:
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
    from app.services.credential_issuance import CredentialIssuanceService

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


def test_issue_success_for_active_user():
    from app.services.credential_issuance import CredentialIssuanceService

    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    blinded_b64 = base64.b64encode(b"my-blinded-message").decode("ascii")
    idemp_key = "idemp-key-test-12345"

    result = service.issue(
        user_id=user.id,
        service="hole_post",
        period=today_period,
        blinded_message_b64=blinded_b64,
        idempotency_key=idemp_key,
        now=now,
    )

    assert result.blind_signature == b"\x88" * 64
    assert result.algorithm == "SM2-BLIND-PROTOCOL-V1"
    assert result.blind_signature_b64 == base64.b64encode(b"\x88" * 64).decode("ascii")

    # Verify quota reservation: issued_count == 1
    ledger = session.query(CredentialLedger).filter_by(
        user_id=user.id,
        service="hole_credential",
        period=today_period,
    ).one_or_none()
    assert ledger is not None
    assert ledger.issued_count == 1

    # Verify idempotency record
    idemp_record = session.query(CredentialIssueIdempotency).filter_by(
        user_id=user.id,
        service="hole_post",
        period=today_period,
    ).one_or_none()
    assert idemp_record is not None
    assert idemp_record.blind_signature == b"\x88" * 64

    # Verify audit log
    audit_entry = session.query(AuditLog).filter_by(
        actor=user.id,
        action="credential.issue",
    ).one_or_none()
    assert audit_entry is not None
    assert audit_entry.target == f"user:{user.id}"
    assert audit_entry.detail_hash is not None


def test_issue_rejects_inactive_frozen_pending_deletion_users():
    from app.services.credential_issuance import CredentialIssuanceError

    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    blinded_b64 = base64.b64encode(b"blinded-content").decode("ascii")
    idemp_key = "idemp-key-test-54321"

    # 1. Non-existent user
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=str(uuid.uuid4()),
            service="hole_post",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=idemp_key,
            now=now,
        )
    assert exc_info.value.code == "user_inactive"

    # 2. Frozen user
    user.status = "frozen"
    session.commit()
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=idemp_key,
            now=now,
        )
    assert exc_info.value.code == "user_inactive"

    # 3. Pending deletion user
    user.status = "pending_deletion"
    session.commit()
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=idemp_key,
            now=now,
        )
    assert exc_info.value.code == "user_inactive"

    # No quota should be consumed
    assert session.query(CredentialLedger).count() == 0


def test_issue_rejects_invalid_service_and_period():
    from app.services.credential_issuance import CredentialIssuanceError

    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()
    blinded_b64 = base64.b64encode(b"blinded-content").decode("ascii")
    idemp_key = "idemp-key-test-99999"

    # Invalid service (e.g. vote_ballot or hole_comment not handled in Issue 17)
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="vote_ballot",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=idemp_key,
            now=now,
        )
    assert exc_info.value.code == "invalid_service"

    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="unknown_service",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=idemp_key,
            now=now,
        )
    assert exc_info.value.code == "invalid_service"

    # Invalid period (future / past / malformed)
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period="2099-01-01",
            blinded_message_b64=blinded_b64,
            idempotency_key=idemp_key,
            now=now,
        )
    assert exc_info.value.code == "invalid_period"

    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period="2020-01-01",
            blinded_message_b64=blinded_b64,
            idempotency_key=idemp_key,
            now=now,
        )
    assert exc_info.value.code == "invalid_period"

    # No quota should be consumed
    assert session.query(CredentialLedger).count() == 0


def test_issue_rejects_invalid_blinded_message_and_idempotency_key():
    from app.services.credential_issuance import CredentialIssuanceError

    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    # Invalid base64
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64="!!!bad-b64!!!",
            idempotency_key="valid-idemp-key-16",
            now=now,
        )
    assert exc_info.value.code == "invalid_blinded_message"

    # Empty base64
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64="",
            idempotency_key="valid-idemp-key-16",
            now=now,
        )
    assert exc_info.value.code == "invalid_blinded_message"

    blinded_b64 = base64.b64encode(b"valid-blinded").decode("ascii")

    # Idempotency key too short (< 16)
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key="short",
            now=now,
        )
    assert exc_info.value.code == "invalid_idempotency_key"

    # Idempotency key too long (> 128)
    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key="x" * 129,
            now=now,
        )
    assert exc_info.value.code == "invalid_idempotency_key"

    assert session.query(CredentialLedger).count() == 0


def test_issue_quota_exhaustion_after_5_issuances():
    from app.services.credential_issuance import CredentialIssuanceError

    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    # Issue 5 times successfully
    for i in range(1, 6):
        blinded_b64 = base64.b64encode(f"msg-{i}".encode("utf-8")).decode("ascii")
        idemp_key = f"idemp-key-run-{i}-12345"
        res = service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=idemp_key,
            now=now,
        )
        assert res.algorithm == "SM2-BLIND-PROTOCOL-V1"

    # Check ledger issued_count is 5
    ledger = session.query(CredentialLedger).filter_by(
        user_id=user.id,
        service="hole_credential",
        period=today_period,
    ).one()
    assert ledger.issued_count == 5

    # 6th attempt must be rejected
    blinded_b64_6 = base64.b64encode(b"msg-6").decode("ascii")
    idemp_key_6 = "idemp-key-run-6-12345"
    blind_sign_call_count = len([call for call in crypto_engine.calls if call[0] == "blind_sign"])
    assert blind_sign_call_count == 5

    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64=blinded_b64_6,
            idempotency_key=idemp_key_6,
            now=now,
        )
    assert exc_info.value.code == "quota_exhausted"

    # Engine must NOT be called for 6th attempt
    new_call_count = len([call for call in crypto_engine.calls if call[0] == "blind_sign"])
    assert new_call_count == 5


def test_issue_engine_failure_rolls_back_quota_and_audit():
    from app.services.credential_issuance import CredentialIssuanceError

    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    # Set engine to fail
    crypto_engine.set_error("blind_sign", CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))

    blinded_b64 = base64.b64encode(b"msg-fail").decode("ascii")
    idemp_key = "idemp-key-fail-12345"

    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=idemp_key,
            now=now,
        )
    assert exc_info.value.code == "engine_unavailable"

    # Verify complete rollback: no quota consumed, no idempotency record, no audit log
    ledger = session.query(CredentialLedger).filter_by(
        user_id=user.id,
        service="hole_credential",
        period=today_period,
    ).one_or_none()
    assert ledger is None

    assert session.query(CredentialIssueIdempotency).count() == 0
    assert session.query(AuditLog).count() == 0


def test_issue_missing_signer_private_key_fails_safely_and_rolls_back():
    from app.services.credential_issuance import CredentialIssuanceError

    session, crypto_engine, signer_key_provider, service, user, now, today_period = _setup_issuance_env()

    # Signer key is unavailable
    signer_key_provider.key = None

    blinded_b64 = base64.b64encode(b"msg-no-key").decode("ascii")
    idemp_key = "idemp-key-no-key-123"

    with pytest.raises(CredentialIssuanceError) as exc_info:
        service.issue(
            user_id=user.id,
            service="hole_post",
            period=today_period,
            blinded_message_b64=blinded_b64,
            idempotency_key=idemp_key,
            now=now,
        )
    assert exc_info.value.code == "engine_unavailable"

    # Verify complete rollback
    assert session.query(CredentialLedger).count() == 0
    assert session.query(CredentialIssueIdempotency).count() == 0
    assert session.query(AuditLog).count() == 0
