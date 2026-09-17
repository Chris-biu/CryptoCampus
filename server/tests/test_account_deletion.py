from datetime import datetime, timedelta, timezone

import pytest

from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord
from app.models.credential import CredentialLedger
from app.models.notification import Notification
from app.models.session import UserSession
from app.models.user import User
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.account_lifecycle import AccountGovernanceError, AccountGovernanceService


class PasswordEngine:
    def sm3_hash_password(self, password: bytes, salt: bytes) -> bytes:
        return b"valid" if password == b"CorrectPassword1" and salt == b"a" else b"invalid"

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right

    def sm3_digest(self, value: bytes) -> bytes:
        return b"d" * 32


class RecordingCA:
    def __init__(self) -> None:
        self.revocations: list[str] = []

    def revoke_certificate(self, serial, reason, operator_user_id, this_update, next_update) -> None:
        del reason, operator_user_id, this_update, next_update
        self.revocations.append(serial)


class UnavailableCA:
    def revoke_certificate(self, *args) -> None:
        del args
        raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE)


def _user(db_session) -> User:
    user = User(
        email="delete@campus.edu",
        salt_a=b"a",
        auth_hash=b"valid",
        salt_k=b"k",
        enc_sk=b"encrypted",
        pubkey=b"public",
        cert_serial="delete-cert",
    )
    db_session.add(user)
    db_session.flush()
    db_session.add(
        CertificateRecord(
            serial="delete-cert", subject_user_id=user.id, issuer_serial="platform-ca", kind="user_identity",
            certificate_der=b"certificate", key_usage="digitalSignature", not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2027, 1, 1, tzinfo=timezone.utc), status="active",
        )
    )
    db_session.add(UserSession(user_id=user.id, device="device", ip="1.1.1.1", refresh_token_hash=b"s" * 32, expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc), last_active_at=datetime(2026, 9, 7, tzinfo=timezone.utc)))
    db_session.commit()
    return user


def test_delete_requires_correct_password_and_confirmation_without_writes(db_session) -> None:
    user = _user(db_session)
    service = AccountGovernanceService(db_session, PasswordEngine(), PrivateKeyUnlockCache(), platform_ca=RecordingCA())

    with pytest.raises(AccountGovernanceError, match="credentials_invalid"):
        service.delete_account(user.id, "wrong", "DELETE_MY_ACCOUNT", datetime(2026, 9, 7, tzinfo=timezone.utc))

    assert db_session.get(User, user.id).status == "active"
    assert db_session.query(UserSession).one().revoked is False


def test_delete_maps_unavailable_ca_to_unavailable_without_writes(db_session) -> None:
    user = _user(db_session)
    service = AccountGovernanceService(db_session, PasswordEngine(), PrivateKeyUnlockCache(), platform_ca=UnavailableCA())

    with pytest.raises(AccountGovernanceError, match="unavailable"):
        service.delete_account(user.id, "CorrectPassword1", "DELETE_MY_ACCOUNT", datetime(2026, 9, 7, tzinfo=timezone.utc))

    assert db_session.get(User, user.id).status == "active"


def test_delete_uses_pending_deletion_retains_audit_and_revokes_certificate(db_session) -> None:
    user = _user(db_session)
    cache = PrivateKeyUnlockCache()
    cache.put(user.id, b"private", datetime(2026, 9, 8, tzinfo=timezone.utc))
    ca = RecordingCA()
    service = AccountGovernanceService(db_session, PasswordEngine(), cache, platform_ca=ca)

    service.delete_account(user.id, "CorrectPassword1", "DELETE_MY_ACCOUNT", datetime(2026, 9, 7, tzinfo=timezone.utc))

    db_session.refresh(user)
    assert user.status == "pending_deletion"
    assert user.auth_hash is None and user.enc_sk is None and user.pubkey is None
    assert db_session.get(CertificateRecord, "delete-cert").subject_user_id == user.id
    assert db_session.query(UserSession).one().revoked is True
    assert ca.revocations == ["delete-cert"]
    assert cache.get(user.id, datetime(2026, 9, 7, tzinfo=timezone.utc)) is None
    assert {item.action for item in db_session.query(AuditLog).all()} >= {"user.delete.requested", "user.delete.completed"}


def test_retention_purges_only_ledger_records_after_thirty_days(db_session) -> None:
    expired_user = User(status="pending_deletion")
    recent_user = User(status="pending_deletion")
    db_session.add_all([expired_user, recent_user])
    db_session.flush()
    db_session.add_all(
        [
            AuditLog(
                actor=expired_user.id,
                action="user.delete.completed",
                target=f"user:{expired_user.id}",
                detail_hash=b"d" * 32,
                ts=datetime(2026, 8, 7, tzinfo=timezone.utc),
            ),
            AuditLog(
                actor=recent_user.id,
                action="user.delete.completed",
                target=f"user:{recent_user.id}",
                detail_hash=b"d" * 32,
                ts=datetime(2026, 8, 9, tzinfo=timezone.utc),
            ),
            CredentialLedger(user_id=expired_user.id, service="drop", period="2026-08-07", issued_count=1),
            CredentialLedger(user_id=recent_user.id, service="drop", period="2026-08-09", issued_count=1),
        ]
    )
    db_session.commit()
    service = AccountGovernanceService(db_session, PasswordEngine(), PrivateKeyUnlockCache())

    removed = service.purge_expired_credential_ledgers(datetime(2026, 9, 7, tzinfo=timezone.utc))

    assert removed == 1
    assert db_session.query(CredentialLedger).filter_by(user_id=expired_user.id).count() == 0
    assert db_session.query(CredentialLedger).filter_by(user_id=recent_user.id).count() == 1
    assert db_session.query(AuditLog).count() == 2


def test_delete_account_purges_user_notifications_without_affecting_others(db_session) -> None:
    user1 = _user(db_session)
    user2 = User(
        email="other@campus.edu",
        salt_a=b"a",
        auth_hash=b"valid",
        salt_k=b"k",
        enc_sk=b"encrypted",
        pubkey=b"public",
        cert_serial="other-cert",
    )
    db_session.add(user2)
    db_session.flush()

    notif1 = Notification(
        id=1,
        user_id=user1.id,
        type="drop_extracted",
        title="你的密信已被成功提取",
        related_resource_id="drop-1",
        source_event_id="event-uuid-001",
        read=False,
        created_at=datetime(2026, 9, 7, tzinfo=timezone.utc),
    )
    notif2 = Notification(
        id=2,
        user_id=user2.id,
        type="drop_extracted",
        title="你的密信已被成功提取",
        related_resource_id="drop-2",
        source_event_id="event-uuid-002",
        read=False,
        created_at=datetime(2026, 9, 7, tzinfo=timezone.utc),
    )
    db_session.add_all([notif1, notif2])
    db_session.commit()

    service = AccountGovernanceService(db_session, PasswordEngine(), PrivateKeyUnlockCache(), platform_ca=RecordingCA())
    service.delete_account(user1.id, "CorrectPassword1", "DELETE_MY_ACCOUNT", datetime(2026, 9, 7, tzinfo=timezone.utc))

    # user1 notifications must be purged
    assert db_session.query(Notification).filter_by(user_id=user1.id).count() == 0
    # user2 notifications must remain untouched
    assert db_session.query(Notification).filter_by(user_id=user2.id).count() == 1

