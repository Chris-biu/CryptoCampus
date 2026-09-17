from datetime import datetime, timezone

from app.models.session import UserSession
from app.models.user import User
from app.services.sessions import SessionError, SessionService


class DigestEngine:
    def sm3_digest(self, message: bytes) -> bytes:
        return message[:1].ljust(32, b"x")


def test_session_list_masks_ip_and_isolates_user(db_session):
    first = User(email="one@example.edu", salt_a=b"a", auth_hash=b"h", salt_k=b"k", enc_sk=b"e", pubkey=b"p", cert_serial="one-cert")
    second = User(email="two@example.edu", salt_a=b"a", auth_hash=b"h", salt_k=b"k", enc_sk=b"e", pubkey=b"p", cert_serial="two-cert")
    db_session.add_all([first, second])
    db_session.commit()
    records = [
        UserSession(user_id=first.id, device="Chrome", ip="192.168.1.42", refresh_token_hash=b"1" * 32, expires_at=datetime(2030, 1, 2, tzinfo=timezone.utc), last_active_at=datetime(2030, 1, 1, tzinfo=timezone.utc)),
        UserSession(user_id=second.id, device="Other", ip="10.0.0.9", refresh_token_hash=b"2" * 32, expires_at=datetime(2030, 1, 2, tzinfo=timezone.utc), last_active_at=datetime(2030, 1, 1, tzinfo=timezone.utc)),
    ]
    db_session.add_all(records)
    db_session.commit()
    items = SessionService(db_session, DigestEngine()).list_for_user(first.id, records[0].id)
    assert len(items) == 1
    assert items[0].ip_masked == "192.168.1.xxx"
    assert items[0].current is True


def test_remote_revoke_cannot_touch_other_user(db_session):
    first = User(email="three@example.edu", salt_a=b"a", auth_hash=b"h", salt_k=b"k", enc_sk=b"e", pubkey=b"p", cert_serial="three-cert")
    second = User(email="four@example.edu", salt_a=b"a", auth_hash=b"h", salt_k=b"k", enc_sk=b"e", pubkey=b"p", cert_serial="four-cert")
    db_session.add_all([first, second])
    db_session.commit()
    record = UserSession(user_id=second.id, device="Other", ip="10.0.0.9", refresh_token_hash=b"3" * 32, expires_at=datetime(2030, 1, 2, tzinfo=timezone.utc), last_active_at=datetime(2030, 1, 1, tzinfo=timezone.utc))
    db_session.add(record)
    db_session.commit()
    try:
        SessionService(db_session, DigestEngine()).revoke_for_user(first.id, record.id)
    except SessionError as error:
        assert error.code == "not_found"
    else:
        raise AssertionError("cross-user revoke unexpectedly succeeded")
    assert db_session.get(UserSession, record.id).revoked is False
