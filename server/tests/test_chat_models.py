from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError

from app.models.chat import ChatSession, ChatSessionIdempotency, EncryptedMessage
from app.models.user import User


def _user() -> User:
    return User(id=str(uuid4()), email=f"{uuid4()}@example.test", role="student", status="active")


def test_chat_models_exclude_plaintext_and_session_secrets() -> None:
    forbidden = {
        "plaintext",
        "message_plaintext",
        "private_key",
        "shared_secret",
        "session_key",
        "ephemeral_private_key",
        "decrypted_status",
        "jwt",
    }

    for model in (ChatSession, ChatSessionIdempotency, EncryptedMessage):
        assert forbidden.isdisjoint(model.__table__.columns.keys())


def test_chat_session_requires_ordered_unique_pair_per_mode(db_session) -> None:
    left, right = sorted((_user(), _user()), key=lambda item: item.id)
    db_session.add_all((left, right))
    db_session.flush()
    db_session.add(
        ChatSession(participant_a_id=left.id, participant_b_id=right.id, pqc_mode=False)
    )
    db_session.commit()

    db_session.add(
        ChatSession(participant_a_id=left.id, participant_b_id=right.id, pqc_mode=False)
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    db_session.add(
        ChatSession(participant_a_id=right.id, participant_b_id=left.id, pqc_mode=True)
    )
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_message_sequence_is_unique_per_sender_and_session(db_session) -> None:
    left, right = sorted((_user(), _user()), key=lambda item: item.id)
    db_session.add_all((left, right))
    db_session.flush()
    chat = ChatSession(participant_a_id=left.id, participant_b_id=right.id, pqc_mode=False)
    db_session.add(chat)
    db_session.flush()
    values = dict(
        session_id=chat.id,
        sender_id=left.id,
        sequence=1,
        ciphertext=b"ciphertext",
        nonce=b"n" * 12,
        tag=b"t" * 16,
        signature=b"signature",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(EncryptedMessage(**values))
    db_session.commit()
    db_session.add(EncryptedMessage(**values))

    with pytest.raises(IntegrityError):
        db_session.commit()
