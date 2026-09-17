import pytest
from pydantic import ValidationError

from app.schemas.chat import ChatEncryptedMessageInput, CreateChatSessionRequest


def test_chat_frames_reject_coerced_sequence_types() -> None:
    with pytest.raises(ValidationError):
        ChatEncryptedMessageInput(
            session_id="11111111-1111-1111-1111-111111111111",
            sequence="1",
            ciphertext="YQ==",
            nonce="bm5ubm5ubm5ubm5u",
            tag="dHR0dHR0dHR0dHR0dHR0dA==",
            signature="cw==",
        )


def test_create_session_rejects_coerced_pqc_mode() -> None:
    with pytest.raises(ValidationError):
        CreateChatSessionRequest(
            peer_user_id="11111111-1111-1111-1111-111111111111",
            pqc_mode="false",
        )
