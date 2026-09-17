import base64
from collections.abc import Generator
from datetime import datetime
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import app.api.routes.chat as chat_routes
from app.api.routes.chat import (
    CHAT_SUBPROTOCOL,
    ChatConnectionManager,
    _Connection,
    router,
)
from app.crypto.dependencies import get_crypto_engine
from app.db.session import create_session_factory, get_db
from app.models.chat import ChatSession, EncryptedMessage
from app.models.user import User
from app.security.auth_dependencies import get_token_verifier
from app.services.chat import ChatServiceError


class TokenVerifier:
    def __init__(self, claims_by_token: dict[str, dict[str, object]]) -> None:
        self.claims_by_token = claims_by_token
        self.seen: list[str] = []

    def verify_access_token(self, token: str, now: datetime) -> dict[str, object]:
        del now
        self.seen.append(token)
        if token not in self.claims_by_token:
            raise ValueError("invalid")
        return self.claims_by_token[token]


class NoChatCryptoCalls:
    def __getattr__(self, name: str):
        raise AssertionError(f"chat must not call crypto operation {name}")


class RecordingWebSocket:
    def __init__(self) -> None:
        self.payloads: list[dict[str, object]] = []

    async def send_json(self, payload: dict[str, object]) -> None:
        self.payloads.append(payload)


def _auth_protocol(token: str) -> str:
    encoded = base64.urlsafe_b64encode(token.encode()).decode().rstrip("=")
    return f"auth.b64u.{encoded}"


def _seed(db_session, *, owner_status: str = "active"):
    owner = User(
        id=str(uuid4()), email=f"{uuid4()}@example.test", role="student", status=owner_status
    )
    peer = User(
        id=str(uuid4()), email=f"{uuid4()}@example.test", role="teacher", status="active"
    )
    outsider = User(
        id=str(uuid4()), email=f"{uuid4()}@example.test", role="student", status="active"
    )
    db_session.add_all((owner, peer, outsider))
    db_session.flush()
    left, right = sorted((owner.id, peer.id))
    chat = ChatSession(participant_a_id=left, participant_b_id=right, pqc_mode=False)
    db_session.add(chat)
    db_session.commit()
    return owner, peer, outsider, chat


def _app(db_engine, verifier: TokenVerifier) -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    factory = create_session_factory(db_engine)

    def database() -> Generator:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_token_verifier] = lambda: verifier
    app.dependency_overrides[get_crypto_engine] = lambda: NoChatCryptoCalls()
    return TestClient(app)


def _claims(user: User) -> dict[str, object]:
    return {"sub": user.id, "role": user.role}


def test_websocket_auth_uses_encoded_subprotocol_without_echoing_token(db_engine, db_session) -> None:
    owner, _, _, _ = _seed(db_session)
    verifier = TokenVerifier({"secret.jwt": _claims(owner)})
    client = _app(db_engine, verifier)

    with client.websocket_connect(
        "/api/v1/chat/ws",
        subprotocols=[CHAT_SUBPROTOCOL, _auth_protocol("secret.jwt")],
    ) as websocket:
        assert websocket.accepted_subprotocol == CHAT_SUBPROTOCOL

    assert verifier.seen == ["secret.jwt"]


@pytest.mark.parametrize(
    "path,subprotocols",
    [
        ("/api/v1/chat/ws", []),
        ("/api/v1/chat/ws?token=secret.jwt", [CHAT_SUBPROTOCOL, "auth.b64u.c2VjcmV0Lmp3dA"]),
        ("/api/v1/chat/ws", [CHAT_SUBPROTOCOL, "secret.jwt"]),
    ],
)
def test_websocket_rejects_missing_raw_or_query_token(
    db_engine, db_session, path, subprotocols
) -> None:
    owner, _, _, _ = _seed(db_session)
    client = _app(db_engine, TokenVerifier({"secret.jwt": _claims(owner)}))

    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect(path, subprotocols=subprotocols):
            pass
    assert error.value.code == 1008
    assert "secret.jwt" not in error.value.reason


def test_websocket_rejects_frozen_user_and_non_member_frame(db_engine, db_session) -> None:
    frozen, peer, outsider, chat = _seed(db_session, owner_status="frozen")
    verifier = TokenVerifier(
        {"frozen": _claims(frozen), "outsider": _claims(outsider), "peer": _claims(peer)}
    )
    client = _app(db_engine, verifier)

    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect(
            "/api/v1/chat/ws",
            subprotocols=[CHAT_SUBPROTOCOL, _auth_protocol("frozen")],
        ):
            pass
    assert error.value.code == 1008

    with client.websocket_connect(
        "/api/v1/chat/ws",
        subprotocols=[CHAT_SUBPROTOCOL, _auth_protocol("outsider")],
    ) as websocket:
        websocket.send_json(
            {"type": "handshake", "session_id": chat.id, "payload": "cHVibGlj"}
        )
        assert websocket.receive_json()["code"] == "FORBIDDEN"
        with pytest.raises(WebSocketDisconnect) as frame_error:
            websocket.receive_json()
        assert frame_error.value.code == 1008


@pytest.mark.anyio
async def test_connection_manager_relays_only_to_subscribed_recipient() -> None:
    manager = ChatConnectionManager()
    subscribed = RecordingWebSocket()
    unrelated = RecordingWebSocket()
    manager.connect(_Connection(subscribed, "peer", frozenset({"session-1"})))
    manager.connect(_Connection(unrelated, "peer", frozenset({"session-2"})))

    payload = {"type": "handshake", "payload": "cHVibGlj"}
    await manager.send_to(user_id="peer", session_id="session-1", payload=payload)

    assert subscribed.payloads == [payload]
    assert unrelated.payloads == []


def test_websocket_persists_before_ciphertext_acknowledgement(
    db_engine, db_session
) -> None:
    owner, _, _, chat = _seed(db_session)
    verifier = TokenVerifier({"owner": _claims(owner)})
    client = _app(db_engine, verifier)
    protocols_owner = [CHAT_SUBPROTOCOL, _auth_protocol("owner")]

    with client.websocket_connect("/api/v1/chat/ws", subprotocols=protocols_owner) as sender:
        sender.send_json(
            {
                "type": "encrypted_message",
                "session_id": chat.id,
                "sequence": 1,
                "ciphertext": "Y2lwaGVy",
                "nonce": "bm5ubm5ubm5ubm5u",
                "tag": "dHR0dHR0dHR0dHR0dHR0dA==",
                "signature": "c2ln",
            }
        )
        delivered = sender.receive_json()
        assert delivered["sender_id"] == owner.id
        assert delivered["type"] == "encrypted_message"
        assert set(delivered) == {
            "type", "id", "session_id", "sender_id", "sequence",
            "ciphertext", "nonce", "tag", "signature", "created_at",
        }

    factory = create_session_factory(db_engine)
    with factory() as session:
        stored = session.query(EncryptedMessage).one()
        assert stored.ciphertext == b"cipher"
        assert stored.sender_id == owner.id


def test_websocket_rejects_forged_fields_malformed_base64_and_duplicate_sequence(
    db_engine, db_session
) -> None:
    owner, _, _, chat = _seed(db_session)
    verifier = TokenVerifier({"owner": _claims(owner)})
    client = _app(db_engine, verifier)
    protocols = [CHAT_SUBPROTOCOL, _auth_protocol("owner")]
    good = {
        "type": "encrypted_message",
        "session_id": chat.id,
        "sequence": 1,
        "ciphertext": "YQ==",
        "nonce": "bm5ubm5ubm5ubm5u",
        "tag": "dHR0dHR0dHR0dHR0dHR0dA==",
        "signature": "cw==",
    }

    with client.websocket_connect("/api/v1/chat/ws", subprotocols=protocols) as websocket:
        websocket.send_json(good)
        websocket.receive_json()
        websocket.send_json(good)
        assert websocket.receive_json()["code"] == "DUPLICATE_SEQUENCE"
        with pytest.raises(WebSocketDisconnect) as error:
            websocket.receive_json()
        assert error.value.code == 1008

    for invalid in (
        {**good, "sequence": 2, "sender_id": owner.id},
        {**good, "sequence": 2, "ciphertext": "not-base64"},
    ):
        with client.websocket_connect("/api/v1/chat/ws", subprotocols=protocols) as websocket:
            websocket.send_json(invalid)
            assert websocket.receive_json()["code"] == "INVALID_FRAME"
            with pytest.raises(WebSocketDisconnect) as error:
                websocket.receive_json()
            assert error.value.code == 1008


@pytest.mark.parametrize("binary", [False, True])
def test_websocket_rejects_oversized_text_and_binary_frames(
    db_engine, db_session, binary: bool
) -> None:
    owner, _, _, _ = _seed(db_session)
    client = _app(db_engine, TokenVerifier({"owner": _claims(owner)}))
    protocols = [CHAT_SUBPROTOCOL, _auth_protocol("owner")]

    with client.websocket_connect("/api/v1/chat/ws", subprotocols=protocols) as websocket:
        if binary:
            websocket.send_bytes(b"binary")
        else:
            websocket.send_text("x" * 131073)
        assert websocket.receive_json()["code"] == "INVALID_FRAME"
        with pytest.raises(WebSocketDisconnect) as error:
            websocket.receive_json()
        assert error.value.code == 1008


def test_database_failure_is_not_broadcast_and_closes_1011(
    db_engine, db_session, monkeypatch
) -> None:
    owner, _, _, chat = _seed(db_session)
    client = _app(db_engine, TokenVerifier({"owner": _claims(owner)}))
    sent: list[dict[str, object]] = []

    class FailingChatService:
        def __init__(self, session, crypto_engine) -> None:
            del session, crypto_engine

        def subscribed_session_ids(self, *, user_id: str) -> frozenset[str]:
            del user_id
            return frozenset({chat.id})

        def persist_message(self, **kwargs):
            del kwargs
            raise ChatServiceError("internal_error")

    async def record_broadcast(**kwargs) -> None:
        sent.append(kwargs)

    monkeypatch.setattr(chat_routes, "ChatService", FailingChatService)
    monkeypatch.setattr(chat_routes.connection_manager, "send_to", record_broadcast)
    protocols = [CHAT_SUBPROTOCOL, _auth_protocol("owner")]
    with client.websocket_connect("/api/v1/chat/ws", subprotocols=protocols) as websocket:
        websocket.send_json(
            {
                "type": "encrypted_message",
                "session_id": chat.id,
                "sequence": 1,
                "ciphertext": "YQ==",
                "nonce": "bm5ubm5ubm5ubm5u",
                "tag": "dHR0dHR0dHR0dHR0dHR0dA==",
                "signature": "cw==",
            }
        )
        assert websocket.receive_json()["code"] == "INTERNAL_ERROR"
        with pytest.raises(WebSocketDisconnect) as error:
            websocket.receive_json()
        assert error.value.code == 1011
    assert sent == []
