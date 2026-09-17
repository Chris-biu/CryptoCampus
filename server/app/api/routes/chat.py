import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re

from fastapi import APIRouter, Depends, Header, Query, WebSocket, status
from pydantic import ValidationError
from sqlalchemy.orm import Session
from starlette.websockets import WebSocketDisconnect

from app.core.errors import ApiError
from app.crypto.dependencies import get_crypto_engine
from app.crypto.engine import CryptoEngine
from app.db.session import get_db
from app.schemas.chat import (
    ChatEncryptedMessageInput,
    ChatErrorFrame,
    ChatHandshakeInput,
    ChatSessionList,
    ChatSessionOut,
    CreateChatSessionRequest,
    EncryptedMessagePage,
)
from app.security.auth_dependencies import (
    CurrentUser,
    authenticate_access_token,
    get_token_verifier,
    require_roles,
)
from app.security.tokens import TokenVerifier
from app.services.chat import ChatService, ChatServiceError


CHAT_SUBPROTOCOL = "cryptocampus.chat.v1"
AUTH_SUBPROTOCOL_PREFIX = "auth.b64u."
MAX_WEBSOCKET_FRAME_BYTES = 131072

router = APIRouter(prefix="/chat", tags=["Chat"])


@dataclass
class _Connection:
    websocket: WebSocket
    user_id: str
    session_ids: frozenset[str]


class ChatConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, list[_Connection]] = {}

    def connect(self, connection: _Connection) -> None:
        self._connections.setdefault(connection.user_id, []).append(connection)

    def disconnect(self, connection: _Connection) -> None:
        connections = self._connections.get(connection.user_id, [])
        if connection in connections:
            connections.remove(connection)
        if not connections:
            self._connections.pop(connection.user_id, None)

    async def send_to(
        self, *, user_id: str, session_id: str, payload: dict[str, object]
    ) -> None:
        for connection in tuple(self._connections.get(user_id, ())):
            if session_id not in connection.session_ids:
                continue
            try:
                await connection.websocket.send_json(payload)
            except (RuntimeError, WebSocketDisconnect):
                self.disconnect(connection)


connection_manager = ChatConnectionManager()


def _decode_token_subprotocol(subprotocols: list[str]) -> str:
    if len(subprotocols) != 2 or subprotocols[0] != CHAT_SUBPROTOCOL:
        raise ValueError("invalid websocket subprotocols")
    auth_protocol = subprotocols[1]
    if not auth_protocol.startswith(AUTH_SUBPROTOCOL_PREFIX):
        raise ValueError("invalid websocket auth subprotocol")
    encoded = auth_protocol[len(AUTH_SUBPROTOCOL_PREFIX) :]
    if not encoded or len(encoded) > 10923 or re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None:
        raise ValueError("invalid websocket auth encoding")
    try:
        token_bytes = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        token = token_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as error:
        raise ValueError("invalid websocket auth encoding") from error
    if not 1 <= len(token_bytes) <= 8192:
        raise ValueError("invalid websocket token size")
    canonical = base64.urlsafe_b64encode(token_bytes).decode("ascii").rstrip("=")
    if canonical != encoded:
        raise ValueError("non-canonical websocket auth encoding")
    return token


async def _policy_close(
    websocket: WebSocket, *, code: str, message: str = "WebSocket 帧不合法"
) -> None:
    await websocket.send_json(ChatErrorFrame(code=code, message=message).model_dump())
    await websocket.close(code=1008, reason="policy violation")


def get_chat_service(
    session: Session = Depends(get_db),
    crypto_engine: CryptoEngine = Depends(get_crypto_engine),
) -> ChatService:
    return ChatService(session, crypto_engine)


def _map_error(error: ChatServiceError) -> ApiError:
    if error.code == "self_chat":
        return ApiError(400, "INVALID_PEER", "不能与自己创建聊天会话")
    if error.code == "peer_not_found":
        return ApiError(404, "NOT_FOUND", "对端用户不存在或不可用")
    if error.code in {"certificate_unavailable", "pqc_material_unavailable"}:
        return ApiError(503, "KEY_MATERIAL_UNAVAILABLE", "对端密钥材料暂不可用")
    if error.code == "idempotency_conflict":
        return ApiError(409, "CONFLICT", "同一幂等键已用于不同请求")
    if error.code in {"invalid_idempotency_key", "invalid_pagination"}:
        return ApiError(422, "VALIDATION_ERROR", "请求参数校验失败")
    if error.code == "forbidden":
        return ApiError(403, "FORBIDDEN", "无权访问该聊天会话")
    if error.code == "unauthorized":
        return ApiError(401, "UNAUTHORIZED", "未授权")
    return ApiError(500, "INTERNAL_ERROR", "聊天服务内部错误")


@router.get(
    "/sessions",
    response_model=ChatSessionList,
    status_code=status.HTTP_200_OK,
    operation_id="listChatSessions",
)
def list_chat_sessions(
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: ChatService = Depends(get_chat_service),
) -> ChatSessionList:
    try:
        return ChatSessionList(items=service.list_sessions(user_id=current_user.user_id))
    except ChatServiceError as error:
        raise _map_error(error) from error


@router.post(
    "/sessions",
    response_model=ChatSessionOut,
    status_code=status.HTTP_201_CREATED,
    operation_id="createChatSession",
)
def create_chat_session(
    request: CreateChatSessionRequest,
    idempotency_key: str = Header(
        ..., alias="Idempotency-Key", min_length=16, max_length=128
    ),
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: ChatService = Depends(get_chat_service),
) -> ChatSessionOut:
    try:
        return service.create_session(
            owner_user_id=current_user.user_id,
            request=request,
            idempotency_key=idempotency_key,
            now=datetime.now(timezone.utc),
        )
    except ChatServiceError as error:
        raise _map_error(error) from error


@router.get(
    "/sessions/{chat_session_id}/messages",
    response_model=EncryptedMessagePage,
    status_code=status.HTTP_200_OK,
    operation_id="listEncryptedMessages",
)
def list_encrypted_messages(
    chat_session_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: ChatService = Depends(get_chat_service),
) -> EncryptedMessagePage:
    try:
        return service.list_messages(
            user_id=current_user.user_id,
            session_id=chat_session_id,
            page=page,
            page_size=page_size,
        )
    except ChatServiceError as error:
        raise _map_error(error) from error


@router.websocket("/ws")
async def chat_websocket(
    websocket: WebSocket,
    session: Session = Depends(get_db),
    verifier: TokenVerifier = Depends(get_token_verifier),
    crypto_engine: CryptoEngine = Depends(get_crypto_engine),
) -> None:
    query_names = {name.lower() for name in websocket.query_params.keys()}
    if query_names.intersection({"token", "access_token", "jwt"}):
        await websocket.close(code=1008, reason="policy violation")
        return
    try:
        token = _decode_token_subprotocol(list(websocket.scope.get("subprotocols", [])))
        current_user = authenticate_access_token(token, verifier, session)
        service = ChatService(session, crypto_engine)
        subscriptions = service.subscribed_session_ids(user_id=current_user.user_id)
    except Exception:
        await websocket.close(code=1008, reason="policy violation")
        return

    await websocket.accept(subprotocol=CHAT_SUBPROTOCOL)
    connection = _Connection(
        websocket=websocket,
        user_id=current_user.user_id,
        session_ids=subscriptions,
    )
    connection_manager.connect(connection)
    try:
        while True:
            event = await websocket.receive()
            if event["type"] == "websocket.disconnect":
                break
            text = event.get("text")
            if text is None or len(text.encode("utf-8")) > MAX_WEBSOCKET_FRAME_BYTES:
                await _policy_close(websocket, code="INVALID_FRAME")
                return
            try:
                raw = json.loads(text)
                if not isinstance(raw, dict):
                    raise ValueError("frame must be an object")
                frame_type = raw.get("type")
                if frame_type == "handshake":
                    frame = ChatHandshakeInput.model_validate(raw)
                    recipient_id, relay = service.relay_handshake(
                        sender_id=current_user.user_id, frame=frame
                    )
                    await connection_manager.send_to(
                        user_id=recipient_id,
                        session_id=frame.session_id,
                        payload=relay.model_dump(),
                    )
                elif frame_type == "encrypted_message":
                    frame = ChatEncryptedMessageInput.model_validate(raw)
                    persisted = service.persist_message(
                        sender_id=current_user.user_id,
                        frame=frame,
                        now=datetime.now(timezone.utc),
                    )
                    recipient_id = service.recipient_for(
                        session_id=frame.session_id, sender_id=current_user.user_id
                    )
                    payload = persisted.model_dump(mode="json")
                    await connection_manager.send_to(
                        user_id=current_user.user_id,
                        session_id=frame.session_id,
                        payload=payload,
                    )
                    await connection_manager.send_to(
                        user_id=recipient_id,
                        session_id=frame.session_id,
                        payload=payload,
                    )
                else:
                    raise ValueError("unknown frame type")
            except (json.JSONDecodeError, UnicodeError, ValueError, ValidationError):
                await _policy_close(websocket, code="INVALID_FRAME")
                return
            except ChatServiceError as error:
                if error.code == "duplicate_sequence":
                    await _policy_close(
                        websocket,
                        code="DUPLICATE_SEQUENCE",
                        message="消息序号重复",
                    )
                elif error.code == "forbidden":
                    await _policy_close(
                        websocket,
                        code="FORBIDDEN",
                        message="无权访问该聊天会话",
                    )
                else:
                    await websocket.send_json(
                        ChatErrorFrame(
                            code="INTERNAL_ERROR", message="聊天服务内部错误"
                        ).model_dump()
                    )
                    await websocket.close(code=1011, reason="internal error")
                return
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.send_json(
                ChatErrorFrame(
                    code="INTERNAL_ERROR", message="聊天服务内部错误"
                ).model_dump()
            )
            await websocket.close(code=1011, reason="internal error")
        except (RuntimeError, WebSocketDisconnect):
            pass
    finally:
        connection_manager.disconnect(connection)
