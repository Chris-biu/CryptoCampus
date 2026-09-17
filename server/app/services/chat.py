import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from threading import Lock
from typing import Iterator

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.types import MLKEM_PUBLIC_KEY_SIZE
from app.models.certificate import CertificateRecord
from app.models.chat import ChatSession, ChatSessionIdempotency, EncryptedMessage
from app.models.user import User
from app.schemas.chat import (
    ChatEncryptedMessageInput,
    ChatHandshakeInput,
    ChatHandshakeRelay,
    ChatSessionOut,
    CreateChatSessionRequest,
    EncryptedMessageOut,
    EncryptedMessagePage,
    PeerKeyBundle,
    decode_base64,
)


class ChatServiceError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_CHAT_SESSION_CREATE_LOCK = Lock()


class ChatService:
    def __init__(self, session: Session, crypto_engine: CryptoEngine) -> None:
        self.session = session
        self.crypto_engine = crypto_engine

    def create_session(
        self,
        *,
        owner_user_id: str,
        request: CreateChatSessionRequest,
        idempotency_key: str,
        now: datetime,
    ) -> ChatSessionOut:
        with _CHAT_SESSION_CREATE_LOCK:
            return self._create_session_locked(
                owner_user_id=owner_user_id,
                request=request,
                idempotency_key=idempotency_key,
                now=now,
            )

    def _create_session_locked(
        self,
        *,
        owner_user_id: str,
        request: CreateChatSessionRequest,
        idempotency_key: str,
        now: datetime,
    ) -> ChatSessionOut:
        now_utc = self._utc(now)
        if not isinstance(idempotency_key, str) or not 16 <= len(idempotency_key) <= 128:
            raise ChatServiceError("invalid_idempotency_key")
        owner = self._active_user(owner_user_id)
        if owner is None:
            raise ChatServiceError("unauthorized")
        if owner.id == request.peer_user_id:
            raise ChatServiceError("self_chat")

        key_hash = self.crypto_engine.sm3_digest(idempotency_key.encode("utf-8"))
        request_hash = self.crypto_engine.sm3_digest(
            json.dumps(
                {"peer_user_id": request.peer_user_id, "pqc_mode": request.pqc_mode},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        existing_key = (
            self.session.query(ChatSessionIdempotency)
            .filter_by(owner_user_id=owner_user_id, key_hash=key_hash)
            .one_or_none()
        )
        if existing_key is not None:
            if not self.crypto_engine.constant_time_equal(
                existing_key.request_hash, request_hash
            ):
                raise ChatServiceError("idempotency_conflict")
            chat = self.session.get(ChatSession, existing_key.chat_session_id)
            if chat is None:
                raise ChatServiceError("internal_error")
            return self._session_out(chat, owner_user_id, now_utc)

        peer = self._active_user(request.peer_user_id)
        if peer is None:
            raise ChatServiceError("peer_not_found")
        self._key_bundle(peer, request.pqc_mode, now_utc)
        participant_a_id, participant_b_id = sorted((owner_user_id, peer.id))

        try:
            with self._transaction():
                chat = (
                    self.session.query(ChatSession)
                    .filter_by(
                        participant_a_id=participant_a_id,
                        participant_b_id=participant_b_id,
                        pqc_mode=request.pqc_mode,
                    )
                    .one_or_none()
                )
                if chat is None:
                    chat = ChatSession(
                        participant_a_id=participant_a_id,
                        participant_b_id=participant_b_id,
                        pqc_mode=request.pqc_mode,
                        created_at=now_utc,
                    )
                    self.session.add(chat)
                    self.session.flush()
                self.session.add(
                    ChatSessionIdempotency(
                        owner_user_id=owner_user_id,
                        key_hash=key_hash,
                        request_hash=request_hash,
                        chat_session_id=chat.id,
                        created_at=now_utc,
                    )
                )
                self.session.flush()
            self.session.commit()
        except IntegrityError as error:
            self.session.rollback()
            replay = (
                self.session.query(ChatSessionIdempotency)
                .filter_by(owner_user_id=owner_user_id, key_hash=key_hash)
                .one_or_none()
            )
            if replay is None or not self.crypto_engine.constant_time_equal(
                replay.request_hash, request_hash
            ):
                raise ChatServiceError("idempotency_conflict") from error
            chat = self.session.get(ChatSession, replay.chat_session_id)
            if chat is None:
                raise ChatServiceError("internal_error") from error
        return self._session_out(chat, owner_user_id, now_utc)

    def list_sessions(self, *, user_id: str) -> list[ChatSessionOut]:
        records = (
            self.session.query(ChatSession)
            .filter(
                or_(
                    ChatSession.participant_a_id == user_id,
                    ChatSession.participant_b_id == user_id,
                )
            )
            .order_by(ChatSession.created_at.asc(), ChatSession.id.asc())
            .all()
        )
        now = datetime.now(timezone.utc)
        return [self._session_out(record, user_id, now) for record in records]

    def list_messages(
        self, *, user_id: str, session_id: str, page: int, page_size: int
    ) -> EncryptedMessagePage:
        chat = self.session.get(ChatSession, session_id)
        self._require_member(chat, user_id)
        if page < 1 or not 1 <= page_size <= 100:
            raise ChatServiceError("invalid_pagination")
        query = (
            self.session.query(EncryptedMessage)
            .filter_by(session_id=session_id)
            .order_by(EncryptedMessage.created_at.asc(), EncryptedMessage.id.asc())
        )
        total = query.count()
        records = query.offset((page - 1) * page_size).limit(page_size).all()
        return EncryptedMessagePage(
            items=[self._message_out(record) for record in records],
            page=page,
            page_size=page_size,
            total=total,
        )

    def subscribed_session_ids(self, *, user_id: str) -> frozenset[str]:
        records = (
            self.session.query(ChatSession.id)
            .filter(
                or_(
                    ChatSession.participant_a_id == user_id,
                    ChatSession.participant_b_id == user_id,
                )
            )
            .all()
        )
        return frozenset(session_id for (session_id,) in records)

    def relay_handshake(
        self, *, sender_id: str, frame: ChatHandshakeInput
    ) -> tuple[str, ChatHandshakeRelay]:
        chat = self.session.get(ChatSession, frame.session_id)
        self._require_member(chat, sender_id)
        return self._peer_id(chat, sender_id), ChatHandshakeRelay(
            session_id=frame.session_id, sender_id=sender_id, payload=frame.payload
        )

    def persist_message(
        self,
        *,
        sender_id: str,
        frame: ChatEncryptedMessageInput,
        now: datetime,
    ) -> EncryptedMessageOut:
        chat = self.session.get(ChatSession, frame.session_id)
        self._require_member(chat, sender_id)
        record = EncryptedMessage(
            session_id=frame.session_id,
            sender_id=sender_id,
            sequence=frame.sequence,
            ciphertext=decode_base64(frame.ciphertext, minimum=1, maximum=65536, field="ciphertext"),
            nonce=decode_base64(frame.nonce, minimum=12, maximum=12, field="nonce"),
            tag=decode_base64(frame.tag, minimum=16, maximum=16, field="tag"),
            signature=decode_base64(frame.signature, minimum=1, maximum=4096, field="signature"),
            created_at=self._utc(now),
        )
        try:
            self.session.add(record)
            self.session.commit()
        except IntegrityError as error:
            self.session.rollback()
            duplicate = (
                self.session.query(EncryptedMessage)
                .filter_by(
                    session_id=frame.session_id,
                    sender_id=sender_id,
                    sequence=frame.sequence,
                )
                .one_or_none()
            )
            if duplicate is not None:
                raise ChatServiceError("duplicate_sequence") from error
            raise ChatServiceError("internal_error") from error
        return self._message_out(record)

    def recipient_for(self, *, session_id: str, sender_id: str) -> str:
        chat = self.session.get(ChatSession, session_id)
        self._require_member(chat, sender_id)
        return self._peer_id(chat, sender_id)

    def _session_out(
        self, chat: ChatSession, viewer_id: str, now: datetime
    ) -> ChatSessionOut:
        self._require_member(chat, viewer_id)
        peer_id = self._peer_id(chat, viewer_id)
        peer = self._active_user(peer_id)
        if peer is None:
            raise ChatServiceError("peer_not_found")
        return ChatSessionOut(
            id=chat.id,
            peer_user_id=peer_id,
            pqc_mode=chat.pqc_mode,
            key_agreement=chat.key_agreement,
            peer_key_bundle=self._key_bundle(peer, chat.pqc_mode, now),
            created_at=self._utc(chat.created_at),
        )

    def _key_bundle(self, peer: User, pqc_mode: bool, now: datetime) -> PeerKeyBundle:
        certificate = (
            self.session.get(CertificateRecord, peer.cert_serial)
            if peer.cert_serial
            else None
        )
        if (
            certificate is None
            or certificate.subject_user_id != peer.id
            or certificate.kind != "user_identity"
            or certificate.status != "active"
            or self._utc(certificate.not_before) > now
            or self._utc(certificate.not_after) <= now
            or "keyAgreement" not in certificate.key_usage.split(",")
        ):
            raise ChatServiceError("certificate_unavailable")
        ml_kem = None
        if pqc_mode:
            if peer.pqc_pubkey is None or len(peer.pqc_pubkey) != MLKEM_PUBLIC_KEY_SIZE:
                raise ChatServiceError("pqc_material_unavailable")
            ml_kem = base64.b64encode(peer.pqc_pubkey).decode("ascii")
        return PeerKeyBundle(
            sm2_certificate=base64.b64encode(certificate.certificate_der).decode("ascii"),
            ml_kem_public_key=ml_kem,
        )

    def _active_user(self, user_id: str) -> User | None:
        user = self.session.get(User, user_id)
        if (
            user is None
            or user.status != "active"
            or user.role not in {"student", "admin", "teacher"}
        ):
            return None
        return user

    @staticmethod
    def _require_member(chat: ChatSession | None, user_id: str) -> None:
        if chat is None or user_id not in {
            chat.participant_a_id,
            chat.participant_b_id,
        }:
            raise ChatServiceError("forbidden")

    @staticmethod
    def _peer_id(chat: ChatSession, user_id: str) -> str:
        return (
            chat.participant_b_id
            if chat.participant_a_id == user_id
            else chat.participant_a_id
        )

    @staticmethod
    def _message_out(record: EncryptedMessage) -> EncryptedMessageOut:
        return EncryptedMessageOut(
            id=record.id,
            session_id=record.session_id,
            sender_id=record.sender_id,
            sequence=record.sequence,
            ciphertext=base64.b64encode(record.ciphertext).decode("ascii"),
            nonce=base64.b64encode(record.nonce).decode("ascii"),
            tag=base64.b64encode(record.tag).decode("ascii"),
            signature=base64.b64encode(record.signature).decode("ascii"),
            created_at=ChatService._utc(record.created_at),
        )

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        manager = (
            self.session.begin_nested()
            if self.session.in_transaction()
            else self.session.begin()
        )
        with manager:
            yield

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
