from datetime import datetime, timedelta, timezone
import hashlib
from uuid import uuid4

import pytest

from app.crypto.types import MLKEM_PUBLIC_KEY_SIZE
from app.models.certificate import CertificateRecord
from app.models.chat import ChatSession, EncryptedMessage
from app.models.user import User
from app.schemas.chat import ChatEncryptedMessageInput, CreateChatSessionRequest
from app.services.chat import ChatService, ChatServiceError


class DigestEngine:
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(message).digest()

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


def _user(*, status: str = "active", pqc: bool = True) -> User:
    return User(
        id=str(uuid4()),
        email=f"{uuid4()}@example.test",
        role="student",
        status=status,
        pubkey=b"p" * 65,
        pqc_pubkey=b"q" * MLKEM_PUBLIC_KEY_SIZE if pqc else None,
        enc_pqc_sk=b"encrypted" if pqc else None,
    )


def _add_identity(db_session, user: User, now: datetime) -> None:
    serial = f"cert-{user.id}"
    user.cert_serial = serial
    db_session.add(
        CertificateRecord(
            serial=serial,
            subject_user_id=user.id,
            issuer_serial="ca-1",
            kind="user_identity",
            certificate_der=f"certificate:{user.id}".encode(),
            key_usage="digitalSignature,keyAgreement",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=1),
            status="active",
        )
    )


def _seed_pair(db_session, *, peer_status: str = "active", peer_pqc: bool = True):
    now = datetime.now(timezone.utc)
    owner, peer = _user(), _user(status=peer_status, pqc=peer_pqc)
    db_session.add_all((owner, peer))
    db_session.flush()
    _add_identity(db_session, owner, now)
    _add_identity(db_session, peer, now)
    db_session.commit()
    return now, owner, peer


def _service(db_session) -> ChatService:
    return ChatService(db_session, DigestEngine())


def test_create_session_is_idempotent_and_reuses_member_pair(db_session) -> None:
    now, owner, peer = _seed_pair(db_session)
    service = _service(db_session)
    request = CreateChatSessionRequest(peer_user_id=peer.id, pqc_mode=False)

    first = service.create_session(
        owner_user_id=owner.id,
        request=request,
        idempotency_key="idempotency-key-0001",
        now=now,
    )
    replay = service.create_session(
        owner_user_id=owner.id,
        request=request,
        idempotency_key="idempotency-key-0001",
        now=now,
    )
    second_key = service.create_session(
        owner_user_id=owner.id,
        request=request,
        idempotency_key="idempotency-key-0002",
        now=now,
    )

    assert first.id == replay.id == second_key.id
    assert first.peer_user_id == peer.id
    assert first.key_agreement == "SM2-ECDH"
    assert first.peer_key_bundle.ml_kem_public_key is None
    assert db_session.query(ChatSession).count() == 1


def test_idempotency_key_cannot_be_reused_for_different_request(db_session) -> None:
    now, owner, peer = _seed_pair(db_session)
    service = _service(db_session)
    service.create_session(
        owner_user_id=owner.id,
        request=CreateChatSessionRequest(peer_user_id=peer.id, pqc_mode=False),
        idempotency_key="idempotency-key-0001",
        now=now,
    )

    with pytest.raises(ChatServiceError, match="idempotency_conflict"):
        service.create_session(
            owner_user_id=owner.id,
            request=CreateChatSessionRequest(peer_user_id=peer.id, pqc_mode=True),
            idempotency_key="idempotency-key-0001",
            now=now,
        )


def test_pqc_session_requires_real_peer_material(db_session) -> None:
    now, owner, peer = _seed_pair(db_session, peer_pqc=False)

    with pytest.raises(ChatServiceError, match="pqc_material_unavailable"):
        _service(db_session).create_session(
            owner_user_id=owner.id,
            request=CreateChatSessionRequest(peer_user_id=peer.id, pqc_mode=True),
            idempotency_key="idempotency-key-0001",
            now=now,
        )


@pytest.mark.parametrize("certificate_state", ["revoked", "expired"])
def test_session_creation_rejects_revoked_or_expired_certificate(
    db_session, certificate_state: str
) -> None:
    now, owner, peer = _seed_pair(db_session)
    certificate = db_session.get(CertificateRecord, peer.cert_serial)
    assert certificate is not None
    if certificate_state == "revoked":
        certificate.status = "revoked"
        certificate.revoked_at = now
        certificate.revocation_reason = "superseded"
    else:
        certificate.not_after = now
    db_session.commit()

    with pytest.raises(ChatServiceError, match="certificate_unavailable"):
        _service(db_session).create_session(
            owner_user_id=owner.id,
            request=CreateChatSessionRequest(peer_user_id=peer.id, pqc_mode=False),
            idempotency_key="idempotency-key-0001",
            now=now,
        )


def test_frozen_peer_is_not_enumerable_and_self_chat_is_rejected(db_session) -> None:
    now, owner, peer = _seed_pair(db_session, peer_status="frozen")
    service = _service(db_session)

    with pytest.raises(ChatServiceError, match="peer_not_found"):
        service.create_session(
            owner_user_id=owner.id,
            request=CreateChatSessionRequest(peer_user_id=peer.id, pqc_mode=False),
            idempotency_key="idempotency-key-0001",
            now=now,
        )
    with pytest.raises(ChatServiceError, match="self_chat"):
        service.create_session(
            owner_user_id=owner.id,
            request=CreateChatSessionRequest(peer_user_id=owner.id, pqc_mode=False),
            idempotency_key="idempotency-key-0002",
            now=now,
        )


def test_list_and_history_enforce_membership_and_stable_order(db_session) -> None:
    now, owner, peer = _seed_pair(db_session)
    outsider = _user()
    db_session.add(outsider)
    db_session.commit()
    service = _service(db_session)
    created = service.create_session(
        owner_user_id=owner.id,
        request=CreateChatSessionRequest(peer_user_id=peer.id, pqc_mode=False),
        idempotency_key="idempotency-key-0001",
        now=now,
    )

    first = service.persist_message(
        sender_id=owner.id,
        frame=ChatEncryptedMessageInput(
            session_id=created.id,
            sequence=1,
            ciphertext="YQ==",
            nonce="bm5ubm5ubm5ubm5u",
            tag="dHR0dHR0dHR0dHR0dHR0dA==",
            signature="cw==",
        ),
        now=now,
    )
    second = service.persist_message(
        sender_id=peer.id,
        frame=ChatEncryptedMessageInput(
            session_id=created.id,
            sequence=1,
            ciphertext="Yg==",
            nonce="bm5ubm5ubm5ubm5u",
            tag="dHR0dHR0dHR0dHR0dHR0dA==",
            signature="cw==",
        ),
        now=now,
    )

    assert [item.id for item in service.list_sessions(user_id=owner.id)] == [created.id]
    page = service.list_messages(user_id=owner.id, session_id=created.id, page=1, page_size=1)
    assert page.total == 2
    expected_ids = sorted((first.id, second.id))
    assert page.items[0].id == expected_ids[0]
    assert service.list_messages(
        user_id=owner.id, session_id=created.id, page=2, page_size=1
    ).items[0].id == expected_ids[1]
    with pytest.raises(ChatServiceError, match="forbidden"):
        service.list_messages(
            user_id=outsider.id, session_id=created.id, page=1, page_size=20
        )


def test_duplicate_sequence_is_rejected_without_second_row(db_session) -> None:
    now, owner, peer = _seed_pair(db_session)
    service = _service(db_session)
    created = service.create_session(
        owner_user_id=owner.id,
        request=CreateChatSessionRequest(peer_user_id=peer.id, pqc_mode=False),
        idempotency_key="idempotency-key-0001",
        now=now,
    )
    frame = ChatEncryptedMessageInput(
        session_id=created.id,
        sequence=1,
        ciphertext="YQ==",
        nonce="bm5ubm5ubm5ubm5u",
        tag="dHR0dHR0dHR0dHR0dHR0dA==",
        signature="cw==",
    )
    service.persist_message(sender_id=owner.id, frame=frame, now=now)

    with pytest.raises(ChatServiceError, match="duplicate_sequence"):
        service.persist_message(sender_id=owner.id, frame=frame, now=now)

    assert db_session.query(EncryptedMessage).count() == 1
