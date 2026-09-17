from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from threading import Barrier
from uuid import uuid4

from app.db.session import create_session_factory
from app.models.certificate import CertificateRecord
from app.models.chat import ChatSession, EncryptedMessage
from app.models.user import User
from app.schemas.chat import ChatEncryptedMessageInput, CreateChatSessionRequest
from app.services.chat import ChatService, ChatServiceError


ROOT = Path(__file__).resolve().parents[2]


class NoCryptoCalls:
    def __getattr__(self, name: str):
        raise AssertionError(f"unexpected crypto call: {name}")


class DigestEngine:
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(message).digest()

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


def _add_identity(db_session, user: User, now: datetime) -> None:
    user.cert_serial = f"cert-{user.id}"
    db_session.add(
        CertificateRecord(
            serial=user.cert_serial,
            subject_user_id=user.id,
            issuer_serial="ca-1",
            kind="user_identity",
            certificate_der=f"cert:{user.id}".encode(),
            key_usage="digitalSignature,keyAgreement",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=1),
            status="active",
        )
    )


def test_concurrent_session_creation_converges_for_both_participants(
    db_engine, db_session
) -> None:
    now = datetime.now(timezone.utc)
    owner = User(id=str(uuid4()), email=f"{uuid4()}@example.test", role="student", status="active")
    peer = User(id=str(uuid4()), email=f"{uuid4()}@example.test", role="teacher", status="active")
    db_session.add_all((owner, peer))
    db_session.flush()
    _add_identity(db_session, owner, now)
    _add_identity(db_session, peer, now)
    db_session.commit()
    factory = create_session_factory(db_engine)
    barrier = Barrier(2)

    def create(user_id: str, peer_id: str, key: str) -> str:
        with factory() as session:
            barrier.wait()
            result = ChatService(session, DigestEngine()).create_session(
                owner_user_id=user_id,
                request=CreateChatSessionRequest(peer_user_id=peer_id, pqc_mode=False),
                idempotency_key=key,
                now=now,
            )
            return result.id

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(create, owner.id, peer.id, "owner-key-0000001")
        second = executor.submit(create, peer.id, owner.id, "peer-key-00000001")
        session_ids = [first.result(), second.result()]

    assert session_ids[0] == session_ids[1]
    with factory() as session:
        assert session.query(ChatSession).count() == 1


def test_concurrent_duplicate_sequence_persists_exactly_once(db_engine, db_session) -> None:
    owner = User(id=str(uuid4()), email=f"{uuid4()}@example.test", role="student", status="active")
    peer = User(id=str(uuid4()), email=f"{uuid4()}@example.test", role="student", status="active")
    db_session.add_all((owner, peer))
    db_session.flush()
    left, right = sorted((owner.id, peer.id))
    chat = ChatSession(participant_a_id=left, participant_b_id=right, pqc_mode=False)
    db_session.add(chat)
    db_session.commit()
    frame = ChatEncryptedMessageInput(
        session_id=chat.id,
        sequence=1,
        ciphertext="Y2lwaGVy",
        nonce="bm5ubm5ubm5ubm5u",
        tag="dHR0dHR0dHR0dHR0dHR0dA==",
        signature="c2ln",
    )
    factory = create_session_factory(db_engine)
    barrier = Barrier(2)

    def submit() -> str:
        with factory() as session:
            barrier.wait()
            try:
                ChatService(session, NoCryptoCalls()).persist_message(
                    sender_id=owner.id,
                    frame=frame,
                    now=datetime.now(timezone.utc),
                )
                return "created"
            except ChatServiceError as error:
                return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: submit(), range(2)))

    assert sorted(results) == ["created", "duplicate_sequence"]
    with factory() as session:
        assert session.query(EncryptedMessage).count() == 1


def test_chat_implementation_has_no_decryption_or_session_secret_storage() -> None:
    model_source = (ROOT / "server/app/models/chat.py").read_text(encoding="utf-8")
    service_source = (ROOT / "server/app/services/chat.py").read_text(encoding="utf-8")
    route_source = (ROOT / "server/app/api/routes/chat.py").read_text(encoding="utf-8")

    forbidden_columns = (
        "mapped_column(String",  # secret-like values must never be added as text columns below
    )
    del forbidden_columns
    for forbidden in (
        "shared_secret:",
        "session_key:",
        "private_key:",
        "plaintext:",
        "decrypted_status:",
    ):
        assert forbidden not in model_source
    for forbidden_call in (
        ".sm2_ecdh(",
        ".hkdf_sm3(",
        ".sm4_gcm_encrypt(",
        ".sm4_gcm_decrypt(",
        ".envelope_open(",
    ):
        assert forbidden_call not in service_source
        assert forbidden_call not in route_source
