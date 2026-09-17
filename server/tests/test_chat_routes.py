from collections.abc import Generator
from datetime import datetime, timedelta, timezone
import hashlib
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.chat import router
from app.core.errors import install_exception_handlers
from app.crypto.dependencies import get_crypto_engine
from app.crypto.types import MLKEM_PUBLIC_KEY_SIZE
from app.db.session import get_db
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, get_current_user


class DigestEngine:
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(message).digest()

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


def _seed(db_session):
    now = datetime.now(timezone.utc)
    users = [
        User(
            id=str(uuid4()),
            email=f"{uuid4()}@example.test",
            role="student",
            status="active",
            pubkey=b"p" * 65,
            pqc_pubkey=b"q" * MLKEM_PUBLIC_KEY_SIZE,
            enc_pqc_sk=b"encrypted",
        )
        for _ in range(3)
    ]
    db_session.add_all(users)
    db_session.flush()
    for user in users:
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
    db_session.commit()
    return users


def _client(db_session, active_user: dict[str, User]) -> TestClient:
    app = FastAPI()
    install_exception_handlers(app)
    app.include_router(router, prefix="/api/v1")

    def database() -> Generator:
        yield db_session

    def current_user() -> CurrentUser:
        user = active_user["value"]
        return CurrentUser(user_id=user.id, role=user.role, status=user.status)

    app.dependency_overrides[get_db] = database
    app.dependency_overrides[get_crypto_engine] = lambda: DigestEngine()
    app.dependency_overrides[get_current_user] = current_user
    return TestClient(app)


def test_chat_http_create_list_history_and_idor(db_session) -> None:
    owner, peer, outsider = _seed(db_session)
    active_user = {"value": owner}
    client = _client(db_session, active_user)
    headers = {"Idempotency-Key": "idempotency-key-0001"}

    created = client.post(
        "/api/v1/chat/sessions",
        headers=headers,
        json={"peer_user_id": peer.id, "pqc_mode": False},
    )
    assert created.status_code == 201
    session_id = created.json()["id"]
    assert created.json()["peer_user_id"] == peer.id
    assert client.get("/api/v1/chat/sessions").json()["items"][0]["id"] == session_id
    assert client.get(
        f"/api/v1/chat/sessions/{session_id}/messages?page=1&page_size=20"
    ).json() == {"items": [], "page": 1, "page_size": 20, "total": 0}

    active_user["value"] = outsider
    forbidden = client.get(
        f"/api/v1/chat/sessions/{session_id}/messages?page=1&page_size=20"
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["code"] == "FORBIDDEN"


def test_chat_http_maps_self_conflict_and_missing_pqc_material(db_session) -> None:
    owner, peer, _ = _seed(db_session)
    active_user = {"value": owner}
    client = _client(db_session, active_user)

    assert client.post(
        "/api/v1/chat/sessions",
        headers={"Idempotency-Key": "idempotency-key-0001"},
        json={"peer_user_id": owner.id, "pqc_mode": False},
    ).status_code == 400

    first = client.post(
        "/api/v1/chat/sessions",
        headers={"Idempotency-Key": "idempotency-key-0002"},
        json={"peer_user_id": peer.id, "pqc_mode": False},
    )
    assert first.status_code == 201
    assert client.post(
        "/api/v1/chat/sessions",
        headers={"Idempotency-Key": "idempotency-key-0002"},
        json={"peer_user_id": peer.id, "pqc_mode": True},
    ).status_code == 409

    peer.pqc_pubkey = None
    peer.enc_pqc_sk = None
    db_session.commit()
    unavailable = client.post(
        "/api/v1/chat/sessions",
        headers={"Idempotency-Key": "idempotency-key-0003"},
        json={"peer_user_id": peer.id, "pqc_mode": True},
    )
    assert unavailable.status_code == 503
    assert unavailable.json()["code"] == "KEY_MATERIAL_UNAVAILABLE"


def test_main_router_replaces_fail_closed_chat_placeholders() -> None:
    from app.api.routes.not_implemented import NOT_IMPLEMENTED_OPERATIONS

    assert not any(path.startswith("/chat/") for _, path, _ in NOT_IMPLEMENTED_OPERATIONS)
