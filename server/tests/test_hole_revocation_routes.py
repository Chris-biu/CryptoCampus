import base64
from datetime import datetime, timedelta, timezone
import hashlib
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.hole import get_revocation_log_service
from app.crypto.dependencies import get_crypto_engine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit import RevocationLog
from app.models.user import User
from app.services.revocation_log import GENESIS_HASH, RevocationLogService, calculate_revocation_hash


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def __init__(self) -> None:
        super().__init__()
        self._error: CryptoBridgeError | None = None

    def set_error(self, error: CryptoBridgeError | None) -> None:
        self._error = error

    def sm3_digest(self, message: bytes) -> bytes:
        if self._error is not None:
            raise self._error
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


def _setup_test_env():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    admin_user = User(
        id=str(uuid.uuid4()),
        email="admin@campus.edu",
        role="admin",
        status="active",
    )
    session.add(admin_user)
    session.commit()

    crypto_engine = DeterministicMockCryptoEngine()
    app = create_app()

    service = RevocationLogService(session=session, crypto_engine=crypto_engine)

    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto_engine
    app.dependency_overrides[get_revocation_log_service] = lambda: service

    client = TestClient(app)
    return {
        "app": app,
        "client": client,
        "session": session,
        "crypto_engine": crypto_engine,
        "admin_user": admin_user,
    }


def _populate_chain(session: Session, crypto_engine: DeterministicMockCryptoEngine, count: int, operator_id: str) -> list[RevocationLog]:
    prev_hash = GENESIS_HASH
    records = []
    base_time = datetime(2026, 9, 10, 8, 0, 0, tzinfo=timezone.utc)
    for i in range(count):
        sn = f"sn-{i:012d}".encode("ascii").ljust(16, b"x")
        reason = f"撤销理由第 {i+1} 条"
        ts = base_time + timedelta(seconds=i * 10)
        curr_hash = calculate_revocation_hash(
            crypto_engine,
            hash_prev=prev_hash,
            sn=sn,
            reason=reason,
            timestamp=ts,
        )
        rec = RevocationLog(
            hash_curr=curr_hash,
            hash_prev=prev_hash,
            sn=sn,
            reason=reason,
            operator=operator_id,
            ts=ts,
        )
        session.add(rec)
        records.append(rec)
        prev_hash = curr_hash
    session.commit()
    return records


def test_list_revocations_public_access_no_token_and_invalid_token() -> None:
    env = _setup_test_env()
    client = env["client"]

    # 1. No token
    res1 = client.get("/api/v1/hole/revocations")
    assert res1.status_code == 200

    # 2. Invalid Bearer token
    res2 = client.get(
        "/api/v1/hole/revocations",
        headers={"Authorization": "Bearer completely-invalid-jwt-token"},
    )
    assert res2.status_code == 200

    # 3. Invalid header format
    res3 = client.get(
        "/api/v1/hole/revocations",
        headers={"Authorization": "Basic 123456"},
    )
    assert res3.status_code == 200


def test_list_revocations_empty_chain() -> None:
    env = _setup_test_env()
    client = env["client"]

    response = client.get("/api/v1/hole/revocations")
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["page"] == 1
    assert data["page_size"] == 20
    assert data["total"] == 0


def test_list_revocations_pagination_and_continuity() -> None:
    env = _setup_test_env()
    client = env["client"]
    session = env["session"]
    crypto_engine = env["crypto_engine"]
    admin = env["admin_user"]

    # Populate 25 chained entries
    records = _populate_chain(session, crypto_engine, 25, admin.id)

    # Page 1: default page=1, page_size=20
    res_page1 = client.get("/api/v1/hole/revocations")
    assert res_page1.status_code == 200
    data_page1 = res_page1.json()
    assert data_page1["total"] == 25
    assert data_page1["page"] == 1
    assert data_page1["page_size"] == 20
    assert len(data_page1["items"]) == 20

    # First entry hash_prev must be genesis hash base64
    expected_genesis_b64 = base64.b64encode(GENESIS_HASH).decode("ascii")
    assert data_page1["items"][0]["hash_prev"] == expected_genesis_b64

    # Verify within-page chain continuity
    for i in range(len(data_page1["items"]) - 1):
        curr_item = data_page1["items"][i]
        next_item = data_page1["items"][i + 1]
        assert curr_item["hash_curr"] == next_item["hash_prev"]

    # Verify strictly 5 allowed fields and no sensitive leaks
    for item in data_page1["items"]:
        assert set(item.keys()) == {"sn", "reason", "hash_prev", "hash_curr", "timestamp"}
        assert "operator" not in item
        assert "post_id" not in item
        assert "author_id" not in item

    # Page 2: page=2, page_size=20
    res_page2 = client.get("/api/v1/hole/revocations?page=2&page_size=20")
    assert res_page2.status_code == 200
    data_page2 = res_page2.json()
    assert data_page2["total"] == 25
    assert data_page2["page"] == 2
    assert data_page2["page_size"] == 20
    assert len(data_page2["items"]) == 5

    # Cross-page continuity check: last item of page 1 hash_curr == first item of page 2 hash_prev
    last_item_p1 = data_page1["items"][-1]
    first_item_p2 = data_page2["items"][0]
    assert last_item_p1["hash_curr"] == first_item_p2["hash_prev"]


def test_list_revocations_beyond_last_page() -> None:
    env = _setup_test_env()
    client = env["client"]
    session = env["session"]
    crypto_engine = env["crypto_engine"]
    admin = env["admin_user"]

    _populate_chain(session, crypto_engine, 25, admin.id)

    # Page 3: offset is 40, total is 25 -> items must be empty
    response = client.get("/api/v1/hole/revocations?page=3&page_size=20")
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["page"] == 3
    assert data["page_size"] == 20
    assert data["total"] == 25


def test_list_revocations_param_validation_422() -> None:
    env = _setup_test_env()
    client = env["client"]

    # page < 1
    res1 = client.get("/api/v1/hole/revocations?page=0")
    assert res1.status_code == 422
    assert res1.json()["code"] == "VALIDATION_ERROR"

    res1_neg = client.get("/api/v1/hole/revocations?page=-1")
    assert res1_neg.status_code == 422
    assert res1_neg.json()["code"] == "VALIDATION_ERROR"

    # page_size < 1
    res2 = client.get("/api/v1/hole/revocations?page_size=0")
    assert res2.status_code == 422
    assert res2.json()["code"] == "VALIDATION_ERROR"

    # page_size > 100
    res3 = client.get("/api/v1/hole/revocations?page_size=101")
    assert res3.status_code == 422
    assert res3.json()["code"] == "VALIDATION_ERROR"

    # Non-integer parameters
    res4 = client.get("/api/v1/hole/revocations?page=invalid")
    assert res4.status_code == 422
    assert res4.json()["code"] == "VALIDATION_ERROR"


def test_list_revocations_corrupted_chain_returns_500() -> None:
    env = _setup_test_env()
    client = env["client"]
    session = env["session"]
    crypto_engine = env["crypto_engine"]
    admin = env["admin_user"]

    # Populate 5 chained entries
    records = _populate_chain(session, crypto_engine, 5, admin.id)

    # Tamper with record #2's reason directly in DB
    records[2].reason = "篡改后的理由"
    session.commit()

    # Must fail entire chain verification and return 500 INTERNAL_ERROR
    response = client.get("/api/v1/hole/revocations")
    assert response.status_code == 500
    data = response.json()
    assert data["code"] == "INTERNAL_ERROR"
    # Never return partial corrupted records
    assert "items" not in data


def test_list_revocations_engine_unavailable_503() -> None:
    env = _setup_test_env()
    client = env["client"]
    session = env["session"]
    crypto_engine = env["crypto_engine"]
    admin = env["admin_user"]

    _populate_chain(session, crypto_engine, 3, admin.id)
    crypto_engine.set_error(CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))


    response = client.get("/api/v1/hole/revocations")
    assert response.status_code == 503
    data = response.json()
    assert data["code"] == "PROVIDER_UNAVAILABLE"
