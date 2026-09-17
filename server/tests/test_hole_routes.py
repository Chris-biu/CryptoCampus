import base64
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.dependencies import get_crypto_engine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE, SM2_SIGNATURE_SIZE
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit import RevocationLog
from app.models.credential import ConsumedSN
from app.models.hole import HolePost
from app.models.user import User
from app.schemas.credential import CredentialProof
from app.services.signer_provider import (
    ServerSignerVerificationKeyProvider,
    get_signer_verification_key_provider,
)


class DynamicMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            seed = f"hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


class MockVerificationKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x04" + b"\x33" * (SM2_PUBLIC_KEY_SIZE - 1))

    def get_signer_public_key(self, service: str) -> bytes | None:
        return self.key


def _setup_route_test():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    crypto_engine = DynamicMockCryptoEngine()
    crypto_engine.set_result("blind_verify", True)
    key_provider = MockVerificationKeyProvider()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto_engine
    app.dependency_overrides[get_signer_verification_key_provider] = lambda: key_provider

    client = TestClient(app)
    return client, session, crypto_engine, key_provider


def test_post_publish_success_201():
    client, session, crypto_engine, key_provider = _setup_route_test()

    today_utc = datetime.now(timezone.utc).date().isoformat()
    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")

    payload = {
        "content": "Hello anonymous hole post via API!",
        "credential": {
            "sn": sn_hex,
            "service": "hole_post",
            "period": today_utc,
            "signature": sig_b64,
        },
    }

    # Public endpoint: NO Authorization header
    resp = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "idemp-key-route-12345678"},
        json=payload,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()

    assert "id" in data
    assert data["content"] == "Hello anonymous hole post via API!"
    assert data["credential_prefix"] == "00112233"
    assert data["credential_valid"] is True
    assert data["status"] == "published"
    assert "created_at" in data

    # Strict anonymity check: NO identity fields in response
    for forbidden in ["user_id", "author_id", "email", "session_id", "sn", "signature", "credential"]:
        assert forbidden not in data


def test_post_publish_validation_errors_422():
    client, session, crypto_engine, key_provider = _setup_route_test()
    today_utc = datetime.now(timezone.utc).date().isoformat()
    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")

    # Missing Idempotency-Key
    resp = client.post(
        "/api/v1/hole/posts",
        json={"content": "Post without key", "credential": {"sn": sn_hex, "service": "hole_post", "period": today_utc, "signature": sig_b64}},
    )
    assert resp.status_code == 422

    # Short Idempotency-Key (< 16 chars)
    resp = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "short"},
        json={"content": "Post with short key", "credential": {"sn": sn_hex, "service": "hole_post", "period": today_utc, "signature": sig_b64}},
    )
    assert resp.status_code == 422

    # Empty content
    resp = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "idemp-key-valid-length-123"},
        json={"content": "", "credential": {"sn": sn_hex, "service": "hole_post", "period": today_utc, "signature": sig_b64}},
    )
    assert resp.status_code == 422

    # Wrong service in proof
    resp = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "idemp-key-valid-length-123"},
        json={"content": "Post wrong svc", "credential": {"sn": sn_hex, "service": "vote_ballot", "period": today_utc, "signature": sig_b64}},
    )
    assert resp.status_code in (401, 422)


def test_post_publish_invalid_signature_401():
    client, session, crypto_engine, key_provider = _setup_route_test()
    crypto_engine.set_result("blind_verify", False)

    today_utc = datetime.now(timezone.utc).date().isoformat()
    payload = {
        "content": "Invalid sig post",
        "credential": {
            "sn": "00112233445566778899aabbccddeeff",
            "service": "hole_post",
            "period": today_utc,
            "signature": base64.b64encode(b"\x00" * SM2_SIGNATURE_SIZE).decode("ascii"),
        },
    }

    resp = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "idemp-key-inv-sig-12345"},
        json=payload,
    )
    assert resp.status_code == 401


def test_post_publish_consumed_sn_and_idempotency_conflict_409():
    client, session, crypto_engine, key_provider = _setup_route_test()
    today_utc = datetime.now(timezone.utc).date().isoformat()
    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")

    payload1 = {
        "content": "Original post",
        "credential": {"sn": sn_hex, "service": "hole_post", "period": today_utc, "signature": sig_b64},
    }
    resp1 = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "idemp-key-409-test-12345"},
        json=payload1,
    )
    assert resp1.status_code == 201

    # Idempotent replay: exact same request returns 201 with same post
    resp_replay = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "idemp-key-409-test-12345"},
        json=payload1,
    )
    assert resp_replay.status_code == 201
    assert resp_replay.json()["id"] == resp1.json()["id"]

    # Same idempotency key, different content -> 409
    resp_conflict_content = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "idemp-key-409-test-12345"},
        json={"content": "Changed content", "credential": payload1["credential"]},
    )
    assert resp_conflict_content.status_code == 409

    # Different idempotency key, same SN -> 409 (already consumed)
    resp_reused_sn = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "different-key-1234567890"},
        json={"content": "Attempting to reuse SN", "credential": payload1["credential"]},
    )
    assert resp_reused_sn.status_code == 409


def test_post_publish_provider_unavailable_503():
    client, session, crypto_engine, key_provider = _setup_route_test()
    key_provider.key = None  # Provider unavailable

    today_utc = datetime.now(timezone.utc).date().isoformat()
    payload = {
        "content": "Post provider offline",
        "credential": {
            "sn": "00112233445566778899aabbccddeeff",
            "service": "hole_post",
            "period": today_utc,
            "signature": base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii"),
        },
    }

    resp = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "idemp-key-prov-offline-123"},
        json=payload,
    )
    assert resp.status_code == 503


def test_get_posts_pagination_and_sorting_200():
    client, session, crypto_engine, key_provider = _setup_route_test()

    now = datetime.now(timezone.utc)
    # Insert 25 published posts and 1 withdrawn post
    for i in range(25):
        post = HolePost(
            id=f"post-uuid-{i:04d}",
            content=f"Post content {i}",
            credential_sn=bytes([i] * 16),
            credential_service="hole_post",
            credential_period="2026-09-09",
            credential_signature=b"\x99" * 64,
            credential_prefix=f"{i:02x}" * 4,
            credential_valid=True,
            status="published",
            created_at=now,
        )
        session.add(post)

    withdrawn_post = HolePost(
        id="withdrawn-post-1",
        content="This should not appear",
        credential_sn=b"\xfe" * 16,
        credential_service="hole_post",
        credential_period="2026-09-09",
        credential_signature=b"\x99" * 64,
        credential_prefix="fefefefe",
        credential_valid=False,
        status="withdrawn",
        created_at=now - timedelta(seconds=60),
    )
    session.add(withdrawn_post)
    session.commit()

    # Public endpoint: NO Authorization header
    # 1. Default page=1, page_size=20
    resp = client.get("/api/v1/hole/posts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 26
    assert data["page"] == 1
    assert data["page_size"] == 20
    assert len(data["items"]) == 20

    # 2. Page 2: should return remaining 6 posts (including withdrawn-post-1)
    resp2 = client.get("/api/v1/hole/posts?page=2&page_size=20")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["total"] == 26
    assert data2["page"] == 2
    assert len(data2["items"]) == 6
    withdrawn_item = next((p for p in data2["items"] if p["id"] == "withdrawn-post-1"), None)
    assert withdrawn_item is not None
    assert withdrawn_item["content"] == "【内容已由管理员撤下（违规）】"
    assert withdrawn_item["credential_valid"] is False
    assert withdrawn_item["status"] == "withdrawn"

    # 3. Beyond last page: empty items
    resp3 = client.get("/api/v1/hole/posts?page=3&page_size=20")
    assert resp3.status_code == 200
    assert resp3.json()["items"] == []

    # 4. page_size=100
    resp4 = client.get("/api/v1/hole/posts?page=1&page_size=100")
    assert resp4.status_code == 200
    assert len(resp4.json()["items"]) == 26

    # 5. Invalid pagination parameters: 422
    assert client.get("/api/v1/hole/posts?page=0").status_code == 422
    assert client.get("/api/v1/hole/posts?page_size=0").status_code == 422
    assert client.get("/api/v1/hole/posts?page_size=101").status_code == 422


def test_post_credentials_verify_route_200():
    client, session, crypto_engine, key_provider = _setup_route_test()

    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")

    # 1. Valid unconsumed unrevoked
    crypto_engine.set_result("blind_verify", True)
    resp = client.post(
        "/api/v1/hole/credentials/verify",
        json={
            "sn": sn_hex,
            "service": "hole_post",
            "period": "2026-09-09",
            "signature": sig_b64,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["service"] == "hole_post"
    assert data["period"] == "2026-09-09"
    assert data["consumed"] is False
    assert data["revoked"] is False

    # 2. Invalid signature returns valid=False (200 OK)
    crypto_engine.set_result("blind_verify", False)
    resp2 = client.post(
        "/api/v1/hole/credentials/verify",
        json={
            "sn": sn_hex,
            "service": "hole_post",
            "period": "2026-09-09",
            "signature": sig_b64,
        },
    )
    assert resp2.status_code == 200
    assert resp2.json()["valid"] is False

    # 3. Provider unavailable returns 503
    key_provider.key = None
    resp3 = client.post(
        "/api/v1/hole/credentials/verify",
        json={
            "sn": sn_hex,
            "service": "hole_post",
            "period": "2026-09-09",
            "signature": sig_b64,
        },
    )
    assert resp3.status_code == 503


def test_hole_routes_and_remaining_unimplemented_routes():
    client, session, crypto_engine, key_provider = _setup_route_test()

    # The hole governance routes are implemented by this feature.
    resp_revocations = client.get("/api/v1/hole/revocations")
    assert resp_revocations.status_code == 200
    revocations_data = resp_revocations.json()
    assert revocations_data["items"] == []
    assert revocations_data["total"] == 0

    resp_withdraw = client.post("/api/v1/admin/hole/posts/dummy-id/withdraw")
    assert resp_withdraw.status_code == 401

    # Vote listing, results, and audit are implemented. An unknown vote remains
    # indistinguishable from an unavailable resource.
    resp_votes = client.get("/api/v1/votes")
    assert resp_votes.status_code == 200

    resp_unimplemented = client.get("/api/v1/votes/dummy-id/audit")
    assert resp_unimplemented.status_code == 404


def test_list_posts_with_withdrawn_post_shows_placeholder_and_retains_db_content():
    client, session, crypto_engine, key_provider = _setup_route_test()
    today_utc = datetime.now(timezone.utc).date().isoformat()

    # 1. Publish post 1 (to be withdrawn)
    sn1_hex = "11112222333344445555666677778888"
    sig1_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    resp1 = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "idemp-key-post-1-withdraw"},
        json={
            "content": "Secret content of post 1 to be withdrawn",
            "credential": {"sn": sn1_hex, "service": "hole_post", "period": today_utc, "signature": sig1_b64},
        },
    )
    assert resp1.status_code == 201
    post1_id = resp1.json()["id"]

    # 2. Publish post 2 (published)
    sn2_hex = "aaaabbbbccccddddeeeeffff00001111"
    sig2_b64 = base64.b64encode(b"\x88" * SM2_SIGNATURE_SIZE).decode("ascii")
    resp2 = client.post(
        "/api/v1/hole/posts",
        headers={"Idempotency-Key": "idemp-key-post-2-normal"},
        json={
            "content": "Normal published content of post 2",
            "credential": {"sn": sn2_hex, "service": "hole_post", "period": today_utc, "signature": sig2_b64},
        },
    )
    assert resp2.status_code == 201
    post2_id = resp2.json()["id"]

    # 3. Withdraw post 1 in database
    db_post1 = session.get(HolePost, post1_id)
    db_post1.status = "withdrawn"
    db_post1.credential_valid = False
    session.commit()

    # 4. GET /api/v1/hole/posts
    resp_list = client.get("/api/v1/hole/posts")
    assert resp_list.status_code == 200
    data = resp_list.json()

    assert data["total"] == 2
    items = data["items"]
    assert len(items) == 2

    # Verify published post
    p2 = next(p for p in items if p["id"] == post2_id)
    assert p2["content"] == "Normal published content of post 2"
    assert p2["credential_valid"] is True
    assert p2["status"] == "published"

    # Verify withdrawn post
    p1 = next(p for p in items if p["id"] == post1_id)
    assert p1["content"] == "【内容已由管理员撤下（违规）】"
    assert p1["credential_valid"] is False
    assert p1["status"] == "withdrawn"

    # 5. Verify database physical retention
    db_post1_check = session.get(HolePost, post1_id)
    assert db_post1_check.content == "Secret content of post 1 to be withdrawn"
