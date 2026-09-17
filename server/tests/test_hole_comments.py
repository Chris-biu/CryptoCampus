import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.dependencies import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit import RevocationLog
from app.models.credential import ConsumedSN
from app.models.hole import HoleComment, HoleCommentIdempotency, HolePost
from app.schemas.credential import CredentialProof
from app.services.credential_verification import verify_consumption_credential
from app.services.hole_interactions import (
    HoleInteractionService,
    HoleInteractionServiceError,
)
from app.services.signer_provider import (
    ServerSignerVerificationKeyProvider,
    get_signer_verification_key_provider,
)


class MockVerificationKeyProvider:
    def __init__(self, key_map: dict[str, bytes] | None = None) -> None:
        self.key_map = key_map if key_map is not None else {
            "hole_post": b"\x22" * SM2_PUBLIC_KEY_SIZE,
            "hole_comment": b"\x33" * SM2_PUBLIC_KEY_SIZE,
            "hole_like": b"\x44" * SM2_PUBLIC_KEY_SIZE,
        }

    def get_signer_public_key(self, service: str) -> bytes | None:
        return self.key_map.get(service)


class DynamicMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0
        self.set_result("blind_verify", True)

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            seed = f"hash-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right


def _create_sqlite_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def _setup_service():
    session = _create_sqlite_session()
    crypto_engine = DynamicMockCryptoEngine()
    provider = MockVerificationKeyProvider()
    service = HoleInteractionService(
        session=session,
        crypto_engine=crypto_engine,
        signer_verification_key_provider=provider,
    )
    now = datetime.now(timezone.utc)
    today_period = now.strftime("%Y-%m-%d")

    # Create a published post
    post = HolePost(
        id=str(uuid.uuid4()),
        content="Published post for comments",
        credential_sn=bytes.fromhex("11" * 16),
        credential_service="hole_post",
        credential_period=today_period,
        credential_signature=b"\x11" * 64,
        credential_prefix="11" * 4,
        credential_valid=True,
        status="published",
        created_at=now,
    )
    session.add(post)
    session.commit()

    return session, crypto_engine, provider, service, post, now, today_period


def test_create_comment_success():
    session, crypto_engine, provider, service, post, now, today_period = _setup_service()

    sn_hex = "22" * 16
    sig_b64 = base64.b64encode(b"\x22" * 64).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_comment",
        period=today_period,
        signature=sig_b64,
    )

    comment = service.create_comment(
        post_id=post.id,
        content="This is an anonymous comment",
        credential=proof,
        idempotency_key="idemp-key-comment-001",
        now=now,
    )

    assert comment.id is not None
    assert comment.post_id == post.id
    assert comment.content == "This is an anonymous comment"
    assert comment.credential_prefix == sn_hex[:8]
    assert comment.credential_valid is True

    # ConsumedSN check
    consumed = session.get(ConsumedSN, (bytes.fromhex(sn_hex), "hole_comment"))
    assert consumed is not None

    # HoleCommentIdempotency check
    idemp = session.query(HoleCommentIdempotency).filter_by(comment_id=comment.id).first()
    assert idemp is not None


def test_create_comment_rejects_unpublished_or_nonexistent_post():
    session, crypto_engine, provider, service, post, now, today_period = _setup_service()

    # Create withdrawn post
    withdrawn_post = HolePost(
        id=str(uuid.uuid4()),
        content="Withdrawn post",
        credential_sn=bytes.fromhex("33" * 16),
        credential_service="hole_post",
        credential_period=today_period,
        credential_signature=b"\x33" * 64,
        credential_prefix="33" * 4,
        credential_valid=True,
        status="withdrawn",
        created_at=now,
    )
    session.add(withdrawn_post)
    session.commit()

    proof = CredentialProof(
        sn="44" * 16,
        service="hole_comment",
        period=today_period,
        signature=base64.b64encode(b"\x44" * 64).decode("ascii"),
    )

    # Attempt to comment on withdrawn post
    with pytest.raises(HoleInteractionServiceError) as exc_info:
        service.create_comment(
            post_id=withdrawn_post.id,
            content="Comment on withdrawn post",
            credential=proof,
            idempotency_key="idemp-key-c-withdrawn",
            now=now,
        )
    assert exc_info.value.code == "post_not_available"

    # Attempt to comment on non-existent post
    with pytest.raises(HoleInteractionServiceError) as exc_info2:
        service.create_comment(
            post_id=str(uuid.uuid4()),
            content="Comment on missing post",
            credential=proof,
            idempotency_key="idemp-key-c-missing",
            now=now,
        )
    assert exc_info2.value.code == "post_not_available"

    # Verify no ConsumedSN recorded
    assert session.get(ConsumedSN, (bytes.fromhex("44" * 16), "hole_comment")) is None


def test_create_comment_content_length_validation():
    session, crypto_engine, provider, service, post, now, today_period = _setup_service()

    proof = CredentialProof(
        sn="55" * 16,
        service="hole_comment",
        period=today_period,
        signature=base64.b64encode(b"\x55" * 64).decode("ascii"),
    )

    # Empty content
    with pytest.raises(HoleInteractionServiceError) as exc1:
        service.create_comment(
            post_id=post.id,
            content="",
            credential=proof,
            idempotency_key="idemp-key-empty-content",
            now=now,
        )
    assert exc1.value.code == "invalid_content"

    # Content too long (> 2000 chars)
    with pytest.raises(HoleInteractionServiceError) as exc2:
        service.create_comment(
            post_id=post.id,
            content="a" * 2001,
            credential=proof,
            idempotency_key="idemp-key-long-content",
            now=now,
        )
    assert exc2.value.code == "invalid_content"


def test_comment_idempotency_replay_and_conflict():
    session, crypto_engine, provider, service, post, now, today_period = _setup_service()

    proof = CredentialProof(
        sn="66" * 16,
        service="hole_comment",
        period=today_period,
        signature=base64.b64encode(b"\x66" * 64).decode("ascii"),
    )
    key = "idemp-key-comment-replay-001"

    c1 = service.create_comment(
        post_id=post.id,
        content="First submit",
        credential=proof,
        idempotency_key=key,
        now=now,
    )

    # Replay identical request
    c2 = service.create_comment(
        post_id=post.id,
        content="First submit",
        credential=proof,
        idempotency_key=key,
        now=now,
    )
    assert c1.id == c2.id

    # Conflict: same key, different content
    with pytest.raises(HoleInteractionServiceError) as exc_info:
        service.create_comment(
            post_id=post.id,
            content="Different content",
            credential=proof,
            idempotency_key=key,
            now=now,
        )
    assert exc_info.value.code == "idempotency_conflict"

    # Attempt to consume same credential with different idempotency key
    with pytest.raises(HoleInteractionServiceError) as exc_info2:
        service.create_comment(
            post_id=post.id,
            content="Another attempt",
            credential=proof,
            idempotency_key="idemp-key-different-002",
            now=now,
        )
    assert exc_info2.value.code == "credential_consumed"


def test_list_comments_pagination_and_stability():
    session, crypto_engine, provider, service, post, now, today_period = _setup_service()

    # Add 25 comments
    for i in range(25):
        sn_hex = f"{i:02x}" * 16
        c = HoleComment(
            id=f"comment-id-{i:04d}",
            post_id=post.id,
            content=f"Comment content {i}",
            credential_sn=bytes.fromhex(sn_hex),
            credential_service="hole_comment",
            credential_period=today_period,
            credential_signature=b"\x77" * 64,
            credential_prefix=sn_hex[:8],
            credential_valid=True,
            created_at=now,
        )
        session.add(c)
    session.commit()

    # Page 1
    page1 = service.list_comments(post_id=post.id, page=1, page_size=20)
    assert page1.total == 25
    assert len(page1.items) == 20
    assert page1.page == 1
    assert page1.page_size == 20
    # Stability: sorted by created_at DESC, id DESC
    assert page1.items[0].id == "comment-id-0024"
    assert page1.items[1].id == "comment-id-0023"

    # Page 2
    page2 = service.list_comments(post_id=post.id, page=2, page_size=20)
    assert len(page2.items) == 5
    assert page2.items[0].id == "comment-id-0004"

    # Page 3 (out of range)
    page3 = service.list_comments(post_id=post.id, page=3, page_size=20)
    assert len(page3.items) == 0


def test_list_comments_rejects_missing_post():
    session, crypto_engine, provider, service, post, now, today_period = _setup_service()

    with pytest.raises(HoleInteractionServiceError) as exc_info:
        service.list_comments(post_id=str(uuid.uuid4()))
    assert exc_info.value.code == "post_not_found"


def test_comment_api_routes():
    session = _create_sqlite_session()
    crypto_engine = DynamicMockCryptoEngine()
    provider = MockVerificationKeyProvider()
    now = datetime.now(timezone.utc)
    today_period = now.strftime("%Y-%m-%d")

    post = HolePost(
        id=str(uuid.uuid4()),
        content="Post for route test",
        credential_sn=bytes.fromhex("88" * 16),
        credential_service="hole_post",
        credential_period=today_period,
        credential_signature=b"\x88" * 64,
        credential_prefix="88" * 4,
        credential_valid=True,
        status="published",
        created_at=now,
    )
    session.add(post)
    session.commit()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto_engine
    app.dependency_overrides[get_signer_verification_key_provider] = lambda: provider

    client = TestClient(app)

    sn_hex = "99" * 16
    sig_b64 = base64.b64encode(b"\x99" * 64).decode("ascii")

    # POST comment success
    res = client.post(
        f"/api/v1/hole/posts/{post.id}/comments",
        headers={"Idempotency-Key": "idemp-route-comment-001"},
        json={
            "content": "Route test comment",
            "credential": {
                "sn": sn_hex,
                "service": "hole_comment",
                "period": today_period,
                "signature": sig_b64,
            },
        },
    )
    assert res.status_code == 201, res.text
    data = res.json()
    assert data["post_id"] == post.id
    assert data["content"] == "Route test comment"
    assert data["credential_prefix"] == sn_hex[:8]
    assert data["credential_valid"] is True

    # GET comments
    get_res = client.get(f"/api/v1/hole/posts/{post.id}/comments")
    assert get_res.status_code == 200
    list_data = get_res.json()
    assert list_data["total"] == 1
    assert len(list_data["items"]) == 1
    assert list_data["items"][0]["content"] == "Route test comment"

    # GET comments on missing post returns 404
    missing_res = client.get(f"/api/v1/hole/posts/{str(uuid.uuid4())}/comments")
    assert missing_res.status_code == 404
