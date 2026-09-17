import base64
from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.dependencies import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit import AuditLog, RevocationLog
from app.models.credential import ConsumedSN, CredentialIssueIdempotency, CredentialLedger
from app.models.hole import (
    HoleComment,
    HoleCommentIdempotency,
    HoleLike,
    HoleLikeIdempotency,
    HolePost,
)
from app.models.user import User
from app.schemas.credential import CredentialProof
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
        content="Published post for anonymity tests",
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


class TestHoleInteractionCrossService:
    def test_same_sn_can_be_consumed_separately_for_comment_and_like(self):
        session, crypto_engine, provider, service, post, now, today_period = _setup_service()
        shared_sn_hex = "aa" * 16

        comment_proof = CredentialProof(
            sn=shared_sn_hex,
            service="hole_comment",
            period=today_period,
            signature=base64.b64encode(b"\x33" * 64).decode("ascii"),
        )
        like_proof = CredentialProof(
            sn=shared_sn_hex,
            service="hole_like",
            period=today_period,
            signature=base64.b64encode(b"\x44" * 64).decode("ascii"),
        )

        # 1. Consume comment credential
        comment = service.create_comment(
            post_id=post.id,
            content="A comment with shared SN",
            credential=comment_proof,
            idempotency_key="test-key-shared-sn-comment",
            now=now,
        )
        assert comment is not None

        # 2. Consume like credential with same SN
        service.like_post(
            post_id=post.id,
            credential=like_proof,
            idempotency_key="test-key-shared-sn-like",
            now=now,
        )

        # 3. Verify both exist in ConsumedSN under distinct services
        sn_bytes = bytes.fromhex(shared_sn_hex)
        assert session.get(ConsumedSN, (sn_bytes, "hole_comment")) is not None
        assert session.get(ConsumedSN, (sn_bytes, "hole_like")) is not None

        # 4. Same SN + same service cannot be consumed again
        with pytest.raises(HoleInteractionServiceError) as exc_info:
            service.create_comment(
                post_id=post.id,
                content="Another comment attempt",
                credential=comment_proof,
                idempotency_key="test-key-shared-sn-comment-2",
                now=now,
            )
        assert exc_info.value.code == "credential_consumed"

        with pytest.raises(HoleInteractionServiceError) as exc_info2:
            service.like_post(
                post_id=post.id,
                credential=like_proof,
                idempotency_key="test-key-shared-sn-like-2",
                now=now,
            )
        assert exc_info2.value.code == "credential_consumed"

    def test_cross_service_rejection(self):
        session, crypto_engine, provider, service, post, now, today_period = _setup_service()
        comment_proof = CredentialProof(
            sn="bb" * 16,
            service="hole_comment",
            period=today_period,
            signature=base64.b64encode(b"\x33" * 64).decode("ascii"),
        )
        like_proof = CredentialProof(
            sn="cc" * 16,
            service="hole_like",
            period=today_period,
            signature=base64.b64encode(b"\x44" * 64).decode("ascii"),
        )
        post_proof = CredentialProof(
            sn="dd" * 16,
            service="hole_post",
            period=today_period,
            signature=base64.b64encode(b"\x22" * 64).decode("ascii"),
        )

        # Comment endpoint rejects hole_like and hole_post
        with pytest.raises(HoleInteractionServiceError) as exc:
            service.create_comment(
                post_id=post.id,
                content="Test",
                credential=like_proof,
                idempotency_key="test-key-cross-01",
                now=now,
            )
        assert exc.value.code == "invalid_service"

        with pytest.raises(HoleInteractionServiceError) as exc:
            service.create_comment(
                post_id=post.id,
                content="Test",
                credential=post_proof,
                idempotency_key="test-key-cross-02",
                now=now,
            )
        assert exc.value.code == "invalid_service"

        # Like endpoint rejects hole_comment and hole_post
        with pytest.raises(HoleInteractionServiceError) as exc:
            service.like_post(
                post_id=post.id,
                credential=comment_proof,
                idempotency_key="test-key-cross-03",
                now=now,
            )
        assert exc.value.code == "invalid_service"

        with pytest.raises(HoleInteractionServiceError) as exc:
            service.like_post(
                post_id=post.id,
                credential=post_proof,
                idempotency_key="test-key-cross-04",
                now=now,
            )
        assert exc.value.code == "invalid_service"


class TestHoleInteractionAnonymityBoundaries:
    def test_interaction_models_strict_zero_identity(self):
        forbidden_substrings = [
            "user", "author", "creator", "email", "session",
            "token", "ip", "device", "ledger", "account",
        ]
        models_to_check = [
            HoleComment,
            HoleLike,
            HoleCommentIdempotency,
            HoleLikeIdempotency,
        ]
        for model in models_to_check:
            column_names = [col.name.lower() for col in model.__table__.columns]
            for col in column_names:
                for forbidden in forbidden_substrings:
                    assert forbidden not in col, (
                        f"Model {model.__name__} contains forbidden column: {col}"
                    )

    def test_anonymous_operations_never_query_user_or_ledger(self):
        # We hook into the engine to monitor all executed SQL statements
        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
        session = SessionLocal()

        queried_tables = []

        @event.listens_for(engine, "before_cursor_execute")
        def intercept_sql(conn, cursor, statement, parameters, context, executemany):
            stmt_lower = statement.lower()
            for forbidden_table in ["users", "credential_ledger", "credential_issue_idempotency"]:
                if forbidden_table in stmt_lower:
                    queried_tables.append(forbidden_table)

        crypto_engine = DynamicMockCryptoEngine()
        provider = MockVerificationKeyProvider()
        service = HoleInteractionService(
            session=session,
            crypto_engine=crypto_engine,
            signer_verification_key_provider=provider,
        )
        now = datetime.now(timezone.utc)
        today_period = now.strftime("%Y-%m-%d")

        post = HolePost(
            id=str(uuid.uuid4()),
            content="Anonymity check post",
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

        # Execute create_comment
        comment_proof = CredentialProof(
            sn="12" * 16,
            service="hole_comment",
            period=today_period,
            signature=base64.b64encode(b"\x33" * 64).decode("ascii"),
        )
        service.create_comment(
            post_id=post.id,
            content="Anonymous comment content",
            credential=comment_proof,
            idempotency_key="anonymity-test-key-comment",
            now=now,
        )

        # Execute list_comments
        service.list_comments(post_id=post.id, page=1, page_size=20)

        # Execute like_post
        like_proof = CredentialProof(
            sn="13" * 16,
            service="hole_like",
            period=today_period,
            signature=base64.b64encode(b"\x44" * 64).decode("ascii"),
        )
        service.like_post(
            post_id=post.id,
            credential=like_proof,
            idempotency_key="anonymity-test-key-like",
            now=now,
        )

        # Ensure none of the forbidden tables were touched
        assert len(queried_tables) == 0, f"Forbidden tables were queried: {queried_tables}"
        session.close()

    def test_routes_accessible_without_token_and_with_bogus_token(self):
        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

        crypto_engine = DynamicMockCryptoEngine()
        provider = MockVerificationKeyProvider()

        app = create_app()

        def override_get_db():
            session = SessionLocal()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_crypto_engine] = lambda: crypto_engine
        app.dependency_overrides[get_signer_verification_key_provider] = lambda: provider

        init_session = SessionLocal()
        now = datetime.now(timezone.utc)
        today_period = now.strftime("%Y-%m-%d")
        post = HolePost(
            id=str(uuid.uuid4()),
            content="Route anonymity check post",
            credential_sn=bytes.fromhex("11" * 16),
            credential_service="hole_post",
            credential_period=today_period,
            credential_signature=b"\x11" * 64,
            credential_prefix="11" * 4,
            credential_valid=True,
            status="published",
            created_at=now,
        )
        init_session.add(post)
        init_session.commit()
        post_id = post.id
        init_session.close()

        client = TestClient(app)

        # 1. GET /posts/{post_id}/comments with no token -> 200
        r1 = client.get(f"/api/v1/hole/posts/{post_id}/comments")
        assert r1.status_code == 200

        # With bogus token -> still 200 (not rejected with 401 because it's purely public)
        r2 = client.get(
            f"/api/v1/hole/posts/{post_id}/comments",
            headers={"Authorization": "Bearer totally-fake-token-123"},
        )
        assert r2.status_code == 200

        # 2. POST /posts/{post_id}/comments with bogus token -> executes anonymously
        comment_proof = CredentialProof(
            sn="e1" * 16,
            service="hole_comment",
            period=today_period,
            signature=base64.b64encode(b"\x33" * 64).decode("ascii"),
        )
        r3 = client.post(
            f"/api/v1/hole/posts/{post_id}/comments",
            json={"content": "Anonymous comment", "credential": comment_proof.model_dump()},
            headers={
                "Idempotency-Key": "route-anonymity-comment-key",
                "Authorization": "Bearer totally-fake-token-123",
            },
        )
        assert r3.status_code == 201
        data = r3.json()
        assert "id" in data
        assert data["credential_prefix"] == "e1" * 4
        assert "user_id" not in data
        assert "signature" not in data
        assert "sn" not in data

        # 3. POST /posts/{post_id}/likes with bogus token -> executes anonymously
        like_proof = CredentialProof(
            sn="e2" * 16,
            service="hole_like",
            period=today_period,
            signature=base64.b64encode(b"\x44" * 64).decode("ascii"),
        )
        r4 = client.post(
            f"/api/v1/hole/posts/{post_id}/likes",
            json={"credential": like_proof.model_dump()},
            headers={
                "Idempotency-Key": "route-anonymity-like-key",
                "Authorization": "Bearer totally-fake-token-123",
            },
        )
        assert r4.status_code == 201
        assert r4.json() == {"accepted": True}
