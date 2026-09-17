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
from app.models.hole import HoleLike, HoleLikeIdempotency, HolePost
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
        content="Published post for likes",
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


def _make_like_proof(sn_hex: str = "33" * 16, period: str | None = None, sig_bytes: bytes = b"\x33" * 64) -> CredentialProof:
    if period is None:
        period = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return CredentialProof(
        sn=sn_hex,
        service="hole_like",
        period=period,
        signature=base64.b64encode(sig_bytes).decode("ascii"),
    )


class TestHoleLikesService:
    def test_like_post_success(self):
        session, crypto_engine, provider, service, post, now, today_period = _setup_service()
        proof = _make_like_proof()
        idemp_key = "test-idempotency-key-001"

        service.like_post(
            post_id=post.id,
            credential=proof,
            idempotency_key=idemp_key,
            now=now,
        )

        # Check ConsumedSN
        sn_bytes = bytes.fromhex(proof.sn)
        consumed = session.get(ConsumedSN, (sn_bytes, "hole_like"))
        assert consumed is not None
        assert consumed.service == "hole_like"

        # Check HoleLike
        likes = session.query(HoleLike).filter_by(post_id=post.id).all()
        assert len(likes) == 1
        assert likes[0].credential_sn == sn_bytes
        assert likes[0].credential_service == "hole_like"
        assert likes[0].credential_period == today_period

        # Check HoleLikeIdempotency
        idemp = session.query(HoleLikeIdempotency).all()
        assert len(idemp) == 1
        assert idemp[0].like_id == likes[0].id

    def test_like_post_unpublished_or_missing_post(self):
        session, crypto_engine, provider, service, post, now, today_period = _setup_service()
        proof = _make_like_proof()
        idemp_key = "test-idempotency-key-002"

        # Nonexistent post
        fake_post_id = str(uuid.uuid4())
        with pytest.raises(HoleInteractionServiceError) as exc_info:
            service.like_post(
                post_id=fake_post_id,
                credential=proof,
                idempotency_key=idemp_key,
                now=now,
            )
        assert exc_info.value.code == "post_not_available"

        # Withdrawn post
        post.status = "withdrawn"
        session.commit()
        with pytest.raises(HoleInteractionServiceError) as exc_info:
            service.like_post(
                post_id=post.id,
                credential=proof,
                idempotency_key=idemp_key,
                now=now,
            )
        assert exc_info.value.code == "post_not_available"

        # No consumed SN or likes
        assert session.query(ConsumedSN).count() == 0
        assert session.query(HoleLike).count() == 0

    def test_like_post_invalid_credential_service(self):
        session, crypto_engine, provider, service, post, now, today_period = _setup_service()
        proof = CredentialProof(
            sn="33" * 16,
            service="hole_comment",  # wrong service
            period=today_period,
            signature=base64.b64encode(b"\x33" * 64).decode("ascii"),
        )
        with pytest.raises(HoleInteractionServiceError) as exc_info:
            service.like_post(
                post_id=post.id,
                credential=proof,
                idempotency_key="test-idempotency-key-003",
                now=now,
            )
        assert exc_info.value.code == "invalid_service"

    def test_like_post_idempotency_replay_and_conflict(self):
        session, crypto_engine, provider, service, post, now, today_period = _setup_service()
        proof1 = _make_like_proof(sn_hex="33" * 16)
        idemp_key = "test-idempotency-key-004"

        # 1. First like
        service.like_post(
            post_id=post.id,
            credential=proof1,
            idempotency_key=idemp_key,
            now=now,
        )
        assert session.query(HoleLike).count() == 1

        # 2. Replay same request -> succeeds without creating new row
        service.like_post(
            post_id=post.id,
            credential=proof1,
            idempotency_key=idemp_key,
            now=now,
        )
        assert session.query(HoleLike).count() == 1

        # 3. Same key, different post_id -> conflict 409
        post2 = HolePost(
            id=str(uuid.uuid4()),
            content="Post 2",
            credential_sn=bytes.fromhex("22" * 16),
            credential_service="hole_post",
            credential_period=today_period,
            credential_signature=b"\x22" * 64,
            credential_prefix="22" * 4,
            credential_valid=True,
            status="published",
            created_at=now,
        )
        session.add(post2)
        session.commit()

        with pytest.raises(HoleInteractionServiceError) as exc_info:
            service.like_post(
                post_id=post2.id,
                credential=proof1,
                idempotency_key=idemp_key,
                now=now,
            )
        assert exc_info.value.code == "idempotency_conflict"

        # 4. Same key, different credential -> conflict 409
        proof2 = _make_like_proof(sn_hex="44" * 16)
        with pytest.raises(HoleInteractionServiceError) as exc_info:
            service.like_post(
                post_id=post.id,
                credential=proof2,
                idempotency_key=idemp_key,
                now=now,
            )
        assert exc_info.value.code == "idempotency_conflict"

    def test_like_post_credential_consumed_with_new_key(self):
        session, crypto_engine, provider, service, post, now, today_period = _setup_service()
        proof = _make_like_proof()

        service.like_post(
            post_id=post.id,
            credential=proof,
            idempotency_key="test-idempotency-key-005a",
            now=now,
        )

        # Same credential, new key -> credential_consumed
        with pytest.raises(HoleInteractionServiceError) as exc_info:
            service.like_post(
                post_id=post.id,
                credential=proof,
                idempotency_key="test-idempotency-key-005b",
                now=now,
            )
        assert exc_info.value.code == "credential_consumed"

    def test_like_post_rollback_on_failure(self):
        session, crypto_engine, provider, service, post, now, today_period = _setup_service()
        proof = _make_like_proof()

        # Inject failure during transaction flush
        orig_flush = session.flush

        def mock_flush():
            orig_flush()
            raise RuntimeError("DB failure simulation")

        session.flush = mock_flush

        with pytest.raises(RuntimeError, match="DB failure simulation"):
            service.like_post(
                post_id=post.id,
                credential=proof,
                idempotency_key="test-idempotency-key-006",
                now=now,
            )

        session.flush = orig_flush
        assert session.query(ConsumedSN).count() == 0
        assert session.query(HoleLike).count() == 0
        assert session.query(HoleLikeIdempotency).count() == 0

    def test_like_post_concurrency(self):
        import tempfile
        import threading
        from pathlib import Path
        from concurrent.futures import as_completed

        class ThreadSafeMockCryptoEngine(DynamicMockCryptoEngine):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._lock = threading.Lock()

            def sm3_digest(self, message: bytes) -> bytes:
                with self._lock:
                    return super().sm3_digest(message)

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_file = Path(tmp_dir) / "concurrency_likes_test.db"
            db_url = f"sqlite:///{db_file}"

            engine = create_engine(
                db_url,
                connect_args={"check_same_thread": False, "timeout": 30.0},
            )
            with engine.connect() as conn:
                conn.exec_driver_sql("PRAGMA journal_mode=WAL")
                conn.exec_driver_sql("PRAGMA busy_timeout=30000")

            Base.metadata.create_all(engine)
            session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

            init_session = session_factory()
            now = datetime.now(timezone.utc)
            today_period = now.strftime("%Y-%m-%d")
            post = HolePost(
                id=str(uuid.uuid4()),
                content="Post for concurrent likes",
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

            crypto_engine = ThreadSafeMockCryptoEngine()
            provider = MockVerificationKeyProvider()
            proof = _make_like_proof()

            num_threads = 10
            successes = []
            failures = []

            def do_like(i: int):
                sess = session_factory()
                srv = HoleInteractionService(
                    session=sess,
                    crypto_engine=crypto_engine,
                    signer_verification_key_provider=provider,
                )
                try:
                    srv.like_post(
                        post_id=post_id,
                        credential=proof,
                        idempotency_key=f"concurrent-idemp-key-{i:04d}",
                        now=now,
                    )
                    return ("success", i)
                except Exception as e:
                    return ("failure", type(e).__name__, getattr(e, "code", str(e)))
                finally:
                    sess.close()

            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = [executor.submit(do_like, i) for i in range(num_threads)]
                for future in as_completed(futures):
                    res = future.result()
                    if res[0] == "success":
                        successes.append(res)
                    else:
                        failures.append(res)

            assert len(successes) == 1, f"Expected 1 success, got {len(successes)}: {successes}"
            assert len(failures) == num_threads - 1

            check_session = session_factory()
            try:
                assert check_session.query(ConsumedSN).count() == 1
                assert check_session.query(HoleLike).count() == 1
                assert check_session.query(HoleLikeIdempotency).count() == 1
            finally:
                check_session.close()
                engine.dispose()


class TestHoleLikesRoutes:
    def _create_app_client(self):
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
        post = HolePost(
            id=str(uuid.uuid4()),
            content="Route test post",
            credential_sn=bytes.fromhex("11" * 16),
            credential_service="hole_post",
            credential_period=now.strftime("%Y-%m-%d"),
            credential_signature=b"\x11" * 64,
            credential_prefix="11" * 4,
            credential_valid=True,
            status="published",
            created_at=now,
        )
        init_session.add(post)
        init_session.commit()
        init_session.close()

        client = TestClient(app)
        return client, post.id, SessionLocal

    def test_post_likes_endpoint_201_accepted(self):
        client, post_id, SessionLocal = self._create_app_client()
        proof = _make_like_proof()

        resp = client.post(
            f"/api/v1/hole/posts/{post_id}/likes",
            json={"credential": proof.model_dump()},
            headers={"Idempotency-Key": "test-key-likes-endpoint-001"},
        )
        assert resp.status_code == 201
        assert resp.json() == {"accepted": True}

    def test_post_likes_endpoint_extra_field_forbidden(self):
        client, post_id, SessionLocal = self._create_app_client()
        proof = _make_like_proof()

        resp = client.post(
            f"/api/v1/hole/posts/{post_id}/likes",
            json={"credential": proof.model_dump(), "extra_field": "disallowed"},
            headers={"Idempotency-Key": "test-key-likes-endpoint-002"},
        )
        assert resp.status_code == 422

    def test_post_likes_endpoint_invalid_uuid(self):
        client, post_id, SessionLocal = self._create_app_client()
        proof = _make_like_proof()

        resp = client.post(
            "/api/v1/hole/posts/not-a-valid-uuid/likes",
            json={"credential": proof.model_dump()},
            headers={"Idempotency-Key": "test-key-likes-endpoint-003"},
        )
        assert resp.status_code == 422

    def test_post_likes_endpoint_idempotency_and_replay(self):
        client, post_id, SessionLocal = self._create_app_client()
        proof = _make_like_proof()
        headers = {"Idempotency-Key": "test-key-likes-endpoint-004"}

        resp1 = client.post(
            f"/api/v1/hole/posts/{post_id}/likes",
            json={"credential": proof.model_dump()},
            headers=headers,
        )
        assert resp1.status_code == 201
        assert resp1.json() == {"accepted": True}

        # Replay
        resp2 = client.post(
            f"/api/v1/hole/posts/{post_id}/likes",
            json={"credential": proof.model_dump()},
            headers=headers,
        )
        assert resp2.status_code == 201
        assert resp2.json() == {"accepted": True}

        # Conflict with different credential
        proof_diff = _make_like_proof(sn_hex="55" * 16)
        resp3 = client.post(
            f"/api/v1/hole/posts/{post_id}/likes",
            json={"credential": proof_diff.model_dump()},
            headers=headers,
        )
        assert resp3.status_code == 409
