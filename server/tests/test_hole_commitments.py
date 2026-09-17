import base64
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE
from app.db.base import Base
from app.db.session import get_db
from app.crypto.dependencies import get_crypto_engine
from app.main import create_app
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_roles
from app.services.signer_provider import (
    ServerSignerKeyProvider,
    ServerSignerVerificationKeyProvider,
    get_signer_key_provider,
    get_signer_verification_key_provider,
)
from app.services.commitment_store import BlindCommitmentStore, get_commitment_store


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


class MockSignerProvider(ServerSignerKeyProvider, ServerSignerVerificationKeyProvider):
    def __init__(self) -> None:
        self.priv = b"\x11" * SM2_PRIVATE_KEY_SIZE
        self.pub = b"\x04" + b"\x22" * 64

    def get_signer_private_key(self, service: str) -> bytes | None:
        return self.priv

    def get_signer_public_key(self, service: str) -> bytes | None:
        return self.pub


@pytest.fixture
def commitments_env():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    db = session_factory()

    now = datetime.now(timezone.utc)
    user = User(
        id="u-commitment-test-1",
        email="test_student@campus.edu",
        role="student",
        status="active",
        created_at=now,
    )
    db.add(user)
    db.commit()

    crypto = DynamicMockCryptoEngine()
    crypto.set_result("blind_sign", b"\x66" * 64)
    signer_provider = MockSignerProvider()
    test_commitment_store = BlindCommitmentStore(default_ttl_seconds=300)

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_signer_key_provider] = lambda: signer_provider
    app.dependency_overrides[get_signer_verification_key_provider] = lambda: signer_provider
    app.dependency_overrides[get_commitment_store] = lambda: test_commitment_store

    from app.security.auth_dependencies import require_authenticated_user

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=user.id,
        role="student",
        status="active",
    )

    client = TestClient(app)
    yield {
        "client": client,
        "db": db,
        "crypto": crypto,
        "user": user,
        "store": test_commitment_store,
        "now": now,
    }
    db.close()
    Base.metadata.drop_all(bind=engine)


def test_create_commitment_success(commitments_env):
    client = commitments_env["client"]
    now = datetime.now(timezone.utc)
    period = now.date().isoformat()

    resp = client.post(
        "/api/v1/hole/credentials/commitments",
        json={"service": "hole_post", "period": period},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "commitment_id" in data
    assert len(data["commitment_id"]) == 32  # 16-byte hex
    assert "commitment_point" in data
    assert len(base64.b64decode(data["commitment_point"])) == 65  # SM2 uncompressed point
    assert "expires_at" in data


def test_create_commitment_rejects_invalid_period(commitments_env):
    client = commitments_env["client"]
    resp = client.post(
        "/api/v1/hole/credentials/commitments",
        json={"service": "hole_post", "period": "2020-01-01"},
    )
    assert resp.status_code == 422


def test_commitment_two_round_issue_and_anti_replay(commitments_env):
    client = commitments_env["client"]
    now = datetime.now(timezone.utc)
    period = now.date().isoformat()

    # 1. Round 1: Create commitment
    comm_resp = client.post(
        "/api/v1/hole/credentials/commitments",
        json={"service": "hole_post", "period": period},
    )
    assert comm_resp.status_code == 201
    comm_data = comm_resp.json()
    commitment_id = comm_data["commitment_id"]
    cid_bytes = bytes.fromhex(commitment_id)
    assert len(cid_bytes) == 16

    # 2. Round 2: Pack commitment_id (16B) || c_prime (32B) = 48B payload
    c_prime = b"\xaa" * 32
    payload_48b = cid_bytes + c_prime
    blinded_b64 = base64.b64encode(payload_48b).decode("ascii")

    # Issue credential with this commitment
    issue_resp = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "idemp-key-round-01"},
        json={
            "service": "hole_post",
            "period": period,
            "blinded_message": blinded_b64,
        },
    )
    assert issue_resp.status_code == 201
    assert "blind_signature" in issue_resp.json()

    # 3. Replay attack with same commitment_id must be rejected (422)
    replay_resp = client.post(
        "/api/v1/hole/credentials",
        headers={"Idempotency-Key": "idemp-key-round-02-new"},
        json={
            "service": "hole_post",
            "period": period,
            "blinded_message": blinded_b64,
        },
    )
    assert replay_resp.status_code == 422
    assert "commitment" in replay_resp.text.lower() or "已被使用" in replay_resp.text or "校验失败" in replay_resp.text
