import base64
from datetime import datetime, timedelta, timezone
import json
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE, SM2_PUBLIC_KEY_SIZE
from app.db.session import get_db
from app.main import create_app
from app.models.credential import ConsumedSN
from app.models.user import User
from app.models.vote import (
    AnonymousBallot,
    VoteOption,
    VoteRecord,
    VoteResultSnapshot,
)
from app.services.vote_results import sign_vote_result
from app.services.vote_tally_provider import VoteTallyMaterial


class AuditMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        import hashlib
        return hashlib.sha256(message).digest()

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right

    def sm2_sign(self, private_key: bytes, digest: bytes) -> bytes:
        return b"\x66" * 64

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        return signature == (b"\x66" * 64)


@pytest.fixture
def test_setup(db_session: Session):
    creator = User(email="creator_audit@example.com", role="teacher", status="active")
    db_session.add(creator)
    db_session.commit()

    t0 = datetime(2026, 9, 10, 8, 0, 0, tzinfo=timezone.utc)
    closes_at = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Published vote with 2 ballots
    snap_published_id = str(uuid.uuid4())
    v_published = VoteRecord(
        creator_id=creator.id,
        title="已公示审计投票",
        scope="public",
        closes_at=closes_at,
        status="published",
        created_at=t0,
        settled_at=closes_at,
        final_snapshot_id=snap_published_id,
    )
    db_session.add(v_published)
    db_session.commit()

    opt1 = VoteOption(vote_id=v_published.id, label="A", position=0)
    opt2 = VoteOption(vote_id=v_published.id, label="B", position=1)
    db_session.add_all([opt1, opt2])
    db_session.commit()

    # Add 2 ballots with unordered SNs
    # b_high with SN ff...
    # b_low with SN 01...
    sn_high = bytes.fromhex("ff" * 16)
    sn_low = bytes.fromhex("01" * 16)
    b_high = AnonymousBallot(
        vote_id=v_published.id,
        option_id=opt1.id,
        credential_sn=sn_high,
        credential_service="vote_ballot",
        credential_period="2026-09",
        credential_signature=b"\x88" * 64,
        created_at=closes_at - timedelta(minutes=5),
    )
    b_low = AnonymousBallot(
        vote_id=v_published.id,
        option_id=opt2.id,
        credential_sn=sn_low,
        credential_service="vote_ballot",
        credential_period="2026-09",
        credential_signature=b"\x77" * 64,
        created_at=closes_at - timedelta(minutes=2),
    )
    db_session.add_all([b_high, b_low])
    db_session.commit()

    final_snap = VoteResultSnapshot(
        id=snap_published_id,
        vote_id=v_published.id,
        version=3,
        counts_json=json.dumps({opt1.id: 1, opt2.id: 1}),
        total=2,
        result_digest=b"\xdd" * 32,
        signature=b"\x66" * 64,
        signer_certificate=b"DER-CERT",
        signer_public_key=b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1),
        published_at=closes_at,
        is_final=True,
    )
    db_session.add(final_snap)
    db_session.commit()

    # 2. Open / Unsettled vote
    v_open = VoteRecord(
        creator_id=creator.id,
        title="未截止投票",
        scope="public",
        closes_at=closes_at + timedelta(hours=5),
        status="open",
        created_at=t0,
    )
    db_session.add(v_open)
    db_session.commit()

    from app.models.vote import VoteScopeUnit
    scope_unit = VoteScopeUnit(kind="class", name="班级1", active=True)
    db_session.add(scope_unit)
    db_session.commit()

    # 3. Non-public vote
    snap_class_id = str(uuid.uuid4())
    v_class = VoteRecord(
        creator_id=creator.id,
        title="班级内部投票",
        scope="class",
        scope_id=scope_unit.id,
        closes_at=closes_at,
        status="published",
        created_at=t0,
        settled_at=closes_at,
        final_snapshot_id=snap_class_id,
    )
    db_session.add(v_class)
    db_session.commit()

    snap_class = VoteResultSnapshot(
        id=snap_class_id,
        vote_id=v_class.id,
        version=1,
        counts_json=json.dumps({}),
        total=0,
        result_digest=b"\x00" * 32,
        signature=b"\x66" * 64,
        signer_certificate=b"DER-CERT",
        signer_public_key=b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1),
        published_at=closes_at,
        is_final=True,
    )
    db_session.add(snap_class)
    db_session.commit()

    # 4. Zero-ballot published vote
    snap_zero_id = str(uuid.uuid4())
    v_zero = VoteRecord(
        creator_id=creator.id,
        title="零票已结算投票",
        scope="public",
        closes_at=closes_at,
        status="published",
        created_at=t0,
        settled_at=closes_at,
        final_snapshot_id=snap_zero_id,
    )
    db_session.add(v_zero)
    db_session.commit()

    snap_zero = VoteResultSnapshot(
        id=snap_zero_id,
        vote_id=v_zero.id,
        version=1,
        counts_json=json.dumps({}),
        total=0,
        result_digest=b"\x00" * 32,
        signature=b"\x66" * 64,
        signer_certificate=b"DER-CERT",
        signer_public_key=b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1),
        published_at=closes_at,
        is_final=True,
    )
    db_session.add(snap_zero)
    db_session.commit()

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)

    return {
        "client": client,
        "v_published_id": v_published.id,
        "v_open_id": v_open.id,
        "v_class_id": v_class.id,
        "v_zero_id": v_zero.id,
        "final_snap": final_snap,
    }


def test_vote_audit_not_found(test_setup):
    client: TestClient = test_setup["client"]
    resp = client.get(f"/api/v1/votes/{uuid.uuid4()}/audit")
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"


def test_vote_audit_hidden_scope_not_found(test_setup):
    client: TestClient = test_setup["client"]
    v_class_id = test_setup["v_class_id"]
    resp = client.get(f"/api/v1/votes/{v_class_id}/audit")
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"


def test_vote_audit_unsettled_vote_conflict(test_setup):
    client: TestClient = test_setup["client"]
    v_open_id = test_setup["v_open_id"]
    resp = client.get(f"/api/v1/votes/{v_open_id}/audit")
    assert resp.status_code == 409
    assert resp.json()["code"] == "CONFLICT"


def test_vote_audit_zero_ballots_succeeds(test_setup):
    client: TestClient = test_setup["client"]
    v_zero_id = test_setup["v_zero_id"]
    resp = client.get(f"/api/v1/votes/{v_zero_id}/audit")
    assert resp.status_code == 200
    data = resp.json()
    assert data["vote_id"] == v_zero_id
    assert data["ballots"] == []
    assert data["total"] == 0
    assert data["result_signature"] == base64.b64encode(b"\x66" * 64).decode("ascii")


def test_vote_audit_success_ordering_and_values(test_setup):
    client: TestClient = test_setup["client"]
    v_published_id = test_setup["v_published_id"]
    final_snap = test_setup["final_snap"]

    resp = client.get(f"/api/v1/votes/{v_published_id}/audit")
    assert resp.status_code == 200
    data = resp.json()

    assert data["vote_id"] == v_published_id
    assert data["total"] == 2
    assert data["result_signature"] == base64.b64encode(final_snap.signature).decode("ascii")

    ballots = data["ballots"]
    assert len(ballots) == 2

    # Verify order is strictly sn ASC
    assert ballots[0]["sn"] == ("01" * 16)
    assert ballots[1]["sn"] == ("ff" * 16)
    assert ballots[0]["valid"] is True
    assert ballots[1]["valid"] is True
    assert ballots[0]["signature"] == base64.b64encode(b"\x77" * 64).decode("ascii")
    assert ballots[1]["signature"] == base64.b64encode(b"\x88" * 64).decode("ascii")


def test_vote_audit_strict_anonymity_and_public_access(test_setup):
    client: TestClient = test_setup["client"]
    v_published_id = test_setup["v_published_id"]

    # Test with invalid auth header: MUST ignore and return 200 without leaking
    resp = client.get(
        f"/api/v1/votes/{v_published_id}/audit",
        headers={"Authorization": "Bearer invalid.token.payload"},
    )
    assert resp.status_code == 200
    raw_text = resp.text

    forbidden_substrings = [
        "user_id",
        "creator_id",
        "creator_audit",
        "email",
        "session_id",
        "voter_identity",
        "ip",
        "private_key",
        "token",
    ]
    for bad in forbidden_substrings:
        assert bad not in raw_text, f"Audit report response leaked forbidden substring: {bad}"
