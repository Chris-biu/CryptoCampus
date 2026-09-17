import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.dependencies import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE, SM2_PUBLIC_KEY_SIZE
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app
from app.models.audit import AuditLog
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.models.vote import AnonymousBallot, BallotIdempotency, VoteOption, VoteRecord, VoteResultSnapshot
from app.services.vote_ballot_verification import encode_vote_ballot_message
from app.services.vote_signer import get_vote_signer_provider
from app.services.vote_tally_provider import VoteTallyMaterial, get_vote_tally_provider


class AnonymityMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.valid_signatures: set[tuple[bytes, bytes, bytes]] = set()

    def add_valid_signature(self, message: bytes, signature: bytes, public_key: bytes) -> None:
        self.valid_signatures.add((message, signature, public_key))

    def blind_verify(self, *, message: bytes, signature: bytes, signer_public_key: bytes) -> bool:
        return (message, signature, signer_public_key) in self.valid_signatures

    def sm3_digest(self, message: bytes) -> bytes:
        import hashlib
        return hashlib.sha256(message).digest()

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right

    def sm2_sign(self, private_key: bytes, digest: bytes) -> bytes:
        return b"\x88" * 64

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        return len(signature) == 64 and signature == (b"\x88" * 64)


class MockSignerProvider:
    def __init__(self, key_map: dict[str, bytes]) -> None:
        self.key_map = key_map

    def get_signer_private_key(self, *, vote_id: str) -> bytes | None:
        return None

    def get_signer_public_key(self, *, vote_id: str) -> bytes | None:
        return self.key_map.get(vote_id)


class MockTallyProvider:
    def __init__(self, material: VoteTallyMaterial) -> None:
        self.material = material

    @contextmanager
    def unlocked(self):
        yield self.material


def test_schema_anonymity_strict_column_audit():
    """Audit database model columns to prove no voter identity columns exist."""
    forbidden_substrings = ("user", "voter", "creator", "ip", "session", "agent", "token", "header")

    # 1. AnonymousBallot
    ballot_cols = {c.name for c in AnonymousBallot.__table__.columns}
    assert ballot_cols == {
        "id",
        "vote_id",
        "option_id",
        "credential_sn",
        "credential_service",
        "credential_period",
        "credential_signature",
        "created_at",
    }
    for col in ballot_cols:
        for bad in forbidden_substrings:
            assert bad not in col.lower(), f"Forbidden identifier '{bad}' in AnonymousBallot column '{col}'"

    # 2. BallotIdempotency
    idemp_cols = {c.name for c in BallotIdempotency.__table__.columns}
    assert idemp_cols == {"id", "key_hash", "request_hash", "ballot_id", "created_at"}
    for col in idemp_cols:
        for bad in forbidden_substrings:
            assert bad not in col.lower(), f"Forbidden identifier '{bad}' in BallotIdempotency column '{col}'"

    # 3. VoteResultSnapshot
    snapshot_cols = {c.name for c in VoteResultSnapshot.__table__.columns}
    assert snapshot_cols == {
        "id",
        "vote_id",
        "version",
        "counts_json",
        "total",
        "result_digest",
        "signature",
        "signer_certificate",
        "signer_public_key",
        "published_at",
        "is_final",
    }
    for col in snapshot_cols:
        for bad in forbidden_substrings:
            assert bad not in col.lower(), f"Forbidden identifier '{bad}' in VoteResultSnapshot column '{col}'"


def test_runtime_sql_query_audit_zero_identity_leakage():
    """Execute real ballot submission and assert SQL cursor never touches identity tables."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    now = datetime.now(timezone.utc)
    creator = User(id=str(uuid.uuid4()), email="creator@campus.edu.cn", role="teacher", status="active")
    sys_user = User(id=str(uuid.uuid4()), email="sys_tally@campus.edu.cn", role="system", status="active")
    session.add_all([creator, sys_user])
    session.commit()

    vote = VoteRecord(
        id=str(uuid.uuid4()),
        creator_id=creator.id,
        title="匿名计票 SQL 审计",
        scope="public",
        closes_at=now + timedelta(days=1),
        status="open",
        created_at=now,
    )
    opt1 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="A", position=0)
    opt2 = VoteOption(id=str(uuid.uuid4()), vote_id=vote.id, label="B", position=1)
    session.add_all([vote, opt1, opt2])
    session.commit()

    vote_pubkey = b"\x04" + b"\x44" * (SM2_PUBLIC_KEY_SIZE - 1)
    signer_provider = MockSignerProvider({vote.id: vote_pubkey})

    tally_mat = VoteTallyMaterial(
        system_user_id=sys_user.id,
        certificate_serial="tally-audit-01",
        certificate_der=b"DER-AUDIT",
        public_key=b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1),
        private_key=b"\x12" * SM2_PRIVATE_KEY_SIZE,
    )
    tally_provider = MockTallyProvider(tally_mat)
    crypto = AnonymityMockCryptoEngine()

    sn_hex = "abcdef0123456789abcdef0123456789"
    sig_bytes = b"\x77" * 64
    msg = encode_vote_ballot_message(sn_hex=sn_hex, service="vote_ballot", vote_id=vote.id, option_id=opt1.id)
    crypto.add_valid_signature(msg, sig_bytes, vote_pubkey)

    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_crypto_engine] = lambda: crypto
    app.dependency_overrides[get_vote_signer_provider] = lambda: signer_provider
    app.dependency_overrides[get_vote_tally_provider] = lambda: tally_provider

    # Track all executed SQL statements
    executed_statements: list[str] = []

    def before_cursor_execute_listener(conn, cursor, statement, parameters, context, executemany):
        executed_statements.append(statement)

    event.listen(engine, "before_cursor_execute", before_cursor_execute_listener)

    client = TestClient(app)
    res = client.post(
        f"/api/v1/votes/{vote.id}/ballots",
        headers={"Idempotency-Key": "idemp-sql-audit-0000000001"},
        json={
            "option_id": opt1.id,
            "credential": {
                "sn": sn_hex,
                "service": "vote_ballot",
                "period": vote.id,
                "signature": base64.b64encode(sig_bytes).decode("ascii"),
            },
        },
    )
    assert res.status_code == 201

    # Remove listener
    event.remove(engine, "before_cursor_execute", before_cursor_execute_listener)

    # Assert executed statements exist
    assert len(executed_statements) > 0

    forbidden_tables = [
        "users",
        "user_sessions",
        "vote_credential_issues",
        "credential_ledger",
        "credential_issue_idempotency",
    ]

    for stmt in executed_statements:
        normalized = stmt.lower()
        for forbidden in forbidden_tables:
            assert forbidden not in normalized, (
                f"Privacy violation: SQL statement touched forbidden identity table '{forbidden}':\n{stmt}"
            )

    # Also verify AuditLog operator is tally station system user, not voter
    audit_logs = session.query(AuditLog).filter_by(action="vote.result.sign").all()
    assert len(audit_logs) == 1
    assert audit_logs[0].actor == sys_user.id
