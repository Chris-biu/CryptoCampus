import base64
from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.session import create_db_engine
from app.models.credential import ConsumedSN, CredentialIssueIdempotency, CredentialLedger
from app.models.hole import HolePost, HolePostIdempotency
from app.models.user import User
from app.schemas.credential import CredentialProof
from app.schemas.hole import CreateHolePostRequest, HolePost as HolePostSchema
from app.services.hole_posts import HolePostService


class FakeEngine:
    def blind_verify(self, *, message: bytes, signature: bytes, signer_public_key: bytes) -> bool:
        return True

    def sm3_digest(self, data: bytes) -> bytes:
        # Return 32-byte hash
        return bytes([(b + len(data)) % 256 for b in range(32)])


class FakeKeyProvider:
    def get_signer_public_key(self, service: str) -> bytes | None:
        return b"\x04" + b"\x01" * 64


@pytest.fixture
def test_db():
    engine = create_db_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_hole_post_schema_has_no_identity_or_audit_columns():
    """HolePost 严禁包含 user_id、author_id、email、session_id、ip、device 等身份字段"""
    mapper = sa_inspect(HolePost)
    column_names = {col.key for col in mapper.columns}
    forbidden_columns = {
        "user_id",
        "author_id",
        "user",
        "author",
        "email",
        "session_id",
        "ip",
        "device",
        "issuance_id",
        "credential_ledger_id",
        "blinding_factor",
    }
    intersect = column_names.intersection(forbidden_columns)
    assert not intersect, f"HolePost contains forbidden identity columns: {intersect}"

    # Verify no foreign keys pointing to users or credential_ledger
    for fk in mapper.tables[0].foreign_keys:
        assert fk.column.table.name not in ("users", "credential_ledger", "credential_issue_idempotency")


def test_consumed_sn_has_no_identity_or_issuance_columns():
    """ConsumedSN 严禁包含 user_id、credential_ledger_id、issuance_id 等字段"""
    mapper = sa_inspect(ConsumedSN)
    column_names = {col.key for col in mapper.columns}
    forbidden_columns = {
        "user_id",
        "credential_ledger_id",
        "issuance_id",
        "email",
        "ip",
        "device",
    }
    intersect = column_names.intersection(forbidden_columns)
    assert not intersect, f"ConsumedSN contains forbidden columns: {intersect}"

    for fk in mapper.tables[0].foreign_keys:
        assert fk.column.table.name not in ("users", "credential_ledger", "credential_issue_idempotency")


def test_hole_post_idempotency_has_no_identity_columns():
    """HolePostIdempotency 严禁包含 user_id、author_id、ip、device 等身份字段"""
    mapper = sa_inspect(HolePostIdempotency)
    column_names = {col.key for col in mapper.columns}
    forbidden_columns = {
        "user_id",
        "author_id",
        "ip",
        "device",
        "session_id",
    }
    intersect = column_names.intersection(forbidden_columns)
    assert not intersect, f"HolePostIdempotency contains forbidden columns: {intersect}"


def test_published_post_api_response_schema_reveals_only_prefix():
    """API 响应只公开 credential_prefix (前8字符) 与 credential_valid，不泄露完整 SN 或签名"""
    sn = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    raw_sig = b"\x05" * 64
    b64_sig = base64.b64encode(raw_sig).decode("ascii")
    proof = CredentialProof(
        sn=sn,
        service="hole_post",
        period="2026-09-09",
        signature=b64_sig,
    )
    post = HolePost(
        id="test-post-uuid-1",
        content="匿名树洞内容",
        credential_sn=bytes.fromhex(sn),
        credential_service="hole_post",
        credential_period="2026-09-09",
        credential_signature=raw_sig,
        credential_prefix=sn[:8],
        credential_valid=True,
        status="published",
        created_at=datetime.now(timezone.utc),
    )
    schema = HolePostSchema.model_validate(post)
    dumped = schema.model_dump()

    # Must contain exactly the public contract fields
    assert set(dumped.keys()) == {
        "id",
        "content",
        "created_at",
        "credential_prefix",
        "credential_valid",
        "status",
    }
    assert dumped["credential_prefix"] == sn[:8]
    assert dumped["credential_valid"] is True
    assert dumped["status"] == "published"
    # Ensure full sn and signature are NOT in dumped response
    assert sn not in str(dumped)
    assert b64_sig not in str(dumped)
    assert raw_sig.hex() not in str(dumped)


def test_anonymous_publishing_does_not_mutate_or_query_user_or_ledger(test_db):
    """验证匿名发帖完全独立于 CredentialLedger 和 CredentialIssueIdempotency"""
    # Create an initial user and ledger
    user = User(
        email="student@university.edu",
        role="student",
        cert_serial="ABCDEF123456",
        status="active",
    )
    test_db.add(user)
    test_db.flush()

    ledger = CredentialLedger(
        user_id=user.id,
        service="hole_post",
        period="2026-09-09",
        issued_count=1,
    )
    test_db.add(ledger)
    test_db.commit()

    initial_ledgers_count = test_db.query(CredentialLedger).count()
    initial_idempotency_count = test_db.query(CredentialIssueIdempotency).count()

    # Now execute anonymous hole post publishing
    service = HolePostService(
        session=test_db,
        crypto_engine=FakeEngine(),
        signer_verification_key_provider=FakeKeyProvider(),
    )
    sn = "ffff0000111122223333444455556666"
    b64_sig = base64.b64encode(b"\x01" * 64).decode("ascii")
    proof = CredentialProof(
        sn=sn,
        service="hole_post",
        period="2026-09-09",
        signature=b64_sig,
    )
    post = service.publish(
        content="匿名内容不关联任何用户",
        credential=proof,
        idempotency_key="anon-idempotency-key-123456",
        now=datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc),
    )

    assert post.id is not None
    # Ledger and IssueIdempotency must be completely unchanged
    assert test_db.query(CredentialLedger).count() == initial_ledgers_count
    assert test_db.query(CredentialIssueIdempotency).count() == initial_idempotency_count

    # Verify ConsumedSN is inserted anonymously
    consumed = test_db.query(ConsumedSN).filter_by(sn=bytes.fromhex(sn), service="hole_post").first()
    assert consumed is not None
    assert not hasattr(consumed, "user_id")
