from datetime import datetime, timezone
import hashlib
import uuid
import pytest

from app.crypto.mock import MockCryptoEngine
from app.models.user import User


class DeterministicMockCryptoEngine(MockCryptoEngine):
    def sm3_digest(self, message: bytes) -> bytes:
        return hashlib.sha256(b"mock-sm3-digest:" + message).digest()


def test_admin_audit_canonical_encoding_structure() -> None:
    from app.services.admin_audit import encode_admin_audit_entry, DOMAIN_TAG

    actor_uuid = uuid.UUID("11111111-2222-3333-4444-555555555555")
    hash_prev = b"\x00" * 32
    detail_hash = b"\xaa" * 32
    timestamp = datetime(2026, 9, 10, 12, 0, 0, 123456, tzinfo=timezone.utc)
    action = "user.freeze"
    target = "user:11111111-2222-3333-4444-555555555555"

    encoded = encode_admin_audit_entry(
        hash_prev=hash_prev,
        actor_id=str(actor_uuid),
        action=action,
        target=target,
        detail_hash=detail_hash,
        timestamp=timestamp,
    )

    # 1. Domain tag: len(DOMAIN_TAG) bytes (ASCII "CryptoCampus-Admin-Audit-v1\x00")
    assert encoded[: len(DOMAIN_TAG)] == DOMAIN_TAG
    assert DOMAIN_TAG == b"CryptoCampus-Admin-Audit-v1\x00"
    offset = len(DOMAIN_TAG)

    # 2. hash_prev: 32 bytes
    assert encoded[offset : offset + 32] == hash_prev
    offset += 32

    # 3. actor_uuid: 16 bytes
    assert encoded[offset : offset + 16] == actor_uuid.bytes
    offset += 16

    # 4. len(action:uint32be) + action_utf8
    action_bytes = action.encode("utf-8")
    action_len = int.from_bytes(encoded[offset : offset + 4], "big")
    assert action_len == len(action_bytes)
    offset += 4
    assert encoded[offset : offset + action_len] == action_bytes
    offset += action_len

    # 5. len(target:uint32be) + target_utf8
    target_bytes = target.encode("utf-8")
    target_len = int.from_bytes(encoded[offset : offset + 4], "big")
    assert target_len == len(target_bytes)
    offset += 4
    assert encoded[offset : offset + target_len] == target_bytes
    offset += target_len

    # 6. detail_hash: 32 bytes
    assert encoded[offset : offset + 32] == detail_hash
    offset += 32

    # 7. len(timestamp:uint32be) + timestamp_utf8 ("2026-09-10T12:00:00.123456Z")
    ts_bytes = b"2026-09-10T12:00:00.123456Z"
    ts_len = int.from_bytes(encoded[offset : offset + 4], "big")
    assert ts_len == len(ts_bytes)
    offset += 4
    assert encoded[offset : offset + ts_len] == ts_bytes
    offset += ts_len

    assert len(encoded) == offset


def test_admin_audit_chain_append_and_verify(db_session) -> None:
    from app.models.admin_audit import AdminAuditEntry
    from app.services.admin_audit import AdminAuditChainService

    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)

    actor = User(email="admin@campus.edu", role="admin")
    db_session.add(actor)
    db_session.commit()

    ts1 = datetime(2026, 9, 10, 10, 0, 0, 0, tzinfo=timezone.utc)
    entry1 = chain_service.append(
        session=db_session,
        actor_id=actor.id,
        action="user.freeze",
        target="user:target-1",
        detail_hash=b"\x11" * 32,
        timestamp=ts1,
    )
    db_session.commit()

    assert entry1.hash_prev == b"\x00" * 32
    assert len(entry1.hash_curr) == 32
    assert entry1.actor_id == actor.id

    ts2 = datetime(2026, 9, 10, 10, 5, 0, 0, tzinfo=timezone.utc)
    entry2 = chain_service.append(
        session=db_session,
        actor_id=actor.id,
        action="user.unfreeze",
        target="user:target-1",
        detail_hash=b"\x22" * 32,
        timestamp=ts2,
    )
    db_session.commit()

    assert entry2.hash_prev == entry1.hash_curr
    assert entry2.hash_curr != entry1.hash_curr

    # Verify unbroken chain
    verified = chain_service.verify_chain(db_session)
    assert len(verified) == 2
    assert verified[0].hash_curr == entry1.hash_curr
    assert verified[1].hash_curr == entry2.hash_curr


def test_admin_audit_chain_tamper_detection(db_session) -> None:
    from app.models.admin_audit import AdminAuditEntry
    from app.services.admin_audit import AdminAuditChainService, AuditChainIntegrityError

    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)

    actor = User(email="admin2@campus.edu", role="admin")
    db_session.add(actor)
    db_session.commit()

    ts = datetime(2026, 9, 10, 10, 0, 0, 0, tzinfo=timezone.utc)
    entry = chain_service.append(
        session=db_session,
        actor_id=actor.id,
        action="user.freeze",
        target="user:target-2",
        detail_hash=b"\x11" * 32,
        timestamp=ts,
    )
    db_session.commit()

    # Tamper with target
    entry.target = "user:hacked"
    db_session.commit()

    with pytest.raises(AuditChainIntegrityError):
        chain_service.verify_chain(db_session)


def test_admin_audit_chain_empty_returns_empty(db_session) -> None:
    from app.services.admin_audit import AdminAuditChainService

    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)
    assert chain_service.verify_chain(db_session) == []


def test_admin_audit_chain_chinese_target_encoding() -> None:
    from app.services.admin_audit import encode_admin_audit_entry

    actor_uuid = uuid.UUID("11111111-2222-3333-4444-555555555555")
    hash_prev = b"\x00" * 32
    detail_hash = b"\xaa" * 32
    timestamp = datetime(2026, 9, 10, 12, 0, 0, 0, tzinfo=timezone.utc)
    target = "用户:测试账号"

    encoded = encode_admin_audit_entry(
        hash_prev=hash_prev,
        actor_id=str(actor_uuid),
        action="user.role.update",
        target=target,
        detail_hash=detail_hash,
        timestamp=timestamp,
    )
    assert target.encode("utf-8") in encoded


def test_admin_audit_chain_fork_detection(db_session) -> None:
    from app.models.admin_audit import AdminAuditEntry
    from app.services.admin_audit import AdminAuditChainService, AuditChainIntegrityError

    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)

    actor = User(email="fork_test@campus.edu", role="admin")
    db_session.add(actor)
    db_session.commit()

    entry1 = chain_service.append(
        session=db_session,
        actor_id=actor.id,
        action="user.freeze",
        target="user:1",
        detail_hash=b"\x11" * 32,
        timestamp=datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc),
    )
    db_session.commit()

    # Attempting to insert a fork directly fails at DB level due to UniqueConstraint("hash_prev")
    from sqlalchemy.exc import IntegrityError
    entry2_fork = AdminAuditEntry(
        id=str(uuid.uuid4()),
        actor_id=actor.id,
        action="user.unfreeze",
        target="user:2",
        detail_hash=b"\x22" * 32,
        hash_prev=b"\x00" * 32,  # Duplicate hash_prev = fork!
        hash_curr=b"\x33" * 32,
        timestamp=datetime(2026, 9, 10, 10, 1, 0, tzinfo=timezone.utc),
    )
    db_session.add(entry2_fork)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_admin_audit_chain_verify_disconnected_detection(db_session) -> None:
    from app.models.admin_audit import AdminAuditEntry
    from app.services.admin_audit import AdminAuditChainService, AuditChainIntegrityError

    engine = DeterministicMockCryptoEngine()
    chain_service = AdminAuditChainService(crypto_engine=engine)

    actor = User(email="disc_test@campus.edu", role="admin")
    db_session.add(actor)
    db_session.commit()

    entry1 = chain_service.append(
        session=db_session,
        actor_id=actor.id,
        action="user.freeze",
        target="user:1",
        detail_hash=b"\x11" * 32,
        timestamp=datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc),
    )
    db_session.commit()

    # Insert an island record with disconnected hash_prev
    island_entry = AdminAuditEntry(
        id=str(uuid.uuid4()),
        actor_id=actor.id,
        action="user.freeze",
        target="user:island",
        detail_hash=b"\x99" * 32,
        hash_prev=b"\x88" * 32,  # Not matching entry1.hash_curr
        hash_curr=b"\x77" * 32,
        timestamp=datetime(2026, 9, 10, 10, 2, 0, tzinfo=timezone.utc),
    )
    db_session.add(island_entry)
    db_session.commit()

    with pytest.raises(AuditChainIntegrityError, match="Disconnected chain entries detected"):
        chain_service.verify_chain(db_session)


