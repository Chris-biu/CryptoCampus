import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE, MLKEM_PUBLIC_KEY_SIZE
from app.db.base import Base
from app.models.user import User


def _create_sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_default_recipient_key_resolver_fails_closed() -> None:
    from app.services.recipient_resolver import DefaultRecipientKeyResolver

    resolver = DefaultRecipientKeyResolver()
    session = _create_sqlite_session()
    resolved = resolver.resolve_for_create(session, sender_id=str(uuid.uuid4()), pqc_mode=False)
    assert resolved is None


def test_configured_recipient_key_resolver_valid_recipient() -> None:
    from app.services.recipient_resolver import ConfiguredRecipientKeyResolver

    session = _create_sqlite_session()
    crypto = MockCryptoEngine()

    sender_id = str(uuid.uuid4())
    recipient_id = str(uuid.uuid4())

    valid_sm2_pub = b"\x04" + b"\x11" * (SM2_PUBLIC_KEY_SIZE - 1)
    valid_mlkem_pub = b"\x22" * MLKEM_PUBLIC_KEY_SIZE

    recipient = User(
        id=recipient_id,
        email="target@stu.edu.cn",
        role="student",
        status="active",
        pubkey=valid_sm2_pub,
        pqc_pubkey=valid_mlkem_pub,
        enc_pqc_sk=b"\x33" * 2400,
    )
    session.add(recipient)
    session.commit()

    # Mock sm3_digest
    crypto.set_result("sm3_digest", b"\x99" * 32)

    resolver = ConfiguredRecipientKeyResolver(target_user_id=recipient_id, crypto_engine=crypto)

    # Resolve in non-pqc mode
    resolved = resolver.resolve_for_create(session, sender_id=sender_id, pqc_mode=False)
    assert resolved is not None
    assert resolved.recipient_user_id == recipient_id
    assert resolved.sm2_public_key == valid_sm2_pub
    assert resolved.mlkem_public_key is None
    assert resolved.sm2_fingerprint == b"\x99" * 32
    assert resolved.mlkem_fingerprint is None

    # Resolve in pqc mode
    resolved_pqc = resolver.resolve_for_create(session, sender_id=sender_id, pqc_mode=True)
    assert resolved_pqc is not None
    assert resolved_pqc.recipient_user_id == recipient_id
    assert resolved_pqc.sm2_public_key == valid_sm2_pub
    assert resolved_pqc.mlkem_public_key == valid_mlkem_pub
    assert resolved_pqc.sm2_fingerprint == b"\x99" * 32
    assert resolved_pqc.mlkem_fingerprint == b"\x99" * 32


def test_configured_recipient_key_resolver_fails_closed_on_invalid_conditions() -> None:
    from app.services.recipient_resolver import ConfiguredRecipientKeyResolver

    session = _create_sqlite_session()
    crypto = MockCryptoEngine()
    crypto.set_result("sm3_digest", b"\x99" * 32)

    # 1. Target user not found
    resolver_missing = ConfiguredRecipientKeyResolver(target_user_id=str(uuid.uuid4()), crypto_engine=crypto)
    assert resolver_missing.resolve_for_create(session, sender_id="s1", pqc_mode=False) is None

    # 2. Target user is frozen
    frozen_user = User(
        id=str(uuid.uuid4()),
        email="frozen@stu.edu.cn",
        role="student",
        status="frozen",
        pubkey=b"\x04" + b"\x11" * 64,
    )
    session.add(frozen_user)
    session.commit()
    resolver_frozen = ConfiguredRecipientKeyResolver(target_user_id=frozen_user.id, crypto_engine=crypto)
    assert resolver_frozen.resolve_for_create(session, sender_id="s1", pqc_mode=False) is None

    # 3. Target user missing SM2 pubkey
    no_key_user = User(
        id=str(uuid.uuid4()),
        email="nokey@stu.edu.cn",
        role="student",
        status="active",
        pubkey=None,
    )
    session.add(no_key_user)
    session.commit()
    resolver_no_key = ConfiguredRecipientKeyResolver(target_user_id=no_key_user.id, crypto_engine=crypto)
    assert resolver_no_key.resolve_for_create(session, sender_id="s1", pqc_mode=False) is None

    # 4. Target user invalid length SM2 pubkey
    bad_key_user = User(
        id=str(uuid.uuid4()),
        email="badkey@stu.edu.cn",
        role="student",
        status="active",
        pubkey=b"\x04" + b"\x11" * 30,  # invalid length
    )
    session.add(bad_key_user)
    session.commit()
    resolver_bad_key = ConfiguredRecipientKeyResolver(target_user_id=bad_key_user.id, crypto_engine=crypto)
    assert resolver_bad_key.resolve_for_create(session, sender_id="s1", pqc_mode=False) is None

    # 5. pqc_mode=True but recipient lacks ML-KEM pubkey
    sm2_only_user = User(
        id=str(uuid.uuid4()),
        email="sm2only@stu.edu.cn",
        role="student",
        status="active",
        pubkey=b"\x04" + b"\x11" * 64,
        pqc_pubkey=None,
    )
    session.add(sm2_only_user)
    session.commit()
    resolver_sm2_only = ConfiguredRecipientKeyResolver(target_user_id=sm2_only_user.id, crypto_engine=crypto)
    # Must fail closed, not downgrade!
    assert resolver_sm2_only.resolve_for_create(session, sender_id="s1", pqc_mode=True) is None
