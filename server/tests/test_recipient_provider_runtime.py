from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.api.routes.drops import (
    get_recipient_key_resolver,
    get_recipient_private_key_provider,
)
from app.crypto.mock import MockCryptoEngine
from app.models.user import User
from app.services.recipient_provider import (
    DefaultRecipientPrivateKeyProvider,
    FileRecipientPrivateKeyProvider,
)
from app.services.recipient_resolver import ConfiguredRecipientKeyResolver

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def test_file_provider_requires_matching_user_and_fingerprint(tmp_path: Path) -> None:
    private_key = b"k" * 32
    key_path = tmp_path / "recipient.key"
    key_path.write_bytes(private_key)
    user_id = str(uuid4())
    fingerprint = b"f" * 32
    provider = FileRecipientPrivateKeyProvider(
        recipient_user_id=user_id,
        sm2_key_fingerprint=fingerprint,
        sm2_private_key_path=key_path,
    )

    assert provider.get_unlocked_private_key(
        recipient_user_id=user_id, key_fingerprint=fingerprint, now=NOW
    ) == private_key
    assert provider.get_unlocked_private_key(
        recipient_user_id=str(uuid4()), key_fingerprint=fingerprint, now=NOW
    ) is None
    assert provider.get_unlocked_private_key(
        recipient_user_id=user_id, key_fingerprint=b"x" * 32, now=NOW
    ) is None
    assert private_key.hex() not in repr(provider)


def test_file_provider_rejects_missing_or_malformed_key(tmp_path: Path) -> None:
    key_path = tmp_path / "recipient.key"
    provider = FileRecipientPrivateKeyProvider(
        recipient_user_id="recipient",
        sm2_key_fingerprint=b"f" * 32,
        sm2_private_key_path=key_path,
    )
    assert provider.get_unlocked_private_key(
        recipient_user_id="recipient", key_fingerprint=b"f" * 32, now=NOW
    ) is None

    key_path.write_bytes(b"short")
    assert provider.get_unlocked_private_key(
        recipient_user_id="recipient", key_fingerprint=b"f" * 32, now=NOW
    ) is None


def test_route_dependencies_bind_configured_active_recipient(
    db_session, tmp_path: Path, monkeypatch
) -> None:
    engine = MockCryptoEngine()
    engine.set_result("sm3_digest", b"f" * 32)
    recipient = User(
        id=str(uuid4()),
        email="drop-vault@campus.edu",
        role="system",
        status="active",
        pubkey=b"\x04" + b"p" * 64,
    )
    db_session.add(recipient)
    db_session.commit()
    key_path = tmp_path / "recipient.key"
    key_path.write_bytes(b"k" * 32)
    monkeypatch.setenv("CRYPTOCAMPUS_DROP_RECIPIENT_USER_ID", recipient.id)
    monkeypatch.setenv("CRYPTOCAMPUS_DROP_RECIPIENT_SM2_KEY_FILE", str(key_path))

    resolver = get_recipient_key_resolver(engine)
    provider = get_recipient_private_key_provider(db_session, engine)

    assert isinstance(resolver, ConfiguredRecipientKeyResolver)
    assert provider.get_unlocked_private_key(
        recipient_user_id=recipient.id, key_fingerprint=b"f" * 32, now=NOW
    ) == b"k" * 32


def test_route_dependencies_fail_closed_for_invalid_user_id(
    db_session, monkeypatch
) -> None:
    monkeypatch.setenv("CRYPTOCAMPUS_DROP_RECIPIENT_USER_ID", "../not-a-uuid")
    engine = MockCryptoEngine()

    assert not isinstance(
        get_recipient_key_resolver(engine), ConfiguredRecipientKeyResolver
    )
    assert isinstance(
        get_recipient_private_key_provider(db_session, engine),
        DefaultRecipientPrivateKeyProvider,
    )
