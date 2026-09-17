import pytest
from datetime import datetime, timezone

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    MLKEM_ENC_KEY_SIZE,
    SM2_PRIVATE_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
    EnvelopeArtifact,
)
from app.crypto.unavailable import UnavailableCryptoEngine

# We will test MLKEM_PRIVATE_KEY_SIZE and recipient_provider as well
try:
    from app.crypto.types import MLKEM_PRIVATE_KEY_SIZE
except ImportError:
    MLKEM_PRIVATE_KEY_SIZE = 2400

try:
    from app.services.recipient_provider import (
        DefaultRecipientPrivateKeyProvider,
        MockRecipientPrivateKeyProvider,
        RecipientPrivateKeyProvider,
    )
except ImportError:
    RecipientPrivateKeyProvider = None
    DefaultRecipientPrivateKeyProvider = None
    MockRecipientPrivateKeyProvider = None

VALID_NONCE = b"\x01" * GCM_NONCE_SIZE
VALID_TAG = b"\x02" * GCM_TAG_SIZE
VALID_SM2_ENC = b"\x03" * 96
VALID_MLKEM_ENC = b"\x04" * MLKEM_ENC_KEY_SIZE
VALID_SIG = b"\x05" * SM2_SIGNATURE_SIZE
VALID_CERT = b"\x30\x82\x01\x00" + b"\x06" * 100
VALID_SM2_PRIV = b"\x09" * SM2_PRIVATE_KEY_SIZE
VALID_MLKEM_PRIV = b"\x0a" * 2400


@pytest.fixture
def sample_envelope_classic() -> EnvelopeArtifact:
    return EnvelopeArtifact(
        ciphertext=b"encrypted payload",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=None,
        sender_signature=VALID_SIG,
        sender_certificate=VALID_CERT,
    )


@pytest.fixture
def sample_envelope_pqc() -> EnvelopeArtifact:
    return EnvelopeArtifact(
        ciphertext=b"encrypted payload pqc",
        nonce=VALID_NONCE,
        tag=VALID_TAG,
        enc_key_sm2=VALID_SM2_ENC,
        enc_key_mlkem=VALID_MLKEM_ENC,
        sender_signature=VALID_SIG,
        sender_certificate=VALID_CERT,
    )


def test_unavailable_crypto_engine_envelope_open_raises_unavailable(sample_envelope_classic: EnvelopeArtifact) -> None:
    engine = UnavailableCryptoEngine()
    assert isinstance(engine, CryptoEngine)
    with pytest.raises(CryptoBridgeError) as exc:
        engine.envelope_open(
            envelope=sample_envelope_classic,
            recipient_sm2_private_key=VALID_SM2_PRIV,
            pqc_mode=False,
            recipient_mlkem_private_key=None,
            access_factor=None,
        )
    assert exc.value.code == BridgeErrorCode.PROVIDER_UNAVAILABLE


def test_mock_crypto_engine_envelope_open_classic_success(sample_envelope_classic: EnvelopeArtifact) -> None:
    engine = MockCryptoEngine()
    assert isinstance(engine, CryptoEngine)
    expected_plaintext = b"decrypted hello world"
    engine.set_result("envelope_open", expected_plaintext)

    result = engine.envelope_open(
        envelope=sample_envelope_classic,
        recipient_sm2_private_key=VALID_SM2_PRIV,
        pqc_mode=False,
        recipient_mlkem_private_key=None,
        access_factor=b"\xbb" * 16,
    )

    assert result == expected_plaintext
    assert len(engine.calls) == 1
    op, lengths = engine.calls[0]
    assert op == "envelope_open"
    assert lengths["ciphertext"] == len(sample_envelope_classic.ciphertext)
    assert lengths["recipient_sm2_private_key"] == SM2_PRIVATE_KEY_SIZE
    assert lengths["recipient_mlkem_private_key"] == 0
    assert lengths["access_factor"] == 16
    assert "plaintext" not in lengths
    assert "private_key" not in lengths


def test_mock_crypto_engine_envelope_open_pqc_success(sample_envelope_pqc: EnvelopeArtifact) -> None:
    engine = MockCryptoEngine()
    expected_plaintext = b"decrypted pqc payload"
    engine.set_result("envelope_open", expected_plaintext)

    result = engine.envelope_open(
        envelope=sample_envelope_pqc,
        recipient_sm2_private_key=VALID_SM2_PRIV,
        pqc_mode=True,
        recipient_mlkem_private_key=VALID_MLKEM_PRIV,
        access_factor=None,
    )

    assert result == expected_plaintext
    assert len(engine.calls) == 1
    op, lengths = engine.calls[0]
    assert op == "envelope_open"
    assert lengths["ciphertext"] == len(sample_envelope_pqc.ciphertext)
    assert lengths["recipient_sm2_private_key"] == SM2_PRIVATE_KEY_SIZE
    assert lengths["recipient_mlkem_private_key"] == 2400
    assert lengths["access_factor"] == 0


def test_mock_crypto_engine_envelope_open_rejects_invalid_inputs(sample_envelope_classic: EnvelopeArtifact, sample_envelope_pqc: EnvelopeArtifact) -> None:
    engine = MockCryptoEngine()

    # Invalid recipient_sm2_private_key length
    with pytest.raises(CryptoBridgeError) as exc:
        engine.envelope_open(
            envelope=sample_envelope_classic,
            recipient_sm2_private_key=b"\x09" * 31,
            pqc_mode=False,
            recipient_mlkem_private_key=None,
            access_factor=None,
        )
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # PQC mode True but recipient_mlkem_private_key is None
    with pytest.raises(CryptoBridgeError) as exc:
        engine.envelope_open(
            envelope=sample_envelope_pqc,
            recipient_sm2_private_key=VALID_SM2_PRIV,
            pqc_mode=True,
            recipient_mlkem_private_key=None,
            access_factor=None,
        )
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # PQC mode True but recipient_mlkem_private_key invalid length
    with pytest.raises(CryptoBridgeError) as exc:
        engine.envelope_open(
            envelope=sample_envelope_pqc,
            recipient_sm2_private_key=VALID_SM2_PRIV,
            pqc_mode=True,
            recipient_mlkem_private_key=b"\x0a" * 2399,
            access_factor=None,
        )
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # PQC mode False but recipient_mlkem_private_key is provided
    with pytest.raises(CryptoBridgeError) as exc:
        engine.envelope_open(
            envelope=sample_envelope_classic,
            recipient_sm2_private_key=VALID_SM2_PRIV,
            pqc_mode=False,
            recipient_mlkem_private_key=VALID_MLKEM_PRIV,
            access_factor=None,
        )
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # access_factor invalid length (less than 16 or greater than 32)
    with pytest.raises(CryptoBridgeError) as exc:
        engine.envelope_open(
            envelope=sample_envelope_classic,
            recipient_sm2_private_key=VALID_SM2_PRIV,
            pqc_mode=False,
            recipient_mlkem_private_key=None,
            access_factor=b"\xbb" * 15,
        )
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT


def test_recipient_private_key_provider_protocol_and_mock() -> None:
    assert RecipientPrivateKeyProvider is not None
    assert DefaultRecipientPrivateKeyProvider is not None
    assert MockRecipientPrivateKeyProvider is not None

    now = datetime.now(timezone.utc)
    # Default fails closed
    default_provider = DefaultRecipientPrivateKeyProvider()
    assert isinstance(default_provider, RecipientPrivateKeyProvider)
    assert default_provider.get_unlocked_private_key(
        recipient_user_id="user-1", key_fingerprint=b"\x11" * 32, now=now
    ) is None

    # Mock provider
    mock_provider = MockRecipientPrivateKeyProvider()
    assert isinstance(mock_provider, RecipientPrivateKeyProvider)
    mock_provider.set_key("user-1", b"\x11" * 32, VALID_SM2_PRIV)

    # Success match
    retrieved = mock_provider.get_unlocked_private_key(
        recipient_user_id="user-1", key_fingerprint=b"\x11" * 32, now=now
    )
    assert retrieved == VALID_SM2_PRIV

    # Fingerprint mismatch fails closed
    assert mock_provider.get_unlocked_private_key(
        recipient_user_id="user-1", key_fingerprint=b"\x22" * 32, now=now
    ) is None

    # Unknown user fails closed
    assert mock_provider.get_unlocked_private_key(
        recipient_user_id="user-unknown", key_fingerprint=b"\x11" * 32, now=now
    ) is None
