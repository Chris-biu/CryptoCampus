import base64
import pytest
from pydantic import ValidationError

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE, SM2_SIGNATURE_SIZE
from app.crypto.unavailable import UnavailableCryptoEngine
from app.schemas.credential import (
    CredentialProof,
    encode_credential_message,
)
from app.services.signer_provider import (
    DefaultServerSignerKeyProvider,
    ServerSignerVerificationKeyProvider,
    get_signer_verification_key_provider,
)


def test_encode_credential_message_fixed_vector():
    sn_hex = "00112233445566778899aabbccddeeff"
    service = "hole_post"
    period = "2026-09-09"

    msg = encode_credential_message(sn_hex, service, period)

    expected = bytes.fromhex(sn_hex) + b"hole_post" + b"2026-09-09"
    assert msg == expected
    assert len(msg) == 16 + len("hole_post") + len("2026-09-09")
    assert msg[:16] == bytes.fromhex(sn_hex)
    assert msg[16:25] == b"hole_post"
    assert msg[25:] == b"2026-09-09"


def test_credential_proof_validation_valid():
    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")

    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )
    assert proof.sn == sn_hex
    assert proof.service == "hole_post"
    assert proof.period == "2026-09-09"
    assert proof.signature == sig_b64


def test_credential_proof_rejects_invalid_sn():
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")

    # Odd length hex
    with pytest.raises(ValidationError):
        CredentialProof(
            sn="00112233445566778899aabbccddeef",
            service="hole_post",
            period="2026-09-09",
            signature=sig_b64,
        )

    # Less than 16 bytes (30 hex chars)
    with pytest.raises(ValidationError):
        CredentialProof(
            sn="00112233445566778899aabbccddee",
            service="hole_post",
            period="2026-09-09",
            signature=sig_b64,
        )

    # Invalid non-hex characters
    with pytest.raises(ValidationError):
        CredentialProof(
            sn="00112233445566778899aabbccddeegg",
            service="hole_post",
            period="2026-09-09",
            signature=sig_b64,
        )


def test_credential_proof_rejects_invalid_signature():
    sn_hex = "00112233445566778899aabbccddeeff"

    # Signature not 64 bytes (63 bytes)
    sig_63 = base64.b64encode(b"\x99" * 63).decode("ascii")
    with pytest.raises(ValidationError):
        CredentialProof(
            sn=sn_hex,
            service="hole_post",
            period="2026-09-09",
            signature=sig_63,
        )

    # Signature not 64 bytes (65 bytes)
    sig_65 = base64.b64encode(b"\x99" * 65).decode("ascii")
    with pytest.raises(ValidationError):
        CredentialProof(
            sn=sn_hex,
            service="hole_post",
            period="2026-09-09",
            signature=sig_65,
        )

    # Not valid base64
    with pytest.raises(ValidationError):
        CredentialProof(
            sn=sn_hex,
            service="hole_post",
            period="2026-09-09",
            signature="!!!not-base64!!!",
        )


def test_credential_proof_rejects_extra_fields():
    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")

    with pytest.raises(ValidationError):
        CredentialProof(
            sn=sn_hex,
            service="hole_post",
            period="2026-09-09",
            signature=sig_b64,
            user_id="forbidden_user_field",
        )

    with pytest.raises(ValidationError):
        CredentialProof(
            sn=sn_hex,
            service="hole_post",
            period="2026-09-09",
            signature=sig_b64,
            blinding_factor="forbidden_blinding_factor",
        )


def test_unavailable_crypto_engine_blind_verify():
    engine = UnavailableCryptoEngine()
    with pytest.raises(CryptoBridgeError) as exc_info:
        engine.blind_verify(
            message=b"test message",
            signature=b"\x00" * SM2_SIGNATURE_SIZE,
            signer_public_key=b"\x04" + b"\x00" * (SM2_PUBLIC_KEY_SIZE - 1),
        )
    assert exc_info.value.code == BridgeErrorCode.PROVIDER_UNAVAILABLE


def test_mock_crypto_engine_blind_verify_success_and_failure():
    engine = MockCryptoEngine()
    assert isinstance(engine, CryptoEngine)

    msg = b"test message"
    sig = b"\x11" * SM2_SIGNATURE_SIZE
    pubkey = b"\x04" + b"\x22" * (SM2_PUBLIC_KEY_SIZE - 1)

    # Configured True
    engine.set_result("blind_verify", True)
    assert engine.blind_verify(message=msg, signature=sig, signer_public_key=pubkey) is True
    assert ("blind_verify", {"message": len(msg), "signature": 64, "signer_public_key": 65}) in engine.calls

    # Configured False
    engine.set_result("blind_verify", False)
    assert engine.blind_verify(message=msg, signature=sig, signer_public_key=pubkey) is False


def test_mock_crypto_engine_blind_verify_argument_validation():
    engine = MockCryptoEngine()
    engine.set_result("blind_verify", True)

    msg = b"test message"
    sig = b"\x11" * SM2_SIGNATURE_SIZE
    pubkey = b"\x04" + b"\x22" * (SM2_PUBLIC_KEY_SIZE - 1)

    # Empty message
    with pytest.raises(CryptoBridgeError) as exc:
        engine.blind_verify(message=b"", signature=sig, signer_public_key=pubkey)
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # Signature wrong length
    with pytest.raises(CryptoBridgeError) as exc:
        engine.blind_verify(message=msg, signature=b"\x11" * 63, signer_public_key=pubkey)
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT

    # Public key wrong length
    with pytest.raises(CryptoBridgeError) as exc:
        engine.blind_verify(message=msg, signature=sig, signer_public_key=b"\x04" * 64)
    assert exc.value.code == BridgeErrorCode.INVALID_ARGUMENT


def test_server_signer_verification_key_provider():
    provider = DefaultServerSignerKeyProvider()
    assert isinstance(provider, ServerSignerVerificationKeyProvider)
    assert provider.get_signer_public_key("hole_post") is None

    dep_provider = get_signer_verification_key_provider()
    assert dep_provider.get_signer_public_key("hole_post") is None


# ---------------------------------------------------------------------------
# Task 3: CredentialVerificationService Tests
# ---------------------------------------------------------------------------
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models.audit import RevocationLog
from app.models.credential import ConsumedSN
from app.models.user import User
from app.services.credential_verification import (
    CredentialVerificationError,
    CredentialVerificationService,
)


class MockVerificationKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or (b"\x04" + b"\x33" * (SM2_PUBLIC_KEY_SIZE - 1))

    def get_signer_public_key(self, service: str) -> bytes | None:
        return self.key


def _setup_verification_env():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()

    # Create dummy operator user for RevocationLog foreign key
    operator = User(
        id="00000000-0000-0000-0000-000000000001",
        email="operator@test.edu.cn",
        role="admin",
        status="active",
    )
    session.add(operator)
    session.commit()

    crypto_engine = MockCryptoEngine()
    key_provider = MockVerificationKeyProvider()
    service = CredentialVerificationService(
        session=session,
        crypto_engine=crypto_engine,
        signer_verification_key_provider=key_provider,
    )
    return session, crypto_engine, key_provider, service


def test_verify_service_success_valid_unconsumed_unrevoked():
    session, crypto_engine, key_provider, service = _setup_verification_env()
    crypto_engine.set_result("blind_verify", True)

    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    result = service.verify(proof)
    assert result.valid is True
    assert result.service == "hole_post"
    assert result.period == "2026-09-09"
    assert result.consumed is False
    assert result.revoked is False


def test_verify_service_tampered_signature_returns_valid_false():
    session, crypto_engine, key_provider, service = _setup_verification_env()
    crypto_engine.set_result("blind_verify", False)

    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x00" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period="2026-09-09",
        signature=sig_b64,
    )

    result = service.verify(proof)
    assert result.valid is False
    assert result.consumed is False
    assert result.revoked is False


def test_verify_service_consumed_sn_returns_consumed_true():
    session, crypto_engine, key_provider, service = _setup_verification_env()
    crypto_engine.set_result("blind_verify", True)

    sn_bytes = bytes.fromhex("00112233445566778899aabbccddeeff")
    session.add(ConsumedSN(sn=sn_bytes, service="hole_post", consumed_at=datetime.now(timezone.utc)))
    session.commit()

    proof = CredentialProof(
        sn="00112233445566778899aabbccddeeff",
        service="hole_post",
        period="2026-09-09",
        signature=base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii"),
    )

    result = service.verify(proof)
    assert result.valid is True
    assert result.consumed is True
    assert result.revoked is False


def test_verify_service_revoked_sn_returns_revoked_true():
    session, crypto_engine, key_provider, service = _setup_verification_env()
    crypto_engine.set_result("blind_verify", True)

    sn_bytes = bytes.fromhex("00112233445566778899aabbccddeeff")
    revocation = RevocationLog(
        hash_curr=b"\x12" * 32,
        sn=sn_bytes,
        reason="Compromised",
        operator="00000000-0000-0000-0000-000000000001",
        ts=datetime.now(timezone.utc),
    )
    session.add(revocation)
    session.commit()

    proof = CredentialProof(
        sn="00112233445566778899aabbccddeeff",
        service="hole_post",
        period="2026-09-09",
        signature=base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii"),
    )

    result = service.verify(proof)
    assert result.valid is True
    assert result.consumed is False
    assert result.revoked is True


def test_verify_service_provider_unavailable_fails_safely():
    session, crypto_engine, key_provider, service = _setup_verification_env()
    # If key_provider has no public key
    key_provider.key = None

    proof = CredentialProof(
        sn="00112233445566778899aabbccddeeff",
        service="hole_post",
        period="2026-09-09",
        signature=base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii"),
    )

    with pytest.raises(CredentialVerificationError) as exc_info:
        service.verify(proof)
    assert exc_info.value.code == "engine_unavailable"

    # If crypto engine raises PROVIDER_UNAVAILABLE
    key_provider.key = b"\x04" + b"\x33" * (SM2_PUBLIC_KEY_SIZE - 1)
    crypto_engine.set_error("blind_verify", CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE))

    with pytest.raises(CredentialVerificationError) as exc_info2:
        service.verify(proof)
    assert exc_info2.value.code == "engine_unavailable"


def test_verify_service_historical_period_accepted():
    session, crypto_engine, key_provider, service = _setup_verification_env()
    crypto_engine.set_result("blind_verify", True)

    proof = CredentialProof(
        sn="00112233445566778899aabbccddeeff",
        service="hole_post",
        period="2020-01-01",  # Historical period
        signature=base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii"),
    )

    result = service.verify(proof)
    assert result.valid is True
    assert result.period == "2020-01-01"


def test_credential_verification_linkage_with_post_publish_and_withdrawal():
    import hashlib
    from app.services.hole_governance import HoleContentGovernanceService
    from app.services.hole_posts import HolePostService

    session, crypto_engine, key_provider, service = _setup_verification_env()
    crypto_engine.set_result("blind_verify", True)
    crypto_engine.sm3_digest = lambda msg: hashlib.sha256(b"mock-sm3:" + msg).digest()
    crypto_engine.constant_time_equal = lambda l, r: l == r

    today_utc = datetime.now(timezone.utc).date().isoformat()
    now_utc = datetime.now(timezone.utc)
    sn_hex = "11223344556677889900aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * SM2_SIGNATURE_SIZE).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period=today_utc,
        signature=sig_b64,
    )

    # 1. Before publish: valid=True, consumed=False, revoked=False
    res_before = service.verify(proof)
    assert res_before.valid is True
    assert res_before.consumed is False
    assert res_before.revoked is False

    # 2. Publish post via HolePostService
    post_service = HolePostService(
        session=session,
        crypto_engine=crypto_engine,
        signer_verification_key_provider=key_provider,
    )
    post = post_service.publish(
        content="Post for credential linkage test",
        credential=proof,
        idempotency_key="idemp-key-linkage-12345",
        now=now_utc,
    )

    # Verify after publish: valid=True, consumed=True, revoked=False
    res_published = service.verify(proof)
    assert res_published.valid is True
    assert res_published.consumed is True
    assert res_published.revoked is False

    # 3. Withdraw post via HoleContentGovernanceService
    session_factory = sessionmaker(bind=session.get_bind())
    gov_service = HoleContentGovernanceService(
        session_factory=session_factory,
        crypto_engine=crypto_engine,
    )
    gov_service.withdraw_post(
        post_id=post.id,
        reason="违规内容撤销凭据测试",
        operator_id="00000000-0000-0000-0000-000000000001",
        now=now_utc,
    )

    # 4. Verify after withdrawal: valid remains True, consumed remains True, revoked becomes True
    res_withdrawn = service.verify(proof)
    assert res_withdrawn.valid is True
    assert res_withdrawn.consumed is True
    assert res_withdrawn.revoked is True

