import base64
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy.orm import sessionmaker

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PUBLIC_KEY_SIZE
from app.db.session import create_db_engine, init_database
from app.models.audit import RevocationLog
from app.models.credential import ConsumedSN
from app.schemas.credential import CredentialProof, encode_credential_message
from app.services.credential_verification import (
    ConsumptionCredentialVerificationError,
    VerifiedCredential,
    verify_consumption_credential,
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


def _setup_verification_env():
    engine = create_db_engine("sqlite:///:memory:")
    init_database(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()

    crypto_engine = MockCryptoEngine()
    crypto_engine.set_result("blind_verify", True)

    provider = MockVerificationKeyProvider()
    now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    today_period = "2026-09-09"

    return session, crypto_engine, provider, now, today_period


def test_verify_comment_credential_success():
    session, crypto_engine, provider, now, today_period = _setup_verification_env()

    sn_hex = "00112233445566778899aabbccddeeff"
    sig_b64 = base64.b64encode(b"\x99" * 64).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_comment",
        period=today_period,
        signature=sig_b64,
    )

    verified = verify_consumption_credential(
        session=session,
        crypto_engine=crypto_engine,
        signer_verification_key_provider=provider,
        credential=proof,
        expected_service="hole_comment",
        now=now,
    )

    assert isinstance(verified, VerifiedCredential)
    assert verified.sn_bytes == bytes.fromhex(sn_hex)
    assert verified.signature_bytes == b"\x99" * 64
    assert verified.normalized_sn == sn_hex.lower()
    assert verified.service == "hole_comment"
    assert verified.period == today_period


def test_verify_like_credential_success():
    session, crypto_engine, provider, now, today_period = _setup_verification_env()

    sn_hex = "aabbccddeeff00112233445566778899"
    sig_b64 = base64.b64encode(b"\xaa" * 64).decode("ascii")
    proof = CredentialProof(
        sn=sn_hex,
        service="hole_like",
        period=today_period,
        signature=sig_b64,
    )

    verified = verify_consumption_credential(
        session=session,
        crypto_engine=crypto_engine,
        signer_verification_key_provider=provider,
        credential=proof,
        expected_service="hole_like",
        now=now,
    )

    assert verified.service == "hole_like"
    assert verified.sn_bytes == bytes.fromhex(sn_hex)


def test_cross_service_rejection():
    session, crypto_engine, provider, now, today_period = _setup_verification_env()

    sn_hex = "112233445566778899aabbccddeeff00"
    sig_b64 = base64.b64encode(b"\x55" * 64).decode("ascii")

    # hole_post submitted to comment
    proof_post = CredentialProof(
        sn=sn_hex,
        service="hole_post",
        period=today_period,
        signature=sig_b64,
    )
    with pytest.raises(ConsumptionCredentialVerificationError) as exc_info:
        verify_consumption_credential(
            session=session,
            crypto_engine=crypto_engine,
            signer_verification_key_provider=provider,
            credential=proof_post,
            expected_service="hole_comment",
            now=now,
        )
    assert exc_info.value.code == "invalid_service"

    # hole_comment submitted to like
    proof_comment = CredentialProof(
        sn=sn_hex,
        service="hole_comment",
        period=today_period,
        signature=sig_b64,
    )
    with pytest.raises(ConsumptionCredentialVerificationError) as exc_info2:
        verify_consumption_credential(
            session=session,
            crypto_engine=crypto_engine,
            signer_verification_key_provider=provider,
            credential=proof_comment,
            expected_service="hole_like",
            now=now,
        )
    assert exc_info2.value.code == "invalid_service"

    # hole_like submitted to post
    proof_like = CredentialProof(
        sn=sn_hex,
        service="hole_like",
        period=today_period,
        signature=sig_b64,
    )
    with pytest.raises(ConsumptionCredentialVerificationError) as exc_info3:
        verify_consumption_credential(
            session=session,
            crypto_engine=crypto_engine,
            signer_verification_key_provider=provider,
            credential=proof_like,
            expected_service="hole_post",
            now=now,
        )
    assert exc_info3.value.code == "invalid_service"


def test_wrong_period_rejection():
    session, crypto_engine, provider, now, today_period = _setup_verification_env()

    yesterday_period = (now - timedelta(days=1)).date().isoformat()
    proof = CredentialProof(
        sn="00112233445566778899aabbccddeeff",
        service="hole_comment",
        period=yesterday_period,
        signature=base64.b64encode(b"\x99" * 64).decode("ascii"),
    )
    with pytest.raises(ConsumptionCredentialVerificationError) as exc_info:
        verify_consumption_credential(
            session=session,
            crypto_engine=crypto_engine,
            signer_verification_key_provider=provider,
            credential=proof,
            expected_service="hole_comment",
            now=now,
        )
    assert exc_info.value.code == "invalid_period"


def test_tampered_signature_rejection():
    session, crypto_engine, provider, now, today_period = _setup_verification_env()
    crypto_engine.set_result("blind_verify", False)

    proof = CredentialProof(
        sn="00112233445566778899aabbccddeeff",
        service="hole_comment",
        period=today_period,
        signature=base64.b64encode(b"\x99" * 64).decode("ascii"),
    )
    with pytest.raises(ConsumptionCredentialVerificationError) as exc_info:
        verify_consumption_credential(
            session=session,
            crypto_engine=crypto_engine,
            signer_verification_key_provider=provider,
            credential=proof,
            expected_service="hole_comment",
            now=now,
        )
    assert exc_info.value.code == "invalid_signature"


def test_revoked_credential_rejection():
    import uuid
    from app.models.user import User

    session, crypto_engine, provider, now, today_period = _setup_verification_env()

    operator = User(
        id=str(uuid.uuid4()),
        email="operator@campus.edu.cn",
        role="admin",
        status="active",
    )
    session.add(operator)
    session.commit()

    sn_bytes = bytes.fromhex("00112233445566778899aabbccddeeff")
    session.add(
        RevocationLog(
            hash_curr=b"\x01" * 32,
            sn=sn_bytes,
            reason="test revocation",
            operator=operator.id,
            ts=now,
        )
    )
    session.commit()

    proof = CredentialProof(
        sn="00112233445566778899aabbccddeeff",
        service="hole_comment",
        period=today_period,
        signature=base64.b64encode(b"\x99" * 64).decode("ascii"),
    )
    with pytest.raises(ConsumptionCredentialVerificationError) as exc_info:
        verify_consumption_credential(
            session=session,
            crypto_engine=crypto_engine,
            signer_verification_key_provider=provider,
            credential=proof,
            expected_service="hole_comment",
            now=now,
        )
    assert exc_info.value.code == "credential_revoked"


def test_provider_unavailable_safety():
    session, crypto_engine, provider, now, today_period = _setup_verification_env()
    empty_provider = MockVerificationKeyProvider(key_map={})

    proof = CredentialProof(
        sn="00112233445566778899aabbccddeeff",
        service="hole_comment",
        period=today_period,
        signature=base64.b64encode(b"\x99" * 64).decode("ascii"),
    )
    with pytest.raises(ConsumptionCredentialVerificationError) as exc_info:
        verify_consumption_credential(
            session=session,
            crypto_engine=crypto_engine,
            signer_verification_key_provider=empty_provider,
            credential=proof,
            expected_service="hole_comment",
            now=now,
        )
    assert exc_info.value.code == "engine_unavailable"


def test_verification_has_no_side_effects():
    session, crypto_engine, provider, now, today_period = _setup_verification_env()

    proof = CredentialProof(
        sn="00112233445566778899aabbccddeeff",
        service="hole_comment",
        period=today_period,
        signature=base64.b64encode(b"\x99" * 64).decode("ascii"),
    )
    verify_consumption_credential(
        session=session,
        crypto_engine=crypto_engine,
        signer_verification_key_provider=provider,
        credential=proof,
        expected_service="hole_comment",
        now=now,
    )

    # Check that ConsumedSN is untouched
    assert session.query(ConsumedSN).count() == 0
