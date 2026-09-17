import base64
from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.crypto.mock import MockCryptoEngine
from app.db.base import Base
from app.models.inspect import InspectRecordEntity
from app.models.user import User
from app.models.vote import VoteOption, VoteRecord
from app.schemas.credential import CredentialProof
from app.schemas.inspect import (
    DropEnvelopeCreateRedacted,
    DropEnvelopeOpenRedacted,
    DropDestroyRedacted,
    HoleCredentialVerifyRedacted,
    VoteCredentialIssueRedacted,
    VoteBallotVerifyRedacted,
    VoteResultSignRedacted,
    SealCreateRedacted,
    SealVerifyRedacted,
    ChatSessionNegotiateRedacted,
)
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.drop import DropService
from app.services.drop_destruction import DropDestructionService
from app.services.hole_posts import HolePostService
from app.services.inspection import DatabaseInspectionRecorder
from app.services.quota import QuotaService
from app.services.recipient_provider import DefaultRecipientPrivateKeyProvider
from app.services.recipient_resolver import RecipientKeyResolver
from app.services.vote_credentials import VoteCredentialIssuanceService
from app.services.vote_signer import DefaultVoteSignerMaterialProvider


def _create_sqlite_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def test_typed_ports_defined_for_uncompleted_modules():
    # Verify typed ports exist and reject unknown keys
    with pytest.raises(Exception):
        VoteBallotVerifyRedacted.model_validate({"vote_public_id": "vid", "signature_valid": True, "counted": True, "extra": "forbidden"})

    with pytest.raises(Exception):
        VoteResultSignRedacted.model_validate({"vote_public_id": "vid", "total": 10, "algorithm": "SM2", "signer_cert_fingerprint": "fp", "extra": "forbidden"})

    with pytest.raises(Exception):
        SealCreateRedacted.model_validate({"file_bytes": 100, "digest_prefix": "0123456789abcdef", "seal_profile": "p", "algorithm": "SM2", "cert_fingerprint": "fp", "extra": "forbidden"})

    with pytest.raises(Exception):
        SealVerifyRedacted.model_validate({"digest_passed": True, "signature_passed": True, "chain_passed": True, "timestamp_passed": True, "revocation_passed": True, "extra": "forbidden"})

    with pytest.raises(Exception):
        ChatSessionNegotiateRedacted.model_validate({"pqc_mode": False, "key_agreement": "SM2", "public_material_bytes": 100, "extra": "forbidden"})


def test_drop_create_and_extract_emits_inspection_records():
    from app.crypto.types import EnvelopeArtifact, GCM_NONCE_SIZE, GCM_TAG_SIZE
    session = _create_sqlite_session()
    crypto = MockCryptoEngine()
    crypto.set_result("sm3_digest", b"\xaa" * 32)
    crypto.set_result("hkdf_sm3", b"\xbb" * 32)
    artifact = EnvelopeArtifact(
        ciphertext=b"encrypted_ciphertext",
        nonce=b"\x01" * GCM_NONCE_SIZE,
        tag=b"\x02" * GCM_TAG_SIZE,
        enc_key_sm2=b"\x03" * 96,
        enc_key_mlkem=None,
        sender_signature=b"\x04" * 64,
        sender_certificate=b"cert-der",
    )
    crypto.set_result("envelope_seal", artifact)
    key_cache = PrivateKeyUnlockCache()
    recorder = DatabaseInspectionRecorder()

    sender = User(id=str(uuid.uuid4()), email="sender@stu.edu.cn", role="student", status="active", cert_serial="cert-sender")
    recipient = User(id=str(uuid.uuid4()), email="recipient@stu.edu.cn", role="student", status="active", cert_serial="cert-recipient")
    session.add_all([sender, recipient])
    session.commit()

    # Pre-populate keys and certificates
    from datetime import timedelta
    import base64
    priv_key = b"k" * 32
    pub_key = b"\x04" + b"p" * 64
    now = datetime.now(timezone.utc)
    key_cache.put(sender.id, priv_key, now + timedelta(hours=1))

    from app.models.certificate import CertificateRecord
    sender_cert = CertificateRecord(
        serial=sender.cert_serial,
        subject_user_id=sender.id,
        issuer_serial="CA-ROOT-001",
        kind="user_identity",
        certificate_der=b"\x30\x82\x01\x00" + b"\x55" * 100,
        key_usage="digitalSignature",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=365),
        status="active",
    )
    session.add(sender_cert)
    session.commit()

    class DummyResolver:
        def resolve_for_create(self, s, s_id, pqc):
            from collections import namedtuple
            R = namedtuple("R", ["recipient_user_id", "sm2_public_key", "mlkem_public_key", "sm2_fingerprint", "mlkem_fingerprint"])
            return R(recipient.id, pub_key, None, b"\xaa" * 32, None)

    class DummyRecipientProvider:
        def get_unlocked_private_key(self, recipient_user_id, key_fingerprint, now):
            return priv_key

    class DummyCAService:
        def verify_certificate(self, certificate_der, verification_time, required_key_usage):
            from collections import namedtuple
            V = namedtuple("V", ["valid"])
            return V(True)

    drop_service = DropService(
        session=session,
        crypto_engine=crypto,
        key_cache=key_cache,
        quota_service=QuotaService(session, crypto.sm3_digest),
        recipient_resolver=DummyResolver(),  # type: ignore
        recipient_provider=DummyRecipientProvider(),  # type: ignore
        ca_service=DummyCAService(),  # type: ignore
        recorder=recorder,
    )

    resp = drop_service.create_text_drop(
        sender_id=sender.id,
        content="hello secure drop",
        ttl_policy="hours_24",
        pqc_mode=False,
        idempotency_key="idemp-key-12345678",
        now=now,
    )

    # Verify drop.envelope.create inspection record was written
    inspect_create = session.query(InspectRecordEntity).filter_by(
        owner_user_id=sender.id, operation="drop.envelope.create"
    ).first()
    assert inspect_create is not None
    assert inspect_create.status == "passed"
    assert len(inspect_create.steps) == 1
    assert "digest_prefix" in inspect_create.steps[0].redacted_values_json


def test_hole_post_publish_emits_anonymous_inspection_record():
    session = _create_sqlite_session()
    crypto = MockCryptoEngine()
    crypto.set_result("sm3_digest", b"\xaa" * 32)
    crypto.set_result("constant_time_equal", True)
    recorder = DatabaseInspectionRecorder()

    hole_service = HolePostService(
        session=session,
        crypto_engine=crypto,
        recorder=recorder,
    )

    now = datetime.now(timezone.utc)
    sn = "0123456789abcdef0123456789abcdef"
    proof = CredentialProof(
        service="hole_post",
        period="2026-09-10",
        sn=sn,
        signature=base64.b64encode(b"\x01" * 64).decode("ascii"),
    )

    # Monkeypatch verify_consumption_credential to avoid complex cryptographic setup
    import app.services.hole_posts as hp_module
    from collections import namedtuple
    V = namedtuple("V", ["sn_bytes", "signature_bytes"])
    orig_verify = hp_module.verify_consumption_credential
    hp_module.verify_consumption_credential = lambda **kwargs: V(bytes.fromhex(sn), b"\x00" * 64)

    try:
        hole_service.publish(
            content="test content",
            credential=proof,
            idempotency_key="idemp-key-1234567890",
            now=now,
        )

        inspect_hole = session.query(InspectRecordEntity).filter_by(
            operation="hole.credential.verify"
        ).first()
        assert inspect_hole is not None
        assert inspect_hole.owner == "system"
        assert inspect_hole.owner_user_id is None
        assert inspect_hole.status == "passed"
        assert "signature_valid" in inspect_hole.steps[0].redacted_values_json
    finally:
        hp_module.verify_consumption_credential = orig_verify
