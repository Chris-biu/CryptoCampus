import base64
from datetime import datetime, timedelta, timezone
import json
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE, SM2_PUBLIC_KEY_SIZE
from app.db.base import Base
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.models.vote import VoteOption, VoteRecord, VoteResultSnapshot
from app.schemas.vote import SignatureVerification, VoteResult
from app.services.vote_result_verification import (
    VoteResultService,
    VoteResultServiceError,
    VoteResultVerificationService,
)
from app.services.vote_results import encode_vote_result


class VerificationMockCryptoEngine(MockCryptoEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._digests: dict[bytes, bytes] = {}
        self._counter = 0

    def sm3_digest(self, message: bytes) -> bytes:
        if message not in self._digests:
            self._counter += 1
            seed = f"digest-{self._counter:08d}-".encode("ascii")
            self._digests[message] = (seed + message)[:32].ljust(32, b"x")
        return self._digests[message]

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return left == right

    def sm2_sign(self, private_key: bytes, digest: bytes) -> bytes:
        return b"\x88" * 64

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        if len(public_key) != SM2_PUBLIC_KEY_SIZE or len(signature) != 64:
            return False
        return signature == (b"\x88" * 64)


def _setup_db() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.models  # noqa: F401
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return session_factory()


def _seed_vote_and_snapshot(session: Session, crypto: VerificationMockCryptoEngine):
    now = datetime(2026, 9, 10, 12, 0, 0, 0, tzinfo=timezone.utc)
    creator = User(email="tally_creator@campus.edu.cn", role="teacher", status="active")
    session.add(creator)
    session.commit()

    vote = VoteRecord(
        creator_id=creator.id,
        title="评选投票",
        scope="public",
        closes_at=now + timedelta(days=2),
        status="open",
        created_at=now - timedelta(days=1),
    )
    opt_a = VoteOption(vote_id=vote.id, label="选项A", position=0)
    opt_b = VoteOption(vote_id=vote.id, label="选项B", position=1)
    session.add_all([vote, opt_a, opt_b])
    session.commit()

    cert_der = b"DER-CERT-TALLY-STATION"
    cert_record = CertificateRecord(
        serial="cert-serial-tally-01",
        subject_user_id=creator.id,
        kind="platform_ca",
        status="active",
        certificate_der=cert_der,
        key_usage="digitalSignature",
        issuer_serial="root-ca",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=365),
        created_at=now,
    )
    session.add(cert_record)
    session.commit()

    pub_key = b"\x04" + b"\x55" * (SM2_PUBLIC_KEY_SIZE - 1)
    ordered_counts = ((opt_a.id, 7), (opt_b.id, 3))
    total = 10
    encoded = encode_vote_result(
        vote_id=vote.id,
        ordered_counts=ordered_counts,
        total=total,
        published_at=now,
    )
    digest = crypto.sm3_digest(encoded)
    sig = crypto.sm2_sign(b"\x11" * SM2_PRIVATE_KEY_SIZE, digest)

    snap1 = VoteResultSnapshot(
        vote_id=vote.id,
        version=total,
        counts_json=json.dumps({opt_a.id: 7, opt_b.id: 3}),
        total=total,
        result_digest=digest,
        signature=sig,
        signer_certificate=cert_der,
        signer_public_key=pub_key,
        published_at=now,
    )
    session.add(snap1)
    session.commit()

    return vote, opt_a, opt_b, snap1, cert_der, pub_key, now


def test_get_latest_result_returns_highest_version_with_all_options():
    session = _setup_db()
    crypto = VerificationMockCryptoEngine()
    vote, opt_a, opt_b, snap1, cert_der, pub_key, now = _seed_vote_and_snapshot(session, crypto)

    service = VoteResultService(session)
    res = service.get_latest(vote_id=vote.id, now=now)

    assert isinstance(res, VoteResult)
    assert res.vote_id == vote.id
    assert res.total == 10
    assert res.counts[opt_a.id] == 7
    assert res.counts[opt_b.id] == 3
    assert res.signature == base64.b64encode(snap1.signature).decode("ascii")
    assert res.signer_certificate == base64.b64encode(cert_der).decode("ascii")

    # Add higher version
    opt_c = VoteOption(vote_id=vote.id, label="选项C", position=2)
    session.add(opt_c)
    session.commit()

    snap2 = VoteResultSnapshot(
        vote_id=vote.id,
        version=11,
        counts_json=json.dumps({opt_a.id: 7, opt_b.id: 3, opt_c.id: 1}),
        total=11,
        result_digest=b"\x99" * 32,
        signature=b"\x88" * 64,
        signer_certificate=cert_der,
        signer_public_key=pub_key,
        published_at=now + timedelta(minutes=5),
    )
    session.add(snap2)
    session.commit()

    res2 = service.get_latest(vote_id=vote.id, now=now)
    assert res2.total == 11
    assert res2.counts[opt_c.id] == 1


def test_get_latest_result_not_found_cases():
    session = _setup_db()
    service = VoteResultService(session)
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Non-existent vote
    with pytest.raises(VoteResultServiceError) as exc_nf:
        service.get_latest(vote_id=str(uuid.uuid4()), now=now)
    assert exc_nf.value.code == "vote_not_found"

    # 2. Vote exists but no snapshots
    vote = VoteRecord(
        creator_id=str(uuid.uuid4()),
        title="未计票投票",
        scope="public",
        closes_at=now + timedelta(days=1),
        status="open",
        created_at=now,
    )
    session.add(vote)
    session.commit()

    with pytest.raises(VoteResultServiceError) as exc_ns:
        service.get_latest(vote_id=vote.id, now=now)
    assert exc_ns.value.code == "result_not_found"

    # 3. Non-public vote returns vote_not_found (404)
    vote_class = VoteRecord(
        creator_id=str(uuid.uuid4()),
        title="班级投票",
        scope="class",
        scope_id=str(uuid.uuid4()),
        closes_at=now + timedelta(days=1),
        status="open",
        created_at=now,
    )
    session.add(vote_class)
    session.commit()

    with pytest.raises(VoteResultServiceError) as exc_priv:
        service.get_latest(vote_id=vote_class.id, now=now)
    assert exc_priv.value.code == "vote_not_found"


def test_verify_result_success():
    session = _setup_db()
    crypto = VerificationMockCryptoEngine()
    vote, opt_a, opt_b, snap1, cert_der, pub_key, now = _seed_vote_and_snapshot(session, crypto)

    verifier = VoteResultVerificationService(session=session, crypto_engine=crypto)
    res = verifier.verify(vote_id=vote.id, now=now)

    assert isinstance(res, SignatureVerification)
    assert res.valid is True
    assert res.algorithm == "SM3-with-SM2"
    assert res.certificate_valid is True
    assert "通过" in res.message


def test_verify_result_tampering_detections():
    session = _setup_db()
    crypto = VerificationMockCryptoEngine()
    vote, opt_a, opt_b, snap1, cert_der, pub_key, now = _seed_vote_and_snapshot(session, crypto)

    verifier = VoteResultVerificationService(session=session, crypto_engine=crypto)

    # 1. Tamper counts_json
    snap1.counts_json = json.dumps({opt_a.id: 8, opt_b.id: 2})
    session.commit()
    res1 = verifier.verify(vote_id=vote.id, now=now)
    assert res1.valid is False

    # Restore counts
    snap1.counts_json = json.dumps({opt_a.id: 7, opt_b.id: 3})
    session.commit()

    # 2. Tamper total
    snap1.total = 11
    session.commit()
    res2 = verifier.verify(vote_id=vote.id, now=now)
    assert res2.valid is False
    snap1.total = 10
    session.commit()

    # 3. Tamper digest
    snap1.result_digest = b"\xff" * 32
    session.commit()
    res3 = verifier.verify(vote_id=vote.id, now=now)
    assert res3.valid is False

    # 4. Tamper signature
    snap1.result_digest = crypto.sm3_digest(encode_vote_result(
        vote_id=vote.id,
        ordered_counts=((opt_a.id, 7), (opt_b.id, 3)),
        total=10,
        published_at=snap1.published_at,
    ))
    snap1.signature = b"\x00" * 64
    session.commit()
    res4 = verifier.verify(vote_id=vote.id, now=now)
    assert res4.valid is False

    # 5. Revoked certificate
    snap1.signature = b"\x88" * 64
    cert_rec = session.query(CertificateRecord).filter_by(certificate_der=cert_der).one()
    cert_rec.status = "revoked"
    cert_rec.revoked_at = now
    cert_rec.revocation_reason = "keyCompromise"
    session.commit()
    res5 = verifier.verify(vote_id=vote.id, now=now)
    assert res5.valid is False
    assert res5.certificate_valid is False


def test_verify_result_provider_unavailable():
    session = _setup_db()
    crypto = VerificationMockCryptoEngine()
    vote, opt_a, opt_b, snap1, cert_der, pub_key, now = _seed_vote_and_snapshot(session, crypto)

    class FailingCrypto(VerificationMockCryptoEngine):
        def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
            raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE)

    failing_crypto = FailingCrypto()
    verifier = VoteResultVerificationService(session=session, crypto_engine=failing_crypto)

    with pytest.raises(VoteResultServiceError) as exc:
        verifier.verify(vote_id=vote.id, now=now)
    assert exc.value.code == "engine_unavailable"
