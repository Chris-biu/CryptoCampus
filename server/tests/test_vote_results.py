from datetime import datetime, timedelta, timezone
import uuid
import pytest

from app.crypto.engine import CryptoEngine
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE, SM2_PUBLIC_KEY_SIZE
from app.services.vote_results import (
    RESULT_DOMAIN,
    VoteResultEncodingError,
    VoteResultSigningError,
    encode_vote_result,
    sign_vote_result,
)
from app.services.vote_tally_provider import (
    DefaultVoteTallyMaterialProvider,
    VoteTallyMaterial,
    VoteTallyMaterialUnavailableError,
)


class DeterministicCryptoEngine(MockCryptoEngine):
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

    def sm2_sign(self, private_key: bytes, digest: bytes) -> bytes:
        return b"\x77" * 64

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        return signature == (b"\x77" * 64)


def test_encode_vote_result_deterministic_and_ordering():
    vote_id = str(uuid.uuid4())
    opt_a = str(uuid.uuid4())
    opt_b = str(uuid.uuid4())
    now_utc = datetime(2026, 9, 10, 12, 0, 0, 123456, tzinfo=timezone.utc)

    # Position 0: opt_a (5), Position 1: opt_b (10) -> total 15
    ordered_1 = ((opt_a, 5), (opt_b, 10))
    encoded_1 = encode_vote_result(
        vote_id=vote_id,
        ordered_counts=ordered_1,
        total=15,
        published_at=now_utc,
    )

    encoded_2 = encode_vote_result(
        vote_id=vote_id,
        ordered_counts=ordered_1,
        total=15,
        published_at=now_utc,
    )
    assert encoded_1 == encoded_2
    assert encoded_1.startswith(RESULT_DOMAIN)


def test_encode_vote_result_digest_changes_on_any_field_modification():
    crypto = DeterministicCryptoEngine()
    vote_id = str(uuid.uuid4())
    opt_a = str(uuid.uuid4())
    opt_b = str(uuid.uuid4())
    now_utc = datetime(2026, 9, 10, 12, 0, 0, 0, tzinfo=timezone.utc)

    base = encode_vote_result(
        vote_id=vote_id,
        ordered_counts=((opt_a, 1), (opt_b, 2)),
        total=3,
        published_at=now_utc,
    )
    base_digest = crypto.sm3_digest(base)

    # 1. Modify vote_id
    diff_vote = encode_vote_result(
        vote_id=str(uuid.uuid4()),
        ordered_counts=((opt_a, 1), (opt_b, 2)),
        total=3,
        published_at=now_utc,
    )
    assert crypto.sm3_digest(diff_vote) != base_digest

    # 2. Modify option_id
    diff_opt = encode_vote_result(
        vote_id=vote_id,
        ordered_counts=((str(uuid.uuid4()), 1), (opt_b, 2)),
        total=3,
        published_at=now_utc,
    )
    assert crypto.sm3_digest(diff_opt) != base_digest

    # 3. Modify count distribution
    diff_count = encode_vote_result(
        vote_id=vote_id,
        ordered_counts=((opt_a, 2), (opt_b, 1)),
        total=3,
        published_at=now_utc,
    )
    assert crypto.sm3_digest(diff_count) != base_digest

    # 4. Modify published_at
    diff_time = encode_vote_result(
        vote_id=vote_id,
        ordered_counts=((opt_a, 1), (opt_b, 2)),
        total=3,
        published_at=now_utc + timedelta(seconds=1),
    )
    assert crypto.sm3_digest(diff_time) != base_digest


def test_encode_vote_result_rejections_and_validations():
    vote_id = str(uuid.uuid4())
    opt_a = str(uuid.uuid4())
    opt_b = str(uuid.uuid4())
    now_utc = datetime(2026, 9, 10, 12, 0, 0, 0, tzinfo=timezone.utc)

    # 1. Total does not match sum of counts
    with pytest.raises(VoteResultEncodingError, match="总数不符"):
        encode_vote_result(
            vote_id=vote_id,
            ordered_counts=((opt_a, 1), (opt_b, 2)),
            total=4,
            published_at=now_utc,
        )

    # 2. Negative count
    with pytest.raises(VoteResultEncodingError, match="不能为负数"):
        encode_vote_result(
            vote_id=vote_id,
            ordered_counts=((opt_a, -1), (opt_b, 2)),
            total=1,
            published_at=now_utc,
        )

    # 3. Count overflow > 2^64 - 1
    with pytest.raises(VoteResultEncodingError, match="超出上限"):
        encode_vote_result(
            vote_id=vote_id,
            ordered_counts=((opt_a, (1 << 64)),),
            total=(1 << 64),
            published_at=now_utc,
        )

    # 4. Duplicate option_id
    with pytest.raises(VoteResultEncodingError, match="重复选项"):
        encode_vote_result(
            vote_id=vote_id,
            ordered_counts=((opt_a, 1), (opt_a, 2)),
            total=3,
            published_at=now_utc,
        )

    # 5. Non-UTC time or naive datetime
    naive_dt = datetime(2026, 9, 10, 12, 0, 0)
    with pytest.raises(VoteResultEncodingError, match="必须是带时区的 UTC 时间"):
        encode_vote_result(
            vote_id=vote_id,
            ordered_counts=((opt_a, 1), (opt_b, 2)),
            total=3,
            published_at=naive_dt,
        )

    bj_dt = datetime(2026, 9, 10, 20, 0, 0, tzinfo=timezone(timedelta(hours=8)))
    with pytest.raises(VoteResultEncodingError, match="必须是带时区的 UTC 时间"):
        encode_vote_result(
            vote_id=vote_id,
            ordered_counts=((opt_a, 1), (opt_b, 2)),
            total=3,
            published_at=bj_dt,
        )

    # 6. Invalid vote UUID
    with pytest.raises(VoteResultEncodingError, match="非法 UUID"):
        encode_vote_result(
            vote_id="not-a-uuid",
            ordered_counts=((opt_a, 1),),
            total=1,
            published_at=now_utc,
        )


def test_tally_material_security_and_repr():
    priv = b"\x12" * SM2_PRIVATE_KEY_SIZE
    pub = b"\x04" + b"\x34" * (SM2_PUBLIC_KEY_SIZE - 1)
    cert = b"DER-CERT-BYTES"

    material = VoteTallyMaterial(
        system_user_id="sys-tally-01",
        certificate_serial="10001",
        certificate_der=cert,
        public_key=pub,
        private_key=priv,
    )

    # repr must not contain private_key bytes
    rep = repr(material)
    assert "sys-tally-01" in rep
    assert "10001" in rep
    assert priv.hex() not in rep
    assert "private_key" not in rep or "repr=False" in str(type(material))


def test_default_tally_material_provider_fails_closed():
    provider = DefaultVoteTallyMaterialProvider()
    with pytest.raises(VoteTallyMaterialUnavailableError, match="不可用"):
        with provider.unlocked():
            pass


def test_sign_vote_result_success_and_self_verify_failure():
    crypto = DeterministicCryptoEngine()
    priv = b"\x12" * SM2_PRIVATE_KEY_SIZE
    pub = b"\x04" + b"\x34" * (SM2_PUBLIC_KEY_SIZE - 1)
    material = VoteTallyMaterial(
        system_user_id="sys-tally-01",
        certificate_serial="10001",
        certificate_der=b"CERT",
        public_key=pub,
        private_key=priv,
    )

    vote_id = str(uuid.uuid4())
    opt_a = str(uuid.uuid4())
    now_utc = datetime(2026, 9, 10, 12, 0, 0, 0, tzinfo=timezone.utc)

    digest, sig = sign_vote_result(
        crypto_engine=crypto,
        material=material,
        vote_id=vote_id,
        ordered_counts=((opt_a, 5),),
        total=5,
        published_at=now_utc,
    )
    assert len(digest) == 32
    assert len(sig) == 64

    # Now test self-verify failure
    class FailingVerifyCryptoEngine(DeterministicCryptoEngine):
        def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
            return False

    failing_crypto = FailingVerifyCryptoEngine()
    with pytest.raises(VoteResultSigningError, match="自校验失败"):
        sign_vote_result(
            crypto_engine=failing_crypto,
            material=material,
            vote_id=vote_id,
            ordered_counts=((opt_a, 5),),
            total=5,
            published_at=now_utc,
        )
