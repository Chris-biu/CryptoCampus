import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import threading
import time
from typing import Iterator, Optional
import uuid

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.crypto.engine import CryptoEngine
from app.models.audit import AuditLog
from app.models.credential import ConsumedSN
from app.models.vote import (
    AnonymousBallot,
    BallotIdempotency,
    VoteOption,
    VoteRecord,
    VoteResultSnapshot,
)
from app.schemas.vote import Accepted, VoteCredentialProof
from app.services.vote_ballot_verification import (
    VoteBallotVerificationError,
    verify_vote_ballot,
)
from app.services.vote_results import (
    VoteResultSigningError,
    sign_vote_result,
)
from app.services.vote_signer import VoteSignerMaterialProvider
from app.services.vote_tally_provider import (
    VoteTallyMaterialProvider,
    VoteTallyMaterialUnavailableError,
)

IDEMP_DOMAIN = b"CryptoCampus-Ballot-Idemp-v1\x00"

_TALLY_LOCKS: dict[str, threading.Lock] = {}
_GLOBAL_LOCK = threading.Lock()


def get_vote_tally_lock(vote_id: str) -> threading.Lock:
    with _GLOBAL_LOCK:
        if vote_id not in _TALLY_LOCKS:
            _TALLY_LOCKS[vote_id] = threading.Lock()
        return _TALLY_LOCKS[vote_id]


class AnonymousBallotServiceError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def compute_ballot_request_hash(
    *,
    crypto_engine: CryptoEngine,
    vote_id: str,
    option_id: str,
    credential: VoteCredentialProof,
) -> bytes:
    canonical_b64_sig = base64.b64encode(
        base64.b64decode(credential.signature, validate=True)
    ).decode("ascii")
    payload = (
        IDEMP_DOMAIN
        + uuid.UUID(vote_id).bytes
        + uuid.UUID(option_id).bytes
        + bytes.fromhex(credential.sn.lower())
        + credential.service.encode("ascii")
        + credential.period.encode("ascii")
        + canonical_b64_sig.encode("ascii")
    )
    return crypto_engine.sm3_digest(payload)


class AnonymousBallotService:
    def __init__(
        self,
        *,
        crypto_engine: CryptoEngine,
        signer_provider: VoteSignerMaterialProvider,
        tally_material_provider: VoteTallyMaterialProvider,
        session: Optional[Session] = None,
        session_factory: Optional[sessionmaker[Session]] = None,
    ) -> None:
        if session is None and session_factory is None:
            raise ValueError("Either session or session_factory must be provided")
        self.session = session
        self.session_factory = session_factory
        self.crypto_engine = crypto_engine
        self.signer_provider = signer_provider
        self.tally_material_provider = tally_material_provider

    def submit(
        self,
        *,
        vote_id: str,
        option_id: str,
        credential: VoteCredentialProof,
        idempotency_key: str,
        now: datetime,
    ) -> Accepted:
        # 1. Validate Idempotency-Key
        if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
            raise AnonymousBallotServiceError("invalid_idempotency_key", "幂等键长度必须在 16 至 128 字符之间")

        now_utc = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)

        # 2. Compute key_hash and request_hash
        key_hash = self.crypto_engine.sm3_digest(idempotency_key.encode("utf-8"))
        try:
            request_hash = compute_ballot_request_hash(
                crypto_engine=self.crypto_engine,
                vote_id=vote_id,
                option_id=option_id,
                credential=credential,
            )
        except Exception as err:
            raise AnonymousBallotServiceError("invalid_payload", f"选票请求摘要计算失败: {err}") from err

        # 3. Pre-check idempotency on available session (before stateless verify or locks)
        check_session = self._get_session()
        try:
            existing_idemp = (
                check_session.query(BallotIdempotency)
                .filter_by(key_hash=key_hash)
                .one_or_none()
            )
            if existing_idemp is not None:
                if self.crypto_engine.constant_time_equal(existing_idemp.request_hash, request_hash):
                    return Accepted(accepted=True)
                raise AnonymousBallotServiceError("idempotency_conflict", "同一幂等键已用于不同选票请求")
        finally:
            self._close_session_if_created(check_session)

        # 4. Stateless / read-only verify credential
        verify_sess = self._get_session()
        try:
            verified = verify_vote_ballot(
                session=verify_sess,
                crypto_engine=self.crypto_engine,
                signer_provider=self.signer_provider,
                vote_id=vote_id,
                option_id=option_id,
                credential=credential,
                now=now_utc,
            )
        except VoteBallotVerificationError as err:
            raise AnonymousBallotServiceError(err.code, err.message) from err
        finally:
            self._close_session_if_created(verify_sess)

        # 5. Acquire write lock and execute atomic transaction
        lock = get_vote_tally_lock(vote_id)
        with lock:
            max_retries = 3
            for attempt in range(max_retries):
                session = self._get_session()
                try:
                    with self._transaction(session):
                        # 5.1 Re-check idempotency under lock
                        idemp_rec = (
                            session.query(BallotIdempotency)
                            .filter_by(key_hash=key_hash)
                            .one_or_none()
                        )
                        if idemp_rec is not None:
                            if self.crypto_engine.constant_time_equal(idemp_rec.request_hash, request_hash):
                                return Accepted(accepted=True)
                            raise AnonymousBallotServiceError("idempotency_conflict", "同一幂等键已用于不同选票请求")

                        # 5.2 Re-check vote and option
                        current_vote = session.get(VoteRecord, vote_id)
                        if current_vote is None or current_vote.scope != "public":
                            raise AnonymousBallotServiceError("vote_not_found", "投票不存在或未公开")

                        current_option = session.get(VoteOption, option_id)
                        if current_option is None or current_option.vote_id != vote_id:
                            raise AnonymousBallotServiceError("option_not_found", "选项不存在或不属于该投票")

                        closes_at_utc = (
                            current_vote.closes_at.replace(tzinfo=timezone.utc)
                            if current_vote.closes_at.tzinfo is None
                            else current_vote.closes_at.astimezone(timezone.utc)
                        )
                        if current_vote.status != "open" or now_utc >= closes_at_utc:
                            raise AnonymousBallotServiceError("vote_closed", "投票已截止或未开放")

                        # 5.3 Check ConsumedSN
                        if session.get(ConsumedSN, (verified.sn_bytes, "vote_ballot")) is not None:
                            raise AnonymousBallotServiceError("credential_consumed", "该选票凭证已消费")

                        # 5.4 Insert ConsumedSN
                        consumed = ConsumedSN(
                            sn=verified.sn_bytes,
                            service="vote_ballot",
                            consumed_at=now_utc,
                        )
                        session.add(consumed)

                        # 5.5 Insert AnonymousBallot
                        ballot = AnonymousBallot(
                            id=str(uuid.uuid4()),
                            vote_id=vote_id,
                            option_id=option_id,
                            credential_sn=verified.sn_bytes,
                            credential_service="vote_ballot",
                            credential_period=verified.period,
                            credential_signature=verified.signature_bytes,
                            created_at=now_utc,
                        )
                        session.add(ballot)

                        # 5.6 Insert BallotIdempotency
                        idemp_entry = BallotIdempotency(
                            id=str(uuid.uuid4()),
                            key_hash=key_hash,
                            request_hash=request_hash,
                            ballot_id=ballot.id,
                            created_at=now_utc,
                        )
                        session.add(idemp_entry)
                        session.flush()

                        # 5.7 Aggregate vote counts for all options in this vote
                        counts_raw = dict(
                            session.query(AnonymousBallot.option_id, func.count(AnonymousBallot.id))
                            .filter(AnonymousBallot.vote_id == vote_id)
                            .group_by(AnonymousBallot.option_id)
                            .all()
                        )

                        all_options = (
                            session.query(VoteOption)
                            .filter_by(vote_id=vote_id)
                            .order_by(VoteOption.position.asc())
                            .all()
                        )
                        ordered_counts = tuple(
                            (opt.id, counts_raw.get(opt.id, 0)) for opt in all_options
                        )
                        total = sum(c for _, c in ordered_counts)
                        version = total

                        # 5.8 Sign tally result with tally station material
                        try:
                            with self.tally_material_provider.unlocked() as material:
                                result_digest, signature = sign_vote_result(
                                    crypto_engine=self.crypto_engine,
                                    material=material,
                                    vote_id=vote_id,
                                    ordered_counts=ordered_counts,
                                    total=total,
                                    published_at=now_utc,
                                )

                                # 5.9 Insert VoteResultSnapshot
                                snapshot = VoteResultSnapshot(
                                    id=str(uuid.uuid4()),
                                    vote_id=vote_id,
                                    version=version,
                                    counts_json=json.dumps(dict(ordered_counts)),
                                    total=total,
                                    result_digest=result_digest,
                                    signature=signature,
                                    signer_certificate=material.certificate_der,
                                    signer_public_key=material.public_key,
                                    published_at=now_utc,
                                )
                                session.add(snapshot)

                                # 5.10 Insert AuditLog
                                audit = AuditLog(
                                    actor=material.system_user_id,
                                    action="vote.result.sign",
                                    target=f"vote:{vote_id}",
                                    detail_hash=result_digest,
                                    ts=now_utc,
                                )
                                session.add(audit)
                                session.flush()
                        except VoteTallyMaterialUnavailableError as err:
                            raise AnonymousBallotServiceError("engine_unavailable", "计票台系统密钥或证书不可用") from err
                        except VoteResultSigningError as err:
                            raise AnonymousBallotServiceError(err.code, err.message) from err

                    session.commit()
                    return Accepted(accepted=True)

                except IntegrityError as ie:
                    session.rollback()
                    # Check race condition causes
                    race_idemp = (
                        session.query(BallotIdempotency)
                        .filter_by(key_hash=key_hash)
                        .one_or_none()
                    )
                    if race_idemp is not None:
                        if self.crypto_engine.constant_time_equal(race_idemp.request_hash, request_hash):
                            return Accepted(accepted=True)
                        raise AnonymousBallotServiceError("idempotency_conflict", "同一幂等键已用于不同选票请求") from ie

                    if session.get(ConsumedSN, (verified.sn_bytes, "vote_ballot")) is not None:
                        raise AnonymousBallotServiceError("credential_consumed", "该选票凭证已消费") from ie

                    if attempt < max_retries - 1:
                        time.sleep(0.01 * (attempt + 1))
                        continue
                    raise AnonymousBallotServiceError("conflict", "数据写入唯一性约束冲突") from ie

                except OperationalError:
                    session.rollback()
                    if attempt < max_retries - 1:
                        time.sleep(0.02 * (attempt + 1))
                        continue
                    raise

                except Exception:
                    session.rollback()
                    raise
                finally:
                    self._close_session_if_created(session)

            raise AnonymousBallotServiceError("conflict", "高并发计票重试用尽")

    def _get_session(self) -> Session:
        if self.session_factory is not None:
            return self.session_factory()
        assert self.session is not None
        return self.session

    def _close_session_if_created(self, session: Session) -> None:
        if self.session_factory is not None:
            session.close()

    @contextmanager
    def _transaction(self, session: Session) -> Iterator[None]:
        manager = (
            session.begin_nested()
            if session.in_transaction()
            else session.begin()
        )
        with manager:
            yield
