from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import time
from typing import Optional
import uuid

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.crypto.engine import CryptoEngine
from app.models.audit import AuditLog
from app.models.vote import (
    AnonymousBallot,
    VoteOption,
    VoteRecord,
    VoteResultSnapshot,
)
from app.services.vote_ballots import get_vote_tally_lock
from app.services.vote_results import (
    VoteResultSigningError,
    sign_vote_result,
)
from app.services.vote_tally_provider import (
    VoteTallyMaterialProvider,
    VoteTallyMaterialUnavailableError,
)


class FakeClock:
    """可注入的确定性测试时钟，保证 UTC 时区。"""

    def __init__(self, initial_time: Optional[datetime] = None) -> None:
        if initial_time is None:
            initial_time = datetime.now(timezone.utc)
        elif initial_time.tzinfo is None:
            initial_time = initial_time.replace(tzinfo=timezone.utc)
        else:
            initial_time = initial_time.astimezone(timezone.utc)
        self._current_time = initial_time

    def now(self) -> datetime:
        return self._current_time

    def set(self, new_time: datetime) -> None:
        if new_time.tzinfo is None:
            new_time = new_time.replace(tzinfo=timezone.utc)
        else:
            new_time = new_time.astimezone(timezone.utc)
        self._current_time = new_time

    def advance(self, delta: timedelta) -> None:
        self._current_time += delta

    def __call__(self) -> datetime:
        return self.now()


class VoteSettlementError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class VoteSettlementService:
    def __init__(
        self,
        *,
        crypto_engine: CryptoEngine,
        tally_material_provider: VoteTallyMaterialProvider,
        session: Optional[Session] = None,
        session_factory: Optional[sessionmaker[Session]] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        if session is None and session_factory is None:
            raise ValueError("Either session or session_factory must be provided")
        self.session = session
        self.session_factory = session_factory
        self.crypto_engine = crypto_engine
        self.tally_material_provider = tally_material_provider
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _get_session(self) -> Session:
        if self.session_factory is not None:
            return self.session_factory()
        return self.session  # type: ignore[return-value]

    def _close_session_if_created(self, session: Session) -> None:
        if self.session_factory is not None:
            session.close()

    @contextmanager
    def _transaction(self, session: Session) -> Iterator[Session]:
        if session.in_transaction():
            yield session
        else:
            with session.begin():
                yield session

    def settle(
        self,
        vote_id: str,
        now: Optional[datetime] = None,
    ) -> VoteResultSnapshot:
        """对单场到期投票执行最终结算，生成唯一最终签名快照并更新状态为 published。"""
        if now is None:
            now_utc = self.clock()
        elif now.tzinfo is None:
            now_utc = now.replace(tzinfo=timezone.utc)
        else:
            now_utc = now.astimezone(timezone.utc)

        lock = get_vote_tally_lock(vote_id)
        with lock:
            max_retries = 3
            for attempt in range(max_retries):
                session = self._get_session()
                try:
                    with self._transaction(session):
                        vote = session.get(VoteRecord, vote_id)
                        if vote is None:
                            raise VoteSettlementError("vote_not_found", "投票不存在")

                        # 1. 幂等重放：若已发布且已关联最终快照，直接返回
                        if vote.status == "published" and vote.final_snapshot_id:
                            final_snap = session.get(VoteResultSnapshot, vote.final_snapshot_id)
                            if final_snap is not None:
                                session.expunge(final_snap)
                                if final_snap.published_at.tzinfo is None:
                                    final_snap.published_at = final_snap.published_at.replace(tzinfo=timezone.utc)
                                return final_snap

                        # 检查数据库中是否存在已生成的 final snapshot
                        existing_final = (
                            session.query(VoteResultSnapshot)
                            .filter_by(vote_id=vote_id, is_final=True)
                            .first()
                        )
                        if existing_final is not None:
                            if vote.status != "published" or vote.final_snapshot_id != existing_final.id:
                                vote.status = "published"
                                vote.final_snapshot_id = existing_final.id
                                if vote.settled_at is None:
                                    vote.settled_at = existing_final.published_at
                                session.flush()
                            session.expunge(existing_final)
                            if existing_final.published_at.tzinfo is None:
                                existing_final.published_at = existing_final.published_at.replace(tzinfo=timezone.utc)
                            return existing_final

                        # 2. 状态与截止时间校验：now < closes_at 拒绝结算
                        closes_at_utc = (
                            vote.closes_at.replace(tzinfo=timezone.utc)
                            if vote.closes_at.tzinfo is None
                            else vote.closes_at.astimezone(timezone.utc)
                        )
                        if now_utc < closes_at_utc:
                            raise VoteSettlementError(
                                "vote_not_closed",
                                f"投票尚未截止，截止时间为 {closes_at_utc.isoformat()}，当前时间为 {now_utc.isoformat()}",
                            )

                        # 3. 统计有效选票：防御性过滤 created_at <= closes_at_utc
                        counts_raw = dict(
                            session.query(AnonymousBallot.option_id, func.count(AnonymousBallot.id))
                            .filter(
                                AnonymousBallot.vote_id == vote_id,
                                AnonymousBallot.created_at <= closes_at_utc,
                            )
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

                        # 4. 计算最终快照版本号：max_version + 1
                        max_version = (
                            session.query(func.max(VoteResultSnapshot.version))
                            .filter(VoteResultSnapshot.vote_id == vote_id)
                            .scalar()
                        ) or 0
                        version = max_version + 1

                        # 5. 获取计票台密钥材料并执行 SM2 签名及自验
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

                                # 6. 创建唯一最终快照
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
                                    is_final=True,
                                )
                                session.add(snapshot)
                                session.flush()

                                # 7. 更新投票状态为 published 并记录 settled_at
                                vote.status = "published"
                                vote.settled_at = now_utc
                                vote.final_snapshot_id = snapshot.id

                                # 8. 记录 system 审计日志
                                audit = AuditLog(
                                    actor=material.system_user_id,
                                    action="vote.settle",
                                    target=f"vote:{vote_id}",
                                    detail_hash=result_digest,
                                    ts=now_utc,
                                )
                                session.add(audit)
                                session.flush()

                        except VoteTallyMaterialUnavailableError as err:
                            raise VoteSettlementError(
                                "engine_unavailable", "计票台系统密钥或证书不可用"
                            ) from err
                        except VoteResultSigningError as err:
                            raise VoteSettlementError(err.code, err.message) from err

                    session.commit()
                    session.expunge(snapshot)
                    return snapshot

                except (VoteSettlementError,):
                    session.rollback()
                    raise
                except IntegrityError as ie:
                    session.rollback()
                    # 检查是否已有并发写入的 final snapshot
                    check_sess = self._get_session()
                    try:
                        existing = (
                            check_sess.query(VoteResultSnapshot)
                            .filter_by(vote_id=vote_id, is_final=True)
                            .first()
                        )
                        if existing is not None:
                            check_sess.expunge(existing)
                            if existing.published_at.tzinfo is None:
                                existing.published_at = existing.published_at.replace(tzinfo=timezone.utc)
                            return existing
                    finally:
                        self._close_session_if_created(check_sess)

                    if attempt < max_retries - 1:
                        time.sleep(0.01 * (attempt + 1))
                        continue
                    raise VoteSettlementError("conflict", "结算数据唯一性约束冲突") from ie
                except OperationalError:
                    session.rollback()
                    if attempt < max_retries - 1:
                        time.sleep(0.02 * (attempt + 1))
                        continue
                    raise
                finally:
                    self._close_session_if_created(session)

        raise VoteSettlementError("unknown_error", "结算未能完成")

    def settle_due(
        self,
        limit: int = 50,
        now: Optional[datetime] = None,
    ) -> list[VoteResultSnapshot]:
        """扫描已截止未发布的投票并批量执行最终结算。"""
        if now is None:
            now_utc = self.clock()
        elif now.tzinfo is None:
            now_utc = now.replace(tzinfo=timezone.utc)
        else:
            now_utc = now.astimezone(timezone.utc)

        session = self._get_session()
        try:
            due_votes = (
                session.query(VoteRecord.id)
                .filter(
                    VoteRecord.status != "published",
                    VoteRecord.final_snapshot_id.is_(None),
                    VoteRecord.closes_at <= now_utc,
                )
                .order_by(VoteRecord.closes_at.asc())
                .limit(limit)
                .all()
            )
            due_vote_ids = [v[0] for v in due_votes]
        finally:
            self._close_session_if_created(session)

        settled_snapshots: list[VoteResultSnapshot] = []
        for vote_id in due_vote_ids:
            try:
                snap = self.settle(vote_id=vote_id, now=now_utc)
                settled_snapshots.append(snap)
            except VoteSettlementError as err:
                if err.code in ("vote_not_closed", "conflict"):
                    continue
                raise

        return settled_snapshots
