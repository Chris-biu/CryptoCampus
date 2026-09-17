from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator, Protocol, runtime_checkable

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.errors import DropServiceError
from app.models.drop import Drop

COOLDOWN_FAILED_ATTEMPTS_THRESHOLD = 5
COOLDOWN_DURATION_MINUTES = 10


@runtime_checkable
class ExtractAttemptGuard(Protocol):
    def before_attempt(self, drop: Drop, now: datetime) -> None:
        """检查密信状态，若处于冷却期内立即失败关闭，若冷却到期自动恢复。"""
        ...

    def record_failure(self, drop_id: str, now: datetime) -> int:
        """原子递增提取码失败次数，并在达到阈值时触发 10 分钟 UTC 冷却。"""
        ...

    def record_success(self, drop_id: str, now: datetime) -> None:
        """成功提取后原子重置失败次数与冷却截止时间。"""
        ...


class SqlAlchemyExtractCooldownGuard:
    def __init__(self, session: Session) -> None:
        self.session = session

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        if self.session.in_transaction():
            yield
            return
        with self.session.begin():
            yield

    def before_attempt(self, drop: Drop, now: datetime) -> None:
        utc_now = self._utc(now)
        if drop.status == "cooling_down":
            if drop.cooldown_until is not None:
                cooldown_until = self._utc(drop.cooldown_until)
                if utc_now < cooldown_until:
                    raise DropServiceError("cooling_down", "密信不存在或链接已失效")
                else:
                    self.session.execute(
                        update(Drop)
                        .where(Drop.id == drop.id, Drop.status == "cooling_down")
                        .values(status="available", failed_attempts=0, cooldown_until=None)
                    )
                    self.session.commit()
                    drop.status = "available"
                    drop.failed_attempts = 0
                    drop.cooldown_until = None
                    return

        if drop.status != "available":
            raise DropServiceError("not_found", "密信不存在或链接已失效")

    def record_failure(self, drop_id: str, now: datetime) -> int:
        utc_now = self._utc(now)
        # 1. 冷却已到期：原子重置并计为第 1 次失败
        res = self.session.execute(
            update(Drop)
            .where(
                Drop.id == drop_id,
                Drop.status == "cooling_down",
                Drop.cooldown_until <= utc_now,
            )
            .values(status="available", failed_attempts=1, cooldown_until=None)
        )
        if res.rowcount == 1:
            self.session.commit()
            return 1

        # 2. 正常递增（1～4 次失败保持 available）
        res = self.session.execute(
            update(Drop)
            .where(
                Drop.id == drop_id,
                Drop.status == "available",
                Drop.failed_attempts < COOLDOWN_FAILED_ATTEMPTS_THRESHOLD - 1,
            )
            .values(failed_attempts=Drop.failed_attempts + 1)
        )
        if res.rowcount == 1:
            self.session.commit()
            updated_attempts = self.session.execute(
                select(Drop.failed_attempts).where(Drop.id == drop_id)
            ).scalar_one()
            return updated_attempts

        # 3. 达到阈值：第 5 次失败，置为 cooling_down 并设置 10 分钟 UTC 冷却截止时间
        cooldown_until = utc_now + timedelta(minutes=COOLDOWN_DURATION_MINUTES)
        res = self.session.execute(
            update(Drop)
            .where(
                Drop.id == drop_id,
                Drop.status == "available",
                Drop.failed_attempts == COOLDOWN_FAILED_ATTEMPTS_THRESHOLD - 1,
            )
            .values(
                failed_attempts=COOLDOWN_FAILED_ATTEMPTS_THRESHOLD,
                status="cooling_down",
                cooldown_until=cooldown_until,
            )
        )
        if res.rowcount == 1:
            self.session.commit()
            return COOLDOWN_FAILED_ATTEMPTS_THRESHOLD

        # 4. 处于有效冷却中或不可用状态：不超限递增
        self.session.commit()
        drop = self.session.get(Drop, drop_id)
        if drop is not None:
            return drop.failed_attempts
        return 0

    def record_success(self, drop_id: str, now: datetime) -> None:
        del now
        with self._transaction():
            self.session.execute(
                update(Drop)
                .where(Drop.id == drop_id)
                .values(failed_attempts=0, cooldown_until=None)
            )
            self.session.flush()
