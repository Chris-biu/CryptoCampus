from datetime import datetime
import threading
from typing import Optional

from app.models.vote import VoteResultSnapshot
from app.services.vote_settlement import VoteSettlementService


class VoteSettlementScheduler:
    """轻量、应用内可控的到期投票自动结算调度器。"""

    def __init__(
        self,
        settlement_service: VoteSettlementService,
        interval_seconds: int = 60,
        batch_size: int = 50,
    ) -> None:
        self.settlement_service = settlement_service
        self.interval_seconds = interval_seconds
        self.batch_size = batch_size
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_running():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="VoteSettlementScheduler"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.settlement_service.settle_due(limit=self.batch_size)
            except Exception:
                # 记录异常并安全保护调度循环
                pass
            self._stop_event.wait(self.interval_seconds)

    def run_once(
        self,
        limit: Optional[int] = None,
        now: Optional[datetime] = None,
    ) -> list[VoteResultSnapshot]:
        """单次同步扫描执行，便于测试与管理命令调用。"""
        return self.settlement_service.settle_due(
            limit=limit or self.batch_size, now=now
        )
