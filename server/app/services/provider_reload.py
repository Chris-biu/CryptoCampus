import asyncio
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
import logging
from typing import Callable

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.crypto.types import ProviderStatus
from app.models.audit import AuditLog
from app.models.provider_reload import ProviderReloadIdempotency
from app.schemas.system import SystemStatus
from app.services.system_status import map_provider_status_to_system_status

logger = logging.getLogger(__name__)


class ProviderReloadError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class ProviderReloadValidationError(ProviderReloadError):
    def __init__(self, message: str = "Idempotency-Key 格式不合法") -> None:
        super().__init__(422, "VALIDATION_ERROR", message)


class ProviderReloadConflictError(ProviderReloadError):
    def __init__(self, message: str = "同 Idempotency-Key 已用于不同请求") -> None:
        super().__init__(409, "CONFLICT", message)


class ProviderReloadTimeoutError(ProviderReloadError):
    def __init__(self, message: str = "Provider 重载操作超时，请稍后重试") -> None:
        super().__init__(503, "PROVIDER_UNAVAILABLE", message)


class ProviderReloadUnavailableError(ProviderReloadError):
    def __init__(self, message: str = "当前环境不支持 Provider 重载或服务暂不可用") -> None:
        super().__init__(503, "PROVIDER_UNAVAILABLE", message)


class ProviderReloadSelfTestError(ProviderReloadError):
    def __init__(self, message: str = "Provider 重载自检失败") -> None:
        super().__init__(503, "PROVIDER_UNAVAILABLE", message)


class ProviderReloadFailedError(ProviderReloadError):
    def __init__(self, message: str = "Provider 重载失败") -> None:
        super().__init__(503, "PROVIDER_UNAVAILABLE", message)


class ProviderReloadDatabaseError(ProviderReloadError):
    def __init__(self, message: str = "服务器内部错误") -> None:
        super().__init__(500, "INTERNAL_ERROR", message)


class ProviderReloadDegradedFatalError(ProviderReloadError):
    def __init__(self, message: str = "Provider 状态异常且恢复失败") -> None:
        super().__init__(503, "PROVIDER_UNAVAILABLE", message)


class ProviderOperationLock:
    def __init__(self, timeout: float = 5.0) -> None:
        self._lock = asyncio.Lock()
        self.timeout = timeout

    async def acquire(self, timeout: float | None = None) -> bool:
        t = timeout if timeout is not None else self.timeout
        try:
            await asyncio.wait_for(self._lock.acquire(), timeout=t)
            return True
        except (asyncio.TimeoutError, TimeoutError):
            return False

    def release(self) -> None:
        if self._lock.locked():
            self._lock.release()

    @asynccontextmanager
    async def acquire_context(self, timeout: float | None = None):
        acquired = await self.acquire(timeout)
        if not acquired:
            raise ProviderReloadTimeoutError()
        try:
            yield
        finally:
            self.release()


def compute_key_hash(engine: CryptoEngine, idempotency_key: str) -> bytes:
    return engine.sm3_digest(idempotency_key.encode("utf-8"))


def compute_reload_request_hash(engine: CryptoEngine, actor_id: str) -> bytes:
    return engine.sm3_digest(f"provider.reload.pqc|{actor_id}|v1".encode("utf-8"))


def compute_reload_audit_detail_hash(
    engine: CryptoEngine,
    domain: str,
    actor_id: str,
    before: ProviderStatus,
    after: ProviderStatus,
    now: datetime,
) -> bytes:
    before_caps = ",".join(f"{k}:{v}" for k, v in sorted(before.capabilities.items()))
    after_caps = ",".join(f"{k}:{v}" for k, v in sorted(after.capabilities.items()))
    payload = (
        f"{domain}\x00"
        f"{actor_id}\n"
        f"{before.state}|{before.version}|{before_caps}\n"
        f"{after.state}|{after.version}|{after_caps}\n"
        f"{now.isoformat()}"
    ).encode("utf-8")
    return engine.sm3_digest(payload)


class ProviderReloadService:
    def __init__(
        self,
        *,
        engine: CryptoEngine,
        session: Session | None = None,
        session_factory: Callable[[], Session] | None = None,
        lock: ProviderOperationLock | None = None,
    ) -> None:
        self._engine = engine
        self._session = session
        self._session_factory = session_factory
        if self._session is None and self._session_factory is None:
            raise ValueError("Either session or session_factory must be provided")
        self._lock = lock or ProviderOperationLock()

    @contextmanager
    def _get_session(self):
        if self._session is not None:
            yield self._session
        else:
            assert self._session_factory is not None
            sess = self._session_factory()
            try:
                yield sess
            finally:
                sess.close()

    def _query_idempotency(
        self, actor_id: str, key_hash: bytes, request_hash: bytes
    ) -> SystemStatus | None:
        with self._get_session() as session:
            record = (
                session.query(ProviderReloadIdempotency)
                .filter_by(actor_id=actor_id, key_hash=key_hash)
                .first()
            )
            if record is None:
                return None
            if record.request_hash != request_hash:
                raise ProviderReloadConflictError()
            return SystemStatus.model_validate_json(record.response_json)


    async def reload(
        self,
        *,
        actor_id: str,
        idempotency_key: str,
        now: datetime,
    ) -> SystemStatus:
        if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
            raise ProviderReloadValidationError()

        try:
            key_hash = compute_key_hash(self._engine, idempotency_key)
            request_hash = compute_reload_request_hash(self._engine, actor_id)
        except CryptoBridgeError as cbe:
            logger.warning("Engine unavailable when hashing idempotency key: %s", cbe.code)
            raise ProviderReloadUnavailableError() from cbe


        # 1. 锁外查幂等
        cached = self._query_idempotency(actor_id, key_hash, request_hash)
        if cached is not None:
            return cached

        # 2. 获取进程内锁（带超时）
        async with self._lock.acquire_context():
            # 3. 锁内双重检查幂等
            cached = self._query_idempotency(actor_id, key_hash, request_hash)
            if cached is not None:
                return cached

            # 4. 读取 before status
            before_status = self._engine.provider_status()

            # 5. 调用受控 reload
            try:
                self._engine.reload_pqc_provider()
            except CryptoBridgeError as cbe:
                logger.warning("Provider reload bridge error: %s", cbe.code)
                raise ProviderReloadUnavailableError() from cbe
            except Exception as exc:
                logger.warning(
                    "Unexpected error during provider reload: %s",
                    exc.__class__.__name__,
                )
                raise ProviderReloadFailedError() from exc

            # 6. 读取 after status
            after_status = self._engine.provider_status()

            # 7. 映射到 SystemStatus
            system_status = map_provider_status_to_system_status(
                after_status, get_settings().app_version
            )

            # 8. 开启 DB 事务写入幂等记录与审计日志
            detail_hash = compute_reload_audit_detail_hash(
                self._engine,
                "CryptoCampus-Provider-Reload-Audit-v1",
                actor_id,
                before_status,
                after_status,
                now,
            )

            with self._get_session() as session:
                try:
                    idemp_record = ProviderReloadIdempotency(
                        actor_id=actor_id,
                        key_hash=key_hash,
                        request_hash=request_hash,
                        response_json=system_status.model_dump_json(),
                        outcome="success",
                        created_at=now,
                    )
                    session.add(idemp_record)
                    audit_record = AuditLog(
                        actor=actor_id,
                        action="provider.reload",
                        target="provider:pqc",
                        detail_hash=detail_hash,
                        ts=now,
                    )
                    session.add(audit_record)
                    session.commit()
                except Exception as db_err:
                    session.rollback()
                    logger.error(
                        "Database transaction failed during provider reload: %s", db_err
                    )
                    # 尝试补偿恢复外部状态
                    try:
                        if hasattr(self._engine, "restore"):
                            getattr(self._engine, "restore")(before_status)
                    except Exception as restore_err:
                        logger.error(
                            "Provider restore failed after DB failure: %s", restore_err
                        )
                        raise ProviderReloadDegradedFatalError() from restore_err
                    raise ProviderReloadDatabaseError() from db_err


            return system_status
