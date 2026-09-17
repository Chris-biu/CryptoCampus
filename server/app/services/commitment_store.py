import base64
from datetime import datetime, timedelta, timezone
import secrets
from threading import RLock
from typing import NamedTuple

from app.crypto.engine import CryptoEngine


class BlindCommitmentRecord(NamedTuple):
    commitment_id: str
    user_id: str
    service: str
    period: str
    commitment_point: bytes  # 65-byte SM2 uncompressed point (0x04 || X || Y)
    secret_k: bytes  # 32-byte scalar
    expires_at: datetime
    consumed: bool

    @property
    def commitment_point_b64(self) -> str:
        return base64.b64encode(self.commitment_point).decode("ascii")


class BlindCommitmentStoreError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


class BlindCommitmentStore:
    """Thread-safe in-memory store for one-time blind signature commitments."""

    def __init__(self, default_ttl_seconds: int = 600) -> None:
        self._default_ttl = default_ttl_seconds
        self._commitments: dict[str, BlindCommitmentRecord] = {}
        self._lock = RLock()

    def create(
        self,
        *,
        service: str,
        period: str,
        user_id: str,
        crypto_engine: CryptoEngine,
        now: datetime | None = None,
        ttl_seconds: int | None = None,
    ) -> BlindCommitmentRecord:
        now_utc = self._utc(now or datetime.now(timezone.utc))
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        expires_at = now_utc + timedelta(seconds=ttl)

        commitment_id = secrets.token_bytes(16).hex()
        secret_k, commitment_point = crypto_engine.blind_commit()
        if len(secret_k) != 32 or len(commitment_point) != 65 or commitment_point[0] != 0x04:
            raise BlindCommitmentStoreError("engine_invalid", "密码引擎返回的盲签承诺无效")

        record = BlindCommitmentRecord(
            commitment_id=commitment_id,
            user_id=user_id,
            service=service,
            period=period,
            commitment_point=commitment_point,
            secret_k=secret_k,
            expires_at=expires_at,
            consumed=False,
        )

        with self._lock:
            self._cleanup(now_utc)
            self._commitments[commitment_id] = record
        return record

    def get(self, commitment_id: str, now: datetime | None = None) -> BlindCommitmentRecord | None:
        now_utc = self._utc(now or datetime.now(timezone.utc))
        with self._lock:
            record = self._commitments.get(commitment_id)
            if record is None:
                return None
            if now_utc >= record.expires_at:
                self._commitments.pop(commitment_id, None)
                return None
            return record

    def consume(
        self,
        *,
        commitment_id: str,
        user_id: str,
        service: str,
        period: str,
        now: datetime | None = None,
    ) -> BlindCommitmentRecord:
        now_utc = self._utc(now or datetime.now(timezone.utc))
        with self._lock:
            record = self._commitments.get(commitment_id)
            if record is None:
                raise BlindCommitmentStoreError(
                    "commitment_not_found",
                    "commitment 不存在、已过期或已使用",
                )
            if now_utc >= record.expires_at:
                self._commitments.pop(commitment_id, None)
                raise BlindCommitmentStoreError("commitment_expired", "承诺已过期")
            if record.user_id != user_id or record.service != service or record.period != period:
                raise BlindCommitmentStoreError("commitment_mismatch", "承诺绑定的用户、服务或周期不匹配")
            # 在同一把锁下移除，保证同一承诺只能成功消费一次。
            self._commitments.pop(commitment_id, None)
            return record._replace(consumed=True)

    def _cleanup(self, now_utc: datetime) -> None:
        expired = [
            cid for cid, r in self._commitments.items()
            if now_utc >= r.expires_at or (r.consumed and (now_utc - r.expires_at).total_seconds() > 300)
        ]
        for cid in expired:
            self._commitments.pop(cid, None)

    @staticmethod
    def _utc(dt: datetime) -> datetime:
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


# Singleton store for application runtime
_RUNTIME_COMMITMENT_STORE = BlindCommitmentStore()


def get_commitment_store() -> BlindCommitmentStore:
    return _RUNTIME_COMMITMENT_STORE
