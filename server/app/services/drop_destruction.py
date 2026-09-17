from datetime import datetime, timezone
from typing import Iterator
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.errors import DropServiceError
from app.crypto.engine import CryptoEngine
from app.models.audit import AuditLog
from app.models.drop import Drop
from app.schemas.inspect import InspectEvent, InspectStepInput
from app.services.inspection import InspectionRecorder, get_inspection_recorder


class DropDestructionService:
    """
    密信销毁服务：负责阅后即焚成功提取后的原子销毁，以及到期密信的有界批量清理。
    包含敏感材料置空与不可逆 SM3 审计摘要生成。
    """

    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        recorder: InspectionRecorder | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.recorder = recorder or get_inspection_recorder()

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

    def _build_destruction_audit(
        self,
        drop: Drop,
        *,
        reason: str,
        now: datetime,
        actor_id: str | None = None,
    ) -> AuditLog:
        utc_now = self._utc(now)
        drop_id_hash = self.crypto_engine.sm3_digest(drop.id.encode("utf-8")).hex()
        # Non-reversible detail hash using SM3
        summary = f"drop.destroy|{reason}|{drop_id_hash}|{utc_now.isoformat()}".encode("utf-8")
        detail_hash = self.crypto_engine.sm3_digest(summary)

        actor = actor_id or drop.owner_user_id
        return AuditLog(
            actor=actor,
            action="drop.destroy",
            target=f"drop:{drop.id}",
            detail_hash=detail_hash,
            ts=utc_now,
        )

    def destroy_after_success(
        self,
        drop_id: str,
        *,
        now: datetime,
        actor_id: str | None = None,
    ) -> None:
        """
        原子将 status == 'available' 的阅后即焚密信置为 'consumed' 并清理敏感信封材料与记录审计日志。
        若被并发消耗（rowcount != 1），抛出 not_found 错误触发回滚。
        """
        utc_now = self._utc(now)
        drop = self.session.get(Drop, drop_id)
        if drop is None or drop.status != "available":
            raise DropServiceError("not_found", "密信不存在或链接已失效")

        result = self.session.execute(
            update(Drop)
            .where(Drop.id == drop_id, Drop.status == "available")
            .values(
                status="consumed",
                ciphertext=None,
                nonce=None,
                tag=None,
                enc_key_sm2=None,
                enc_key_mlkem=None,
                sender_signature=None,
                sender_certificate_der=None,
                access_factor_salt=None,
            )
        )
        if result.rowcount != 1:
            raise DropServiceError("not_found", "密信不存在或链接已失效")

        audit = self._build_destruction_audit(
            drop,
            reason="burn_after_read",
            now=utc_now,
            actor_id=actor_id or drop.recipient_user_id,
        )
        self.session.add(audit)

        import uuid as _uuid
        owner_uuid = _uuid.UUID(drop.owner_user_id) if drop.owner_user_id else None
        self.recorder.record(
            event=InspectEvent(
                operation="drop.destroy",
                owner_user_id=owner_uuid,
                steps=(
                    InspectStepInput(
                        order=1,
                        name="阅后即焚密信销毁",
                        algorithm="SM4",
                        result="passed",
                        redacted_values={
                            "reason_code": "extracted",
                            "ciphertext_bytes_cleared": len(drop.ciphertext) if drop.ciphertext else 0,
                        },
                    ),
                ),
                occurred_at=utc_now,
            ),
            session=self.session,
        )
        self.session.flush()

    def destroy_expired(
        self,
        *,
        now: datetime,
        limit: int = 100,
        actor_id: str | None = None,
    ) -> int:
        """
        有界扫描并幂等清理到期密信（status in ('available', 'cooling_down') 且 expires_at <= now）。
        返回本次清理的密信数量。
        """
        if limit <= 0:
            return 0
        utc_now = self._utc(now)

        query = (
            select(Drop)
            .where(
                Drop.status.in_(["available", "cooling_down"]),
                Drop.expires_at.is_not(None),
                Drop.expires_at <= utc_now,
            )
            .order_by(Drop.expires_at.asc())
            .limit(limit)
        )
        expired_drops = self.session.scalars(query).all()
        if not expired_drops:
            return 0

        destroyed_count = 0
        for drop in expired_drops:
            res = self.session.execute(
                update(Drop)
                .where(
                    Drop.id == drop.id,
                    Drop.status.in_(["available", "cooling_down"]),
                )
                .values(
                    status="expired",
                    ciphertext=None,
                    nonce=None,
                    tag=None,
                    enc_key_sm2=None,
                    enc_key_mlkem=None,
                    sender_signature=None,
                    sender_certificate_der=None,
                    access_factor_salt=None,
                )
            )
            if res.rowcount == 1:
                audit = self._build_destruction_audit(
                    drop,
                    reason="expired",
                    now=utc_now,
                    actor_id=actor_id or drop.owner_user_id,
                )
                self.session.add(audit)
                destroyed_count += 1

        self.session.flush()
        return destroyed_count

    def destroy_single_expired(
        self,
        drop_id: str,
        *,
        now: datetime,
        actor_id: str | None = None,
    ) -> bool:
        """
        请求触发单条到期密信原子清理。
        """
        utc_now = self._utc(now)
        drop = self.session.get(Drop, drop_id)
        if drop is None:
            return False
        if drop.expires_at is None:
            return False
        exp = self._utc(drop.expires_at)
        if exp > utc_now:
            return False
        if drop.status not in ("available", "cooling_down"):
            return False

        res = self.session.execute(
            update(Drop)
            .where(
                Drop.id == drop_id,
                Drop.status.in_(["available", "cooling_down"]),
            )
            .values(
                status="expired",
                ciphertext=None,
                nonce=None,
                tag=None,
                enc_key_sm2=None,
                enc_key_mlkem=None,
                sender_signature=None,
                sender_certificate_der=None,
                access_factor_salt=None,
            )
        )
        if res.rowcount == 1:
            audit = self._build_destruction_audit(
                drop,
                reason="expired",
                now=utc_now,
                actor_id=actor_id or drop.owner_user_id,
            )
            self.session.add(audit)

            import uuid as _uuid
            owner_uuid = _uuid.UUID(drop.owner_user_id) if drop.owner_user_id else None
            self.recorder.record(
                event=InspectEvent(
                    operation="drop.destroy",
                    owner_user_id=owner_uuid,
                    steps=(
                        InspectStepInput(
                            order=1,
                            name="到期密信销毁",
                            algorithm="SM4",
                            result="passed",
                            redacted_values={
                                "reason_code": "expired",
                                "ciphertext_bytes_cleared": len(drop.ciphertext) if drop.ciphertext else 0,
                            },
                        ),
                    ),
                    occurred_at=utc_now,
                ),
                session=self.session,
            )
            self.session.flush()
            return True
        return False
