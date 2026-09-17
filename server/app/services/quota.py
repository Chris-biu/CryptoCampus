from contextlib import contextmanager
from datetime import datetime, time, timedelta, timezone
import json
from threading import Lock
from typing import Any, Callable, Iterator
import uuid

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.admin_governance import AdminQuotaResetIdempotency
from app.models.audit import AuditLog
from app.models.credential import CredentialLedger
from app.models.user import User
from app.schemas.quota import Quota


RESOURCE_LIMITS = {
    "hole_credential": 5,
    "interaction_credential": 20,
    "drop": 20,
    "vote_ballot": 1,
}
_DAILY_RESOURCES = tuple(resource for resource in RESOURCE_LIMITS if resource != "vote_ballot")


class QuotaError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class QuotaResetIdempotencyStore:
    def __init__(self) -> None:
        self._completed: set[tuple[str, str, str]] = set()
        self._lock = Lock()

    @contextmanager
    def reserve(self, actor_id: str, target_id: str, key: str) -> Iterator[None]:
        if not isinstance(key, str) or not 16 <= len(key) <= 128:
            raise QuotaError("idempotency_invalid")
        pair = (actor_id, target_id, key)
        with self._lock:
            if pair in self._completed:
                raise QuotaError("conflict")
            yield
            self._completed.add(pair)


class QuotaService:
    def __init__(
        self,
        session: Session,
        digest: Callable[[bytes], bytes] | None = None,
        idempotency_store: QuotaResetIdempotencyStore | None = None,
        audit_chain_service: Any = None,
    ) -> None:
        self.session = session
        self.digest = digest
        self.idempotency_store = idempotency_store or QuotaResetIdempotencyStore()
        self.audit_chain_service = audit_chain_service

    def _calculate_digest(self, data: bytes) -> bytes:
        if self.digest is not None:
            return self.digest(data)
        import hashlib
        return hashlib.sha256(data).digest()

    def reserve(self, user_id: str, resource: str, now: datetime, period: str | None = None) -> None:
        limit = RESOURCE_LIMITS.get(resource)
        normalized_period = self._period(resource, now, period)
        if limit is None:
            raise QuotaError("resource_invalid")
        try:
            with self._transaction():
                result = self.session.execute(
                    update(CredentialLedger)
                    .where(
                        CredentialLedger.user_id == user_id,
                        CredentialLedger.service == resource,
                        CredentialLedger.period == normalized_period,
                        CredentialLedger.issued_count < limit,
                    )
                    .values(issued_count=CredentialLedger.issued_count + 1)
                )
                if result.rowcount == 1:
                    return
                existing = self.session.query(CredentialLedger).filter_by(
                    user_id=user_id, service=resource, period=normalized_period
                ).one_or_none()
                if existing is not None:
                    raise QuotaError("exhausted")
                try:
                    with self.session.begin_nested():
                        self.session.add(
                            CredentialLedger(
                                user_id=user_id,
                                service=resource,
                                period=normalized_period,
                                issued_count=1,
                            )
                        )
                        self.session.flush()
                except IntegrityError:
                    result = self.session.execute(
                        update(CredentialLedger)
                        .where(
                            CredentialLedger.user_id == user_id,
                            CredentialLedger.service == resource,
                            CredentialLedger.period == normalized_period,
                            CredentialLedger.issued_count < limit,
                        )
                        .values(issued_count=CredentialLedger.issued_count + 1)
                    )
                    if result.rowcount != 1:
                        raise QuotaError("exhausted") from None
        except QuotaError:
            raise
        except Exception as error:
            raise QuotaError("internal") from error

    def get(self, user_id: str, now: datetime) -> list[Quota]:
        period = self._utc(now).date().isoformat()
        counts = {
            item.service: item.issued_count
            for item in self.session.query(CredentialLedger).filter(
                CredentialLedger.user_id == user_id,
                CredentialLedger.period == period,
                CredentialLedger.service.in_(_DAILY_RESOURCES),
            )
        }
        return [Quota(resource=resource, used=counts.get(resource, 0), limit=RESOURCE_LIMITS[resource]) for resource in _DAILY_RESOURCES]

    def reset(self, user_id: str, actor_id: str, idempotency_key: str, now: datetime) -> list[Quota]:
        if not isinstance(idempotency_key, str) or not 16 <= len(idempotency_key) <= 128:
            raise QuotaError("idempotency_invalid")
        period = self._utc(now).date().isoformat()
        key_hash = self._calculate_digest(idempotency_key.encode("utf-8"))
        request_hash = self._calculate_digest(f"reset_all_quotas|{user_id}".encode("utf-8"))
        try:
            with self._transaction():
                user = self.session.get(User, user_id)
                if user is None:
                    raise QuotaError("not_found")
                if user.status == "pending_deletion":
                    raise QuotaError("pending_deletion")
                if self.session.get(User, actor_id) is None:
                    raise QuotaError("not_found")

                existing = self.session.query(AdminQuotaResetIdempotency).filter_by(
                    actor_id=actor_id, key_hash=key_hash
                ).first()
                if existing is not None:
                    if existing.target_user_id != user_id or existing.request_hash != request_hash:
                        raise QuotaError("conflict")
                    stored_data = json.loads(existing.response_json)
                    return [Quota.model_validate(item) for item in stored_data]

                self.session.execute(
                    update(CredentialLedger)
                    .where(
                        CredentialLedger.user_id == user_id,
                        CredentialLedger.period == period,
                        CredentialLedger.service.in_(_DAILY_RESOURCES),
                    )
                    .values(issued_count=0)
                )
                quotas = self.get(user_id, now)
                idemp_record = AdminQuotaResetIdempotency(
                    id=str(uuid.uuid4()),
                    actor_id=actor_id,
                    target_user_id=user_id,
                    key_hash=key_hash,
                    request_hash=request_hash,
                    response_json=json.dumps([q.model_dump() for q in quotas]),
                    created_at=self._utc(now),
                )
                self.session.add(idemp_record)

                detail_hash = self._calculate_digest(f"quota.reset|{user_id}|{period}".encode("utf-8"))
                self.session.add(
                    AuditLog(
                        actor=actor_id,
                        action="quota.reset",
                        target=f"user:{user_id}",
                        detail_hash=detail_hash,
                    )
                )
                if self.audit_chain_service is not None:
                    self.audit_chain_service.append(
                        session=self.session,
                        actor_id=actor_id,
                        action="user.quota.reset",
                        target=f"user:{user_id}",
                        detail_hash=detail_hash,
                        timestamp=now,
                    )
                self.session.flush()
                return quotas
        except QuotaError:
            raise
        except Exception as error:
            raise QuotaError("internal") from error

    @staticmethod
    def resets_at(now: datetime) -> datetime:
        date = QuotaService._utc(now).date() + timedelta(days=1)
        return datetime.combine(date, time.min, tzinfo=timezone.utc)

    @staticmethod
    def _period(resource: str, now: datetime, period: str | None) -> str:
        if resource not in RESOURCE_LIMITS:
            raise QuotaError("resource_invalid")
        if resource == "vote_ballot":
            if not isinstance(period, str) or not period or len(period) > 128:
                raise QuotaError("period_invalid")
            return period
        if period is not None:
            raise QuotaError("period_invalid")
        return QuotaService._utc(now).date().isoformat()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        if self.session.in_transaction():
            self.session.connection()
            yield
            return
        with self.session.begin():
            yield

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
