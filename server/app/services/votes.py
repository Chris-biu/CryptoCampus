from contextlib import contextmanager
from datetime import datetime, timezone
import json
from typing import Iterator, Optional
from uuid import uuid4

from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.models.audit import AuditLog
from app.models.user import User
from app.models.vote import VoteCreateIdempotency, VoteOption, VoteRecord
from app.schemas.vote import CreateVoteRequest, Vote, VoteOptionOut, VotePage
from app.services.vote_scope import DefaultVoteScopePolicy, VoteScopeError, VoteScopePolicy


class VoteServiceError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


class VoteService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        scope_policy: Optional[VoteScopePolicy] = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.scope_policy = scope_policy or DefaultVoteScopePolicy(session)

    def create(
        self,
        *,
        creator_id: str,
        request: CreateVoteRequest,
        idempotency_key: str,
        now: datetime,
    ) -> Vote:
        now_utc = self._utc(now)
        closes_at_utc = self._utc(request.closes_at)

        # 1. Idempotency-Key validation (16 to 128 characters)
        if not isinstance(idempotency_key, str) or not (16 <= len(idempotency_key) <= 128):
            raise VoteServiceError("invalid_idempotency_key", "幂等键长度必须在 16 至 128 字符之间")

        # 2. Creator validation
        creator = self.session.get(User, creator_id)
        if creator is None:
            raise VoteServiceError("user_not_found", "用户不存在")
        if creator.status != "active":
            raise VoteServiceError("user_inactive", "用户状态不可用")
        if creator.role not in ("student", "admin", "teacher"):
            raise VoteServiceError("permission_denied", "角色无权创建投票")

        # 3. Scope policy check
        try:
            self.scope_policy.require_can_create(
                user_id=creator_id,
                scope=request.scope,
                scope_id=request.scope_id,
            )
        except VoteScopeError as se:
            raise VoteServiceError(se.code, se.message) from se

        # 4. Closes_at validation (must be strictly in future relative to server UTC now)
        if closes_at_utc <= now_utc:
            raise VoteServiceError("closes_at_in_past", "截止时间必须晚于当前服务端时间")

        # 5. Compute SM3 digests using CryptoEngine (strict: no hashlib)
        key_hash = self.crypto_engine.sm3_digest(idempotency_key.encode("utf-8"))
        canonical_payload = {
            "title": request.title,
            "description": request.description,
            "options": [opt.label for opt in request.options],
            "scope": request.scope,
            "scope_id": request.scope_id,
            "closes_at": closes_at_utc.isoformat(),
        }
        canonical_bytes = json.dumps(
            canonical_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        request_hash = self.crypto_engine.sm3_digest(canonical_bytes)

        # 6. Check existing idempotency record before transaction
        existing = (
            self.session.query(VoteCreateIdempotency)
            .filter_by(creator_id=creator_id, key_hash=key_hash)
            .one_or_none()
        )
        if existing is not None:
            if self.crypto_engine.constant_time_equal(existing.request_hash, request_hash):
                existing_vote = self.session.get(VoteRecord, existing.vote_id)
                if existing_vote is not None:
                    return self._to_schema(existing_vote, now_utc)
                raise VoteServiceError("internal_error", "历史投票记录缺失")
            raise VoteServiceError("idempotency_conflict", "同一幂等键已用于不同创建请求")

        # 7. Atomic transaction for vote, options, idempotency record, and audit log
        try:
            with self._transaction():
                vote_id = str(uuid4())
                vote = VoteRecord(
                    id=vote_id,
                    creator_id=creator_id,
                    title=request.title,
                    description=request.description,
                    scope=request.scope,
                    scope_id=request.scope_id,
                    closes_at=closes_at_utc,
                    status="open",
                    created_at=now_utc,
                )
                self.session.add(vote)
                self.session.flush()

                # Persist options preserving requested order
                for pos, opt_req in enumerate(request.options):
                    opt = VoteOption(
                        id=str(uuid4()),
                        vote_id=vote_id,
                        label=opt_req.label,
                        position=pos,
                    )
                    self.session.add(opt)

                # Write idempotency record
                idemp = VoteCreateIdempotency(
                    id=str(uuid4()),
                    creator_id=creator_id,
                    key_hash=key_hash,
                    request_hash=request_hash,
                    vote_id=vote_id,
                    created_at=now_utc,
                )
                self.session.add(idemp)

                # Write audit log with SM3 digest (no sensitive plaintext)
                detail_hash = self.crypto_engine.sm3_digest(
                    f"vote.create|{creator_id}|{vote_id}|{key_hash.hex()}".encode("utf-8")
                )
                audit = AuditLog(
                    actor=creator_id,
                    action="vote.create",
                    target=f"vote:{vote_id}",
                    detail_hash=detail_hash,
                    ts=now_utc,
                )
                self.session.add(audit)
                self.session.flush()

            self.session.commit()
            return self._to_schema(vote, now_utc)
        except IntegrityError as ie:
            self.session.rollback()
            # Race condition check on unique constraint
            existing_after_race = (
                self.session.query(VoteCreateIdempotency)
                .filter_by(creator_id=creator_id, key_hash=key_hash)
                .one_or_none()
            )
            if existing_after_race is not None:
                if self.crypto_engine.constant_time_equal(
                    existing_after_race.request_hash, request_hash
                ):
                    existing_vote = self.session.get(VoteRecord, existing_after_race.vote_id)
                    if existing_vote is not None:
                        return self._to_schema(existing_vote, now_utc)
                raise VoteServiceError("idempotency_conflict", "同一幂等键已用于不同创建请求") from ie
            raise VoteServiceError("internal_error", "并发创建数据写入冲突") from ie
        except Exception:
            self.session.rollback()
            raise

    def list_public(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        now: datetime,
    ) -> VotePage:
        now_utc = self._utc(now)
        if page < 1:
            raise VoteServiceError("invalid_pagination", "页码必须大于或等于 1")
        if not (1 <= page_size <= 100):
            raise VoteServiceError("invalid_pagination", "每页大小必须在 1 至 100 之间")

        query = (
            self.session.query(VoteRecord)
            .filter(VoteRecord.scope == "public")
            .order_by(desc(VoteRecord.created_at), desc(VoteRecord.id))
        )
        total = query.count()
        offset = (page - 1) * page_size
        records = query.offset(offset).limit(page_size).all()

        items = [self._to_schema(record, now_utc) for record in records]
        return VotePage(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
        )

    def get_public(
        self,
        *,
        vote_id: str,
        now: datetime,
    ) -> Vote:
        now_utc = self._utc(now)
        vote = self.session.get(VoteRecord, vote_id)
        if vote is None or vote.scope != "public":
            # Before class/group visibility is decided, non-public votes return 404
            raise VoteServiceError("vote_not_found", "投票不存在或不可见")

        return self._to_schema(vote, now_utc)

    def _to_schema(self, record: VoteRecord, now_utc: datetime) -> Vote:
        # Dynamic status mapping: open becomes closed when now >= closes_at
        effective_status = record.status
        record_closes_at_utc = self._utc(record.closes_at)
        if record.status == "open" and now_utc >= record_closes_at_utc:
            effective_status = "closed"

        options = [
            VoteOptionOut(id=opt.id, label=opt.label)
            for opt in sorted(record.options, key=lambda x: x.position)
        ]
        return Vote(
            id=record.id,
            title=record.title,
            options=options,
            scope=record.scope,
            status=effective_status,
            closes_at=record_closes_at_utc,
        )

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        manager = (
            self.session.begin_nested()
            if self.session.in_transaction()
            else self.session.begin()
        )
        with manager:
            yield

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
