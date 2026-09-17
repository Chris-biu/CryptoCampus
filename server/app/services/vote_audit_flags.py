from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.models.vote import VoteRecord
from app.models.vote_audit import VoteAuditFlag
from app.services.admin_audit import AdminAuditChainService


class VoteAuditFlagError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


class VoteAuditFlagService:
    """
    Service for marking anomalous votes for audit.
    Never alters ballot validity or reveals voter identity.
    """

    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine | Any,
        audit_chain_service: AdminAuditChainService | None = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.audit_chain_service = audit_chain_service

    def flag(
        self,
        *,
        vote_id: str,
        actor_id: str,
        reason: str,
        now: datetime,
    ) -> dict[str, bool]:
        if not isinstance(vote_id, str) or not vote_id.strip():
            raise VoteAuditFlagError("not_found", "投票不存在")

        clean_vote_id = vote_id.strip()
        try:
            uuid.UUID(clean_vote_id)
        except (ValueError, AttributeError):
            raise VoteAuditFlagError("not_found", "投票不存在")

        if not isinstance(reason, str):
            raise VoteAuditFlagError("validation_error", "参数不合法")

        normalized_reason = reason.strip()
        if not (1 <= len(normalized_reason) <= 500):
            raise VoteAuditFlagError("validation_error", "参数不合法")

        vote = self.session.get(VoteRecord, clean_vote_id)
        if vote is None:
            raise VoteAuditFlagError("not_found", "投票不存在")

        reason_hash = self.crypto_engine.sm3_digest(normalized_reason.encode("utf-8"))

        # Check existing flag for idempotency
        existing = (
            self.session.query(VoteAuditFlag)
            .filter_by(vote_id=clean_vote_id, actor_id=actor_id, reason_hash=reason_hash)
            .first()
        )
        if existing is not None:
            return {"accepted": True}

        utc_now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)

        flag_entry = VoteAuditFlag(
            id=str(uuid.uuid4()),
            vote_id=clean_vote_id,
            actor_id=actor_id,
            reason_hash=reason_hash,
            created_at=utc_now,
        )
        self.session.add(flag_entry)

        # Audit chain detail hash: strictly binds action, vote_id, and reason_hash without cleartext
        detail_bytes = f"vote.audit.flag|{clean_vote_id}|{reason_hash.hex()}".encode("utf-8")
        detail_hash = self.crypto_engine.sm3_digest(detail_bytes)

        if self.audit_chain_service is not None:
            self.audit_chain_service.append(
                session=self.session,
                actor_id=actor_id,
                action="vote.audit.flag",
                target=f"vote:{clean_vote_id}",
                detail_hash=detail_hash,
                timestamp=utc_now,
            )

        self.session.flush()
        return {"accepted": True}
