from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.models.drop import Drop, DropExtractIdempotency
from app.services.admin_audit import AdminAuditChainService


class AdminDropGovernanceError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


class AdminDropGovernanceService:
    """
    Service for administrative forced drop destruction and audit logging.
    Wipes all cryptographic material without decryption or inspection.
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

    def destroy(
        self,
        *,
        code: str,
        actor_id: str,
        now: datetime,
    ) -> None:
        if not isinstance(code, str) or not code.strip():
            raise AdminDropGovernanceError("not_found", "密信不存在")

        clean_code = code.strip()
        code_hash = self.crypto_engine.sm3_digest(clean_code.encode("utf-8"))
        drop = self.session.query(Drop).filter_by(link_code_hash=code_hash).first()

        if drop is None and len(clean_code) == 36:
            try:
                uuid.UUID(clean_code)
                drop = self.session.get(Drop, clean_code)
            except (ValueError, AttributeError):
                pass

        if drop is None:
            raise AdminDropGovernanceError("not_found", "密信不存在")

        # Idempotent: if already destroyed, return 204 without appending duplicate audit
        if drop.status == "destroyed":
            return

        utc_now = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)

        # Irreversibly wipe all ciphertext and envelope keys
        drop.status = "destroyed"
        drop.ciphertext = None
        drop.nonce = None
        drop.tag = None
        drop.enc_key_sm2 = None
        drop.enc_key_mlkem = None
        drop.sender_signature = None
        drop.sender_certificate_der = None
        drop.access_factor_salt = None
        drop.access_code_hash = b"\x00" * 32

        # Invalidate related extraction idempotency cache
        self.session.query(DropExtractIdempotency).filter_by(drop_id=drop.id).delete()

        # Non-reversible detail hash binding drop ID and forced destruction reason
        detail_bytes = f"drop.destroy|{drop.id}|admin_forced".encode("utf-8")
        detail_hash = self.crypto_engine.sm3_digest(detail_bytes)

        if self.audit_chain_service is not None:
            self.audit_chain_service.append(
                session=self.session,
                actor_id=actor_id,
                action="drop.destroy",
                target=f"drop:{drop.id}",
                detail_hash=detail_hash,
                timestamp=utc_now,
            )

        self.session.flush()
