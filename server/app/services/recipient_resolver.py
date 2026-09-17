from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.types import MLKEM_PUBLIC_KEY_SIZE, SM2_PUBLIC_KEY_SIZE
from app.models.user import User


@dataclass(frozen=True)
class ResolvedRecipient:
    recipient_user_id: str
    sm2_public_key: bytes
    mlkem_public_key: bytes | None
    sm2_fingerprint: bytes
    mlkem_fingerprint: bytes | None


@runtime_checkable
class RecipientKeyResolver(Protocol):
    def resolve_for_create(
        self, session: Session, sender_id: str, pqc_mode: bool
    ) -> ResolvedRecipient | None: ...


class DefaultRecipientKeyResolver:
    """Production default: when no approved resolution strategy exists, fail closed."""

    def resolve_for_create(
        self, session: Session, sender_id: str, pqc_mode: bool
    ) -> ResolvedRecipient | None:
        return None


class ConfiguredRecipientKeyResolver:
    """Resolves a configured recipient by user_id from the database with strict key validation."""

    def __init__(self, target_user_id: str, crypto_engine: CryptoEngine) -> None:
        self.target_user_id = target_user_id
        self.crypto_engine = crypto_engine

    def resolve_for_create(
        self, session: Session, sender_id: str, pqc_mode: bool
    ) -> ResolvedRecipient | None:
        user = session.get(User, self.target_user_id)
        if user is None or user.status != "active":
            return None
        if not user.pubkey or len(user.pubkey) != SM2_PUBLIC_KEY_SIZE:
            return None

        sm2_fingerprint = self.crypto_engine.sm3_digest(user.pubkey)

        if pqc_mode:
            if not user.pqc_pubkey or len(user.pqc_pubkey) != MLKEM_PUBLIC_KEY_SIZE:
                return None
            mlkem_pubkey = user.pqc_pubkey
            mlkem_fingerprint = self.crypto_engine.sm3_digest(user.pqc_pubkey)
        else:
            mlkem_pubkey = None
            mlkem_fingerprint = None

        return ResolvedRecipient(
            recipient_user_id=user.id,
            sm2_public_key=user.pubkey,
            mlkem_public_key=mlkem_pubkey,
            sm2_fingerprint=sm2_fingerprint,
            mlkem_fingerprint=mlkem_fingerprint,
        )
