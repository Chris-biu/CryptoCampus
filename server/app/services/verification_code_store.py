from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.verification_code import RegistrationVerificationCode
from app.services.verification_code import (
    VerificationCodeDigest,
    VerificationCodeError,
)


class SqlAlchemyVerificationCodeStore:
    def __init__(self, session: Session, crypto_engine: VerificationCodeDigest) -> None:
        self._session = session
        self._crypto_engine = crypto_engine

    def issue(self, email: str, code: str, expires_at: datetime) -> str:
        issue_id = str(uuid4())
        try:
            digest = self._digest(code)
            record = self._session.get(RegistrationVerificationCode, email)
            if record is None:
                record = RegistrationVerificationCode(email=email)
                self._session.add(record)
            record.issue_id = issue_id
            record.code_digest = digest
            record.expires_at = expires_at
            record.consumed = False
            self._session.commit()
            return issue_id
        except SQLAlchemyError as error:
            self._session.rollback()
            raise VerificationCodeError("verification_store_unavailable") from error

    def consume(self, email: str, code: str, now: datetime) -> bool:
        try:
            digest = self._digest(code)
            updated = (
                self._session.query(RegistrationVerificationCode)
                .filter(
                    RegistrationVerificationCode.email == email,
                    RegistrationVerificationCode.code_digest == digest,
                    RegistrationVerificationCode.expires_at > now,
                    RegistrationVerificationCode.consumed.is_(False),
                )
                .update(
                    {RegistrationVerificationCode.consumed: True},
                    synchronize_session=False,
                )
            )
            self._session.commit()
            return updated == 1
        except SQLAlchemyError as error:
            self._session.rollback()
            raise VerificationCodeError("verification_store_unavailable") from error

    def revoke(self, email: str, issue_id: str) -> None:
        try:
            (
                self._session.query(RegistrationVerificationCode)
                .filter(
                    RegistrationVerificationCode.email == email,
                    RegistrationVerificationCode.issue_id == issue_id,
                    RegistrationVerificationCode.consumed.is_(False),
                )
                .delete(synchronize_session=False)
            )
            self._session.commit()
        except SQLAlchemyError as error:
            self._session.rollback()
            raise VerificationCodeError("verification_store_unavailable") from error

    def _digest(self, code: str) -> bytes:
        digest = self._crypto_engine.sm3_digest(code.encode("ascii"))
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise VerificationCodeError("verification_store_unavailable")
        return digest
