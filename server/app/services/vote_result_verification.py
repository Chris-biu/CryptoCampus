import base64
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy.orm import Session

from app.crypto.engine import CryptoEngine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.models.certificate import CertificateRecord
from app.models.vote import VoteOption, VoteRecord, VoteResultSnapshot
from app.schemas.vote import SignatureVerification, VoteResult
from app.services.vote_results import encode_vote_result

if TYPE_CHECKING:
    from app.pki.service import PlatformCAService


class VoteResultServiceError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class VoteResultService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_latest(self, *, vote_id: str, now: datetime) -> VoteResult:
        vote = self.session.get(VoteRecord, vote_id)
        if vote is None or vote.scope != "public":
            raise VoteResultServiceError("vote_not_found", "投票不存在或未公开")

        snapshot = (
            self.session.query(VoteResultSnapshot)
            .filter_by(vote_id=vote_id)
            .order_by(VoteResultSnapshot.version.desc())
            .first()
        )
        if snapshot is None:
            raise VoteResultServiceError("result_not_found", "投票尚无计票快照")

        options = (
            self.session.query(VoteOption)
            .filter_by(vote_id=vote_id)
            .order_by(VoteOption.position.asc())
            .all()
        )
        parsed_counts = snapshot.get_counts()
        counts_out: dict[str, int] = {}
        for opt in options:
            counts_out[opt.id] = parsed_counts.get(opt.id, 0)

        published_at_utc = (
            snapshot.published_at.replace(tzinfo=timezone.utc)
            if snapshot.published_at.tzinfo is None
            else snapshot.published_at.astimezone(timezone.utc)
        )

        return VoteResult(
            vote_id=snapshot.vote_id,
            counts=counts_out,
            total=snapshot.total,
            signature=base64.b64encode(snapshot.signature).decode("ascii"),
            signer_certificate=base64.b64encode(snapshot.signer_certificate).decode("ascii"),
            published_at=published_at_utc,
        )


class VoteResultVerificationService:
    def __init__(
        self,
        session: Session,
        crypto_engine: CryptoEngine,
        ca_service: Optional["PlatformCAService"] = None,
    ) -> None:
        self.session = session
        self.crypto_engine = crypto_engine
        self.ca_service = ca_service

    def verify(self, *, vote_id: str, now: datetime) -> SignatureVerification:
        vote = self.session.get(VoteRecord, vote_id)
        if vote is None or vote.scope != "public":
            raise VoteResultServiceError("vote_not_found", "投票不存在或未公开")

        snapshot = (
            self.session.query(VoteResultSnapshot)
            .filter_by(vote_id=vote_id)
            .order_by(VoteResultSnapshot.version.desc())
            .first()
        )
        if snapshot is None:
            raise VoteResultServiceError("result_not_found", "投票尚无计票快照")

        options = (
            self.session.query(VoteOption)
            .filter_by(vote_id=vote_id)
            .order_by(VoteOption.position.asc())
            .all()
        )
        expected_option_ids = [opt.id for opt in options]

        if not snapshot.validate_counts(expected_options=expected_option_ids):
            return SignatureVerification(
                valid=False,
                algorithm="SM3-with-SM2",
                certificate_valid=False,
                message="计票快照结构或选项总数不一致",
            )

        parsed_counts = snapshot.get_counts()
        ordered_counts = tuple((opt.id, parsed_counts[opt.id]) for opt in options)

        published_at_utc = (
            snapshot.published_at.replace(tzinfo=timezone.utc)
            if snapshot.published_at.tzinfo is None
            else snapshot.published_at.astimezone(timezone.utc)
        )

        try:
            recomputed_encoded = encode_vote_result(
                vote_id=snapshot.vote_id,
                ordered_counts=ordered_counts,
                total=snapshot.total,
                published_at=published_at_utc,
            )
            recomputed_digest = self.crypto_engine.sm3_digest(recomputed_encoded)
        except Exception:
            return SignatureVerification(
                valid=False,
                algorithm="SM3-with-SM2",
                certificate_valid=False,
                message="结果规范编码重构失败",
            )

        if not self.crypto_engine.constant_time_equal(snapshot.result_digest, recomputed_digest):
            return SignatureVerification(
                valid=False,
                algorithm="SM3-with-SM2",
                certificate_valid=False,
                message="计票结果摘要不匹配",
            )

        certificate_valid = False
        if self.ca_service is not None:
            try:
                cert_verif = self.ca_service.verify_certificate(
                    certificate_der=snapshot.signer_certificate,
                    verification_time=now,
                    required_key_usage=("digitalSignature",),
                )
                certificate_valid = cert_verif.valid
            except CryptoBridgeError as cbe:
                if cbe.code == BridgeErrorCode.PROVIDER_UNAVAILABLE:
                    raise VoteResultServiceError("engine_unavailable", "密码服务不可用") from cbe
                certificate_valid = False
            except Exception:
                certificate_valid = False
        else:
            cert_rec = (
                self.session.query(CertificateRecord)
                .filter_by(certificate_der=snapshot.signer_certificate)
                .one_or_none()
            )
            if cert_rec is not None and cert_rec.status == "active":
                certificate_valid = True

        sig_valid = False
        try:
            sig_valid = self.crypto_engine.sm2_verify(
                public_key=snapshot.signer_public_key,
                digest=snapshot.result_digest,
                signature=snapshot.signature,
            )
        except CryptoBridgeError as cbe:
            if cbe.code == BridgeErrorCode.PROVIDER_UNAVAILABLE:
                raise VoteResultServiceError("engine_unavailable", "密码服务不可用") from cbe
            sig_valid = False
        except Exception:
            sig_valid = False

        total_valid = bool(sig_valid and certificate_valid)
        msg = "计票结果签名及证书验证通过" if total_valid else "计票结果签名或证书验证未通过"

        return SignatureVerification(
            valid=total_valid,
            algorithm="SM3-with-SM2",
            certificate_valid=certificate_valid,
            message=msg,
        )
