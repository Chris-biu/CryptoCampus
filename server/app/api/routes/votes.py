import base64
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, Query, status
from sqlalchemy.orm import Session

from app.core.errors import ApiError, crypto_error_to_api_error
from app.crypto.dependencies import get_crypto_engine
from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.db.session import get_db
from app.models.vote import AnonymousBallot, VoteRecord, VoteResultSnapshot
from app.schemas.credential import (
    BlindCommitmentRequest,
    BlindCommitmentResponse,
    BlindCredentialRequest,
    BlindCredentialResponse,
)
from app.schemas.vote import (
    Accepted,
    CreateVoteRequest,
    SignatureVerification,
    SubmitBallotRequest,
    Vote,
    VoteAuditBallot,
    VoteAuditReport,
    VotePage,
    VoteResult,
)
from app.security.auth_dependencies import CurrentUser, require_roles
from app.services.vote_ballots import (
    AnonymousBallotService,
    AnonymousBallotServiceError,
)
from app.services.vote_credentials import (
    VoteCredentialIssuanceError,
    VoteCredentialIssuanceService,
)
from app.services.vote_result_verification import (
    VoteResultService,
    VoteResultServiceError,
    VoteResultVerificationService,
)
from app.services.vote_scope import (
    DefaultVoteScopePolicy,
    VoteScopePolicy,
)
from app.services.vote_signer import (
    VoteSignerMaterialProvider,
    get_vote_signer_provider,
)
from app.services.commitment_store import BlindCommitmentStore, get_commitment_store
from app.services.vote_settlement import VoteSettlementService
from app.services.vote_tally_provider import (
    VoteTallyMaterialProvider,
    get_vote_tally_provider,
)
from app.services.votes import (
    VoteService,
    VoteServiceError,
)

router = APIRouter(prefix="/votes", tags=["Votes"])


def get_vote_scope_policy(
    session: Session = Depends(get_db),
) -> VoteScopePolicy:
    return DefaultVoteScopePolicy(session)


def get_vote_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    scope_policy: VoteScopePolicy = Depends(get_vote_scope_policy),
) -> VoteService:
    return VoteService(session=session, crypto_engine=engine, scope_policy=scope_policy)


def get_vote_credential_issuance_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    signer_provider: VoteSignerMaterialProvider = Depends(get_vote_signer_provider),
    scope_policy: VoteScopePolicy = Depends(get_vote_scope_policy),
) -> VoteCredentialIssuanceService:
    return VoteCredentialIssuanceService(
        session=session,
        crypto_engine=engine,
        signer_provider=signer_provider,
        scope_policy=scope_policy,
        commitment_store=get_commitment_store(),
    )


def _map_vote_service_error(err: VoteServiceError) -> ApiError:
    if err.code == "idempotency_conflict":
        return ApiError(status_code=409, code="CONFLICT", message="同一幂等键已用于不同创建请求")
    if err.code == "creator_inactive":
        return ApiError(status_code=401, code="UNAUTHORIZED", message="用户未认证或处于不可用状态")
    if err.code == "permission_denied":
        return ApiError(status_code=403, code="FORBIDDEN", message="角色无权创建投票")
    if err.code in ("not_scope_member", "scope_inactive", "scope_kind_mismatch"):
        return ApiError(status_code=403, code="FORBIDDEN", message=err.message or "无权使用该投票范围")
    if err.code == "scope_not_found":
        return ApiError(status_code=404, code="NOT_FOUND", message="投票范围不存在")
    if err.code in (
        "invalid_options_count",
        "closes_at_in_past",
        "invalid_idempotency_key",
        "invalid_title",
        "invalid_scope",
        "scope_id_required",
        "scope_id_forbidden",
    ):
        return ApiError(status_code=422, code="VALIDATION_ERROR", message=err.message or "请求参数校验失败")
    if err.code == "vote_not_found":
        return ApiError(status_code=404, code="NOT_FOUND", message="投票不存在")
    return ApiError(status_code=500, code="INTERNAL_ERROR", message="投票服务内部错误")


def _map_vote_credential_error(err: VoteCredentialIssuanceError) -> ApiError:
    if err.code == "credential_already_issued":
        return ApiError(status_code=409, code="CONFLICT", message="同一用户在同场投票仅能申领一次选票凭证")
    if err.code == "vote_closed":
        return ApiError(status_code=409, code="CONFLICT", message="投票已截止或不可用")
    if err.code == "vote_not_found":
        return ApiError(status_code=404, code="NOT_FOUND", message="投票不存在")
    if err.code == "user_inactive":
        return ApiError(status_code=401, code="UNAUTHORIZED", message="用户未认证或处于不可用状态")
    if err.code in (
        "permission_denied",
        "not_scope_member",
        "scope_inactive",
        "scope_kind_mismatch",
        "scope_id_required",
        "invalid_scope",
    ):
        return ApiError(status_code=403, code="FORBIDDEN", message=err.message or "无权申领选票凭证")
    if err.code == "scope_not_found":
        return ApiError(status_code=404, code="NOT_FOUND", message="投票范围不存在")
    if err.code == "quota_exhausted":
        return ApiError(status_code=409, code="CONFLICT", message="本场投票凭证额度已用尽")
    if err.code in (
        "invalid_service",
        "invalid_period",
        "invalid_idempotency_key",
        "invalid_blinded_message",
        "invalid_commitment",
    ):
        return ApiError(status_code=422, code="VALIDATION_ERROR", message=err.message or "请求参数校验失败")
    if err.code == "engine_unavailable":
        return ApiError(status_code=503, code="SERVICE_UNAVAILABLE", message="密码引擎服务不可用")
    return ApiError(status_code=500, code="INTERNAL_ERROR", message="选票凭证签发服务内部错误")


def get_anonymous_ballot_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    signer_provider: VoteSignerMaterialProvider = Depends(get_vote_signer_provider),
    tally_provider: VoteTallyMaterialProvider = Depends(get_vote_tally_provider),
) -> AnonymousBallotService:
    return AnonymousBallotService(
        session=session,
        crypto_engine=engine,
        signer_provider=signer_provider,
        tally_material_provider=tally_provider,
    )


def get_vote_result_service(
    session: Session = Depends(get_db),
) -> VoteResultService:
    return VoteResultService(session=session)


def get_vote_result_verification_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
) -> VoteResultVerificationService:
    return VoteResultVerificationService(session=session, crypto_engine=engine)


def get_vote_settlement_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    tally_provider: VoteTallyMaterialProvider = Depends(get_vote_tally_provider),
) -> VoteSettlementService:
    return VoteSettlementService(
        session=session,
        crypto_engine=engine,
        tally_material_provider=tally_provider,
    )


def _map_ballot_service_error(err: AnonymousBallotServiceError) -> ApiError:
    if err.code in (
        "idempotency_conflict",
        "credential_already_spent",
        "credential_consumed",
        "vote_closed",
        "conflict",
    ):
        return ApiError(status_code=409, code="CONFLICT", message=err.message)
    if err.code in ("vote_not_found", "invalid_vote"):
        return ApiError(status_code=404, code="NOT_FOUND", message=err.message or "投票不存在")
    if err.code in (
        "option_not_found",
        "invalid_option",
        "invalid_idempotency_key",
        "invalid_payload",
        "invalid_credential",
        "invalid_credential_signature",
        "invalid_signature",
        "invalid_service",
        "invalid_period",
    ):
        return ApiError(status_code=422, code="VALIDATION_ERROR", message=err.message or "请求参数校验失败")
    if err.code in ("engine_unavailable",):
        return ApiError(status_code=503, code="SERVICE_UNAVAILABLE", message=err.message or "密码服务不可用")
    return ApiError(status_code=500, code="INTERNAL_ERROR", message=err.message or "匿名计票服务内部错误")


def _map_vote_result_error(err: VoteResultServiceError) -> ApiError:
    if err.code in ("vote_not_found", "result_not_found"):
        return ApiError(status_code=404, code="NOT_FOUND", message=err.message or "资源不存在")
    if err.code in ("engine_unavailable",):
        return ApiError(status_code=503, code="SERVICE_UNAVAILABLE", message=err.message or "密码服务不可用")
    return ApiError(status_code=500, code="INTERNAL_ERROR", message=err.message or "计票结果服务内部错误")


@router.get(
    "",
    response_model=VotePage,
    status_code=status.HTTP_200_OK,
    summary="获取可见投票",
    operation_id="listVotes",
)
def list_votes(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    service: VoteService = Depends(get_vote_service),
) -> VotePage:
    now = datetime.now(timezone.utc)
    try:
        return service.list_public(page=page, page_size=page_size, now=now)
    except VoteServiceError as err:
        raise _map_vote_service_error(err) from err


@router.post(
    "",
    response_model=Vote,
    status_code=status.HTTP_201_CREATED,
    summary="创建投票",
    operation_id="createVote",
)
def create_vote(
    request: CreateVoteRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=16, max_length=128),
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: VoteService = Depends(get_vote_service),
) -> Vote:
    now = datetime.now(timezone.utc)
    try:
        return service.create(
            creator_id=current_user.user_id,
            request=request,
            idempotency_key=idempotency_key,
            now=now,
        )
    except VoteServiceError as err:
        raise _map_vote_service_error(err) from err


@router.get(
    "/{vote_id}",
    response_model=Vote,
    status_code=status.HTTP_200_OK,
    summary="获取单场投票、选项、范围与截止时间",
    operation_id="getVote",
)
def get_vote(
    vote_id: str,
    service: VoteService = Depends(get_vote_service),
) -> Vote:
    now = datetime.now(timezone.utc)
    try:
        return service.get_public(vote_id=vote_id, now=now)
    except VoteServiceError as err:
        raise _map_vote_service_error(err) from err


@router.post(
    "/{vote_id}/credentials/commitments",
    response_model=BlindCommitmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="为单场投票申领一次性盲签承诺",
    operation_id="createVoteBlindCommitment",
)
def create_vote_blind_commitment(
    vote_id: str,
    request: BlindCommitmentRequest,
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    scope_policy: VoteScopePolicy = Depends(get_vote_scope_policy),
    signer_provider: VoteSignerMaterialProvider = Depends(get_vote_signer_provider),
    store: BlindCommitmentStore = Depends(get_commitment_store),
) -> BlindCommitmentResponse:
    now = datetime.now(timezone.utc)
    if request.service != "vote_ballot" or request.period != vote_id:
        raise ApiError(status_code=422, code="VALIDATION_ERROR", message="投票承诺必须绑定 vote_ballot 与当前 vote_id")
    vote = session.get(VoteRecord, vote_id)
    if vote is None:
        raise ApiError(status_code=404, code="NOT_FOUND", message="投票不存在")
    closes_at = vote.closes_at.replace(tzinfo=timezone.utc) if vote.closes_at.tzinfo is None else vote.closes_at.astimezone(timezone.utc)
    if vote.status != "open" or now >= closes_at:
        raise ApiError(status_code=409, code="CONFLICT", message="投票已截止或不可用")
    try:
        scope_policy.require_can_issue(user_id=current_user.user_id, vote_id=vote_id)
    except Exception as error:
        raise ApiError(status_code=403, code="FORBIDDEN", message=str(error)) from error
    public_key = signer_provider.get_signer_public_key(vote_id=vote_id)
    ensure_keypair = getattr(signer_provider, "ensure_keypair", None)
    if public_key is None and callable(ensure_keypair):
        try:
            public_key = ensure_keypair(vote_id=vote_id, engine=engine)
        except (CryptoBridgeError, OSError, ValueError) as error:
            raise ApiError(status_code=503, code="SERVICE_UNAVAILABLE", message="无法初始化本场投票盲签密钥") from error
    if public_key is None or len(public_key) != 65 or public_key[0] != 0x04:
        raise ApiError(status_code=503, code="SERVICE_UNAVAILABLE", message="本场投票盲签公钥不可用")
    try:
        record = store.create(
            service=request.service,
            period=request.period,
            user_id=current_user.user_id,
            crypto_engine=engine,
            now=now,
        )
    except CryptoBridgeError as error:
        raise crypto_error_to_api_error(error) from error
    return BlindCommitmentResponse(
        commitment_id=record.commitment_id,
        commitment_point=record.commitment_point_b64,
        expires_at=record.expires_at,
        signer_public_key=base64.b64encode(public_key).decode("ascii"),
    )


@router.post(
    "/{vote_id}/credentials",
    response_model=BlindCredentialResponse,
    status_code=status.HTTP_201_CREATED,
    summary="每位用户每场投票签发一次盲化选票凭证",
    operation_id="issueVoteCredential",
)
def issue_vote_credential(
    vote_id: str,
    request: BlindCredentialRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=16, max_length=128),
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: VoteCredentialIssuanceService = Depends(get_vote_credential_issuance_service),
) -> BlindCredentialResponse:
    now = datetime.now(timezone.utc)
    try:
        result = service.issue(
            user_id=current_user.user_id,
            vote_id=vote_id,
            service=request.service,
            period=request.period,
            blinded_message_b64=request.blinded_message,
            idempotency_key=idempotency_key,
            now=now,
        )
        return BlindCredentialResponse(
            blind_signature=result.blind_signature_b64,
            algorithm="SM2-BLIND-PROTOCOL-V1",
        )
    except VoteCredentialIssuanceError as err:
        raise _map_vote_credential_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe


@router.post(
    "/{vote_id}/ballots",
    response_model=Accepted,
    status_code=status.HTTP_201_CREATED,
    summary="匿名提交并消费一次性选票",
    operation_id="submitBallot",
    openapi_extra={
        "x-required-roles": ["guest", "student", "admin", "teacher"],
        "x-jwt": False,
        "x-sensitive-fields": ["voter_identity"],
        "security": [],
    },
)
def submit_ballot(
    vote_id: str,
    request: SubmitBallotRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=16, max_length=128),
    service: AnonymousBallotService = Depends(get_anonymous_ballot_service),
) -> Accepted:
    now = datetime.now(timezone.utc)
    try:
        return service.submit(
            vote_id=vote_id,
            option_id=request.option_id,
            credential=request.credential,
            idempotency_key=idempotency_key,
            now=now,
        )
    except AnonymousBallotServiceError as err:
        raise _map_ballot_service_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe


@router.get(
    "/{vote_id}/results/verify",
    response_model=SignatureVerification,
    status_code=status.HTTP_200_OK,
    summary="公开验证计票结果签名",
    operation_id="verifyVoteResult",
    openapi_extra={
        "x-required-roles": ["guest", "student", "admin", "teacher"],
        "x-jwt": False,
        "x-sensitive-fields": ["voter_identity"],
        "security": [],
    },
)
def verify_vote_result(
    vote_id: str,
    service: VoteResultVerificationService = Depends(get_vote_result_verification_service),
) -> SignatureVerification:
    now = datetime.now(timezone.utc)
    try:
        return service.verify(vote_id=vote_id, now=now)
    except VoteResultServiceError as err:
        raise _map_vote_result_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe


@router.get(
    "/{vote_id}/results",
    response_model=VoteResult,
    status_code=status.HTTP_200_OK,
    summary="获取计票结果及计票台签名",
    operation_id="getVoteResults",
    openapi_extra={
        "x-required-roles": ["guest", "student", "admin", "teacher"],
        "x-jwt": False,
        "x-sensitive-fields": ["voter_identity"],
        "security": [],
    },
)
def get_vote_results(
    vote_id: str,
    service: VoteResultService = Depends(get_vote_result_service),
    session: Session = Depends(get_db),
    settlement_service: VoteSettlementService = Depends(get_vote_settlement_service),
) -> VoteResult:
    now = datetime.now(timezone.utc)
    # 受控自动结算触发检查：若公开投票已到期且未发布，触发一次结算
    vote = session.get(VoteRecord, vote_id)
    if vote is not None and vote.status != "published" and vote.scope == "public":
        closes_at_utc = (
            vote.closes_at.replace(tzinfo=timezone.utc)
            if vote.closes_at.tzinfo is None
            else vote.closes_at.astimezone(timezone.utc)
        )
        if now >= closes_at_utc:
            try:
                settlement_service.settle(vote_id=vote_id, now=now)
            except Exception:
                pass

    try:
        return service.get_latest(vote_id=vote_id, now=now)
    except VoteResultServiceError as err:
        raise _map_vote_result_error(err) from err


@router.get(
    "/{vote_id}/audit",
    response_model=VoteAuditReport,
    status_code=status.HTTP_200_OK,
    summary="导出不含身份的有效选票序列号与签名审计报告",
    operation_id="exportVoteAudit",
    openapi_extra={
        "x-required-roles": ["guest", "student", "admin", "teacher"],
        "x-jwt": False,
        "x-sensitive-fields": ["voter_identity"],
        "security": [],
    },
)
def export_vote_audit(
    vote_id: str,
    session: Session = Depends(get_db),
) -> VoteAuditReport:
    vote = session.get(VoteRecord, vote_id)
    if vote is None or vote.scope != "public":
        raise ApiError(status_code=404, code="NOT_FOUND", message="投票不存在或未公开")

    if vote.status != "published" or not vote.final_snapshot_id:
        raise ApiError(status_code=409, code="CONFLICT", message="投票尚未到期最终结算，无法导出审计报告")

    final_snap = session.get(VoteResultSnapshot, vote.final_snapshot_id)
    if final_snap is None or not final_snap.is_final:
        raise ApiError(status_code=409, code="CONFLICT", message="投票尚未生成唯一最终结果快照")

    closes_at_utc = (
        vote.closes_at.replace(tzinfo=timezone.utc)
        if vote.closes_at.tzinfo is None
        else vote.closes_at.astimezone(timezone.utc)
    )

    raw_ballots = (
        session.query(AnonymousBallot)
        .filter(
            AnonymousBallot.vote_id == vote_id,
            AnonymousBallot.created_at <= closes_at_utc,
        )
        .all()
    )

    # 严格按 sn 升序排序
    sorted_ballots = sorted(raw_ballots, key=lambda b: b.credential_sn.hex().lower())

    audit_ballots = [
        VoteAuditBallot(
            sn=b.credential_sn.hex().lower(),
            signature=base64.b64encode(b.credential_signature).decode("ascii"),
            valid=True,
        )
        for b in sorted_ballots
    ]

    return VoteAuditReport(
        vote_id=vote.id,
        ballots=audit_ballots,
        total=final_snap.total,
        result_signature=base64.b64encode(final_snap.signature).decode("ascii"),
    )

