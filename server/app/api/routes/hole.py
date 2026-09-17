import base64
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, Query, status
from sqlalchemy.orm import Session

from app.core.errors import ApiError, crypto_error_to_api_error
from app.crypto.dependencies import get_crypto_engine
from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.db.session import get_db
from app.schemas.credential import (
    BlindCommitmentRequest,
    BlindCommitmentResponse,
    BlindCredentialRequest,
    BlindCredentialResponse,
    CredentialProof,
    CredentialVerification,
)
from app.schemas.hole import (
    CreateHoleCommentRequest,
    CreateHolePostRequest,
    HoleComment as HoleCommentSchema,
    HoleCommentPage,
    HoleLikeResponse,
    HolePost as HolePostSchema,
    HolePostPage,
    LikeHolePostRequest,
    RevocationPage,

)
from app.security.auth_dependencies import CurrentUser, require_roles
from app.services.credential_issuance import (
    CredentialIssuanceError,
    CredentialIssuanceService,
)
from app.services.credential_verification import (
    CredentialVerificationError,
    CredentialVerificationService,
)
from app.services.hole_interactions import (
    HoleInteractionService,
    HoleInteractionServiceError,
)
from app.services.hole_posts import (
    HolePostService,
    HolePostServiceError,
)
from app.services.revocation_log import (
    RevocationLogService,
    RevocationLogServiceError,
)
from app.services.commitment_store import (
    BlindCommitmentStore,
    get_commitment_store,
)
from app.services.signer_provider import (
    ServerSignerKeyProvider,
    ServerSignerVerificationKeyProvider,
    get_signer_key_provider,
    get_signer_verification_key_provider,
)

router = APIRouter(prefix="/hole", tags=["Hole"])


def get_credential_issuance_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    signer_key_provider: ServerSignerKeyProvider = Depends(get_signer_key_provider),
    commitment_store: BlindCommitmentStore = Depends(get_commitment_store),
) -> CredentialIssuanceService:
    return CredentialIssuanceService(
        session=session,
        crypto_engine=engine,
        signer_key_provider=signer_key_provider,
        commitment_store=commitment_store,
    )


def get_hole_post_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    signer_verification_key_provider: ServerSignerVerificationKeyProvider = Depends(
        get_signer_verification_key_provider
    ),
) -> HolePostService:
    return HolePostService(
        session=session,
        crypto_engine=engine,
        signer_verification_key_provider=signer_verification_key_provider,
    )


def get_credential_verification_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    signer_verification_key_provider: ServerSignerVerificationKeyProvider = Depends(
        get_signer_verification_key_provider
    ),
) -> CredentialVerificationService:
    return CredentialVerificationService(
        session=session,
        crypto_engine=engine,
        signer_verification_key_provider=signer_verification_key_provider,
    )


def get_hole_interaction_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    signer_verification_key_provider: ServerSignerVerificationKeyProvider = Depends(
        get_signer_verification_key_provider
    ),
) -> HoleInteractionService:
    return HoleInteractionService(
        session=session,
        crypto_engine=engine,
        signer_verification_key_provider=signer_verification_key_provider,
    )


def _map_hole_interaction_error(err: HoleInteractionServiceError) -> ApiError:
    if err.code in ("idempotency_conflict", "credential_consumed", "conflict", "post_not_available"):
        return ApiError(status_code=409, code="CONFLICT", message=err.message or "操作数据写入冲突")
    if err.code in ("invalid_signature", "credential_revoked"):
        return ApiError(status_code=401, code="UNAUTHORIZED", message=err.message or "凭证验证失败")
    if err.code in (
        "invalid_content",
        "invalid_service",
        "invalid_period",
        "invalid_idempotency_key",
        "invalid_post_id",
    ):
        return ApiError(status_code=422, code="VALIDATION_ERROR", message=err.message or "请求参数校验失败")
    if err.code == "post_not_found":
        return ApiError(status_code=404, code="NOT_FOUND", message=err.message or "目标帖子不存在")
    if err.code == "engine_unavailable":
        return ApiError(status_code=503, code="PROVIDER_UNAVAILABLE", message="密码引擎服务不可用")
    return ApiError(status_code=500, code="INTERNAL_ERROR", message="树洞互动服务内部错误")


def get_revocation_log_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
) -> RevocationLogService:
    return RevocationLogService(
        session=session,
        crypto_engine=engine,
    )


def _map_revocation_log_error(err: RevocationLogServiceError) -> ApiError:
    if err.code == "chain_corrupted":
        return ApiError(status_code=500, code="INTERNAL_ERROR", message=err.message or "撤销日志完整性损坏")
    if err.code == "engine_unavailable":
        return ApiError(status_code=503, code="PROVIDER_UNAVAILABLE", message="密码引擎服务不可用")
    if err.code == "invalid_param":
        return ApiError(status_code=422, code="VALIDATION_ERROR", message=err.message or "请求参数校验失败")
    return ApiError(status_code=500, code="INTERNAL_ERROR", message="撤销链服务内部错误")


def _map_issuance_error(err: CredentialIssuanceError) -> ApiError:
    if err.code == "idempotency_conflict":
        return ApiError(status_code=409, code="CONFLICT", message="同一幂等键已用于不同签发请求")
    if err.code == "quota_exhausted":
        return ApiError(status_code=429, code="RATE_LIMITED", message="当日盲签名凭证额度已用尽")
    if err.code == "user_inactive":
        return ApiError(status_code=401, code="UNAUTHORIZED", message="用户未认证或处于不可用状态")
    if err.code in (
        "invalid_service",
        "invalid_period",
        "invalid_idempotency_key",
        "invalid_blinded_message",
        "invalid_commitment",
    ):
        return ApiError(status_code=422, code="VALIDATION_ERROR", message=err.message or "请求参数校验失败")
    if err.code == "engine_unavailable":
        return ApiError(status_code=503, code="PROVIDER_UNAVAILABLE", message="密码引擎服务不可用")
    return ApiError(status_code=500, code="INTERNAL_ERROR", message="盲签名服务内部错误")


def _map_hole_post_error(err: HolePostServiceError) -> ApiError:
    if err.code in ("idempotency_conflict", "credential_consumed", "conflict"):
        return ApiError(status_code=409, code="CONFLICT", message=err.message or "发布数据写入冲突")
    if err.code in ("invalid_signature", "credential_revoked"):
        return ApiError(status_code=401, code="UNAUTHORIZED", message=err.message or "凭证验证失败")
    if err.code in (
        "invalid_content",
        "invalid_service",
        "invalid_period",
        "invalid_idempotency_key",
    ):
        return ApiError(status_code=422, code="VALIDATION_ERROR", message=err.message or "请求参数校验失败")
    if err.code == "engine_unavailable":
        return ApiError(status_code=503, code="PROVIDER_UNAVAILABLE", message="密码引擎服务不可用")
    return ApiError(status_code=500, code="INTERNAL_ERROR", message="树洞发布服务内部错误")


def _map_verification_error(err: CredentialVerificationError) -> ApiError:
    if err.code == "engine_unavailable":
        return ApiError(status_code=503, code="PROVIDER_UNAVAILABLE", message="密码引擎服务不可用")
    return ApiError(status_code=500, code="INTERNAL_ERROR", message="凭证验证服务内部错误")


@router.post(
    "/credentials/commitments",
    response_model=BlindCommitmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="申领盲签名服务端一次性随机承诺 (ADR-0001)",
)
def create_blind_commitment(
    request: BlindCommitmentRequest,
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    store: BlindCommitmentStore = Depends(get_commitment_store),
    engine: CryptoEngine = Depends(get_crypto_engine),
    signer_verification_key_provider: ServerSignerVerificationKeyProvider = Depends(
        get_signer_verification_key_provider
    ),
) -> BlindCommitmentResponse:
    now_utc = datetime.now(timezone.utc)
    if request.period != now_utc.date().isoformat():
        raise ApiError(status_code=422, code="VALIDATION_ERROR", message="申领周期必须为服务端当前 UTC 日期")
    pk_bytes = signer_verification_key_provider.get_signer_public_key(request.service)
    if pk_bytes is None:
        raise ApiError(status_code=503, code="SERVICE_UNAVAILABLE", message="盲签名公钥未配置")
    try:
        record = store.create(
            service=request.service,
            period=request.period,
            user_id=current_user.user_id,
            now=now_utc,
            crypto_engine=engine,
        )
    except CryptoBridgeError as error:
        raise crypto_error_to_api_error(error) from error
    return BlindCommitmentResponse(
        commitment_id=record.commitment_id,
        commitment_point=record.commitment_point_b64,
        expires_at=record.expires_at,
        signer_public_key=base64.b64encode(pk_bytes).decode("ascii"),
    )


@router.post(
    "/credentials",
    response_model=BlindCredentialResponse,
    status_code=status.HTTP_201_CREATED,
    summary="对客户端提交的盲化消息签发匿名凭证",
)
def issue_hole_credential(
    request: BlindCredentialRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=16, max_length=128),
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: CredentialIssuanceService = Depends(get_credential_issuance_service),
) -> BlindCredentialResponse:
    now = datetime.now(timezone.utc)
    try:
        result = service.issue(
            user_id=current_user.user_id,
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
    except CredentialIssuanceError as err:
        raise _map_issuance_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe


@router.post(
    "/posts",
    response_model=HolePostSchema,
    status_code=status.HTTP_201_CREATED,
    summary="消费一次性盲签名凭证发布帖子",
)
def create_hole_post(
    request: CreateHolePostRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=16, max_length=128),
    service: HolePostService = Depends(get_hole_post_service),
) -> HolePostSchema:
    now = datetime.now(timezone.utc)
    try:
        post = service.publish(
            content=request.content,
            credential=request.credential,
            idempotency_key=idempotency_key,
            now=now,
        )
        return HolePostSchema.model_validate(post)
    except HolePostServiceError as err:
        raise _map_hole_post_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe


@router.get(
    "/posts",
    response_model=HolePostPage,
    status_code=status.HTTP_200_OK,
    summary="浏览树洞帖子",
)
def list_hole_posts(
    page: int = Query(1, ge=1, description="当前页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    service: HolePostService = Depends(get_hole_post_service),
) -> HolePostPage:
    return service.list_posts(page=page, page_size=page_size)


@router.post(
    "/credentials/verify",
    response_model=CredentialVerification,
    status_code=status.HTTP_200_OK,
    summary="公开验证盲签名凭证",
)
def verify_hole_credential(
    credential: CredentialProof,
    service: CredentialVerificationService = Depends(get_credential_verification_service),
) -> CredentialVerification:
    try:
        return service.verify(credential)
    except CredentialVerificationError as err:
        raise _map_verification_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe


@router.get(
    "/posts/{post_id}/comments",
    response_model=HoleCommentPage,
    status_code=status.HTTP_200_OK,
    summary="公开浏览帖子评论",
)
def list_hole_comments(
    post_id: str,
    page: int = Query(1, ge=1, description="当前页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    service: HoleInteractionService = Depends(get_hole_interaction_service),
) -> HoleCommentPage:
    try:
        return service.list_comments(post_id=post_id, page=page, page_size=page_size)
    except HoleInteractionServiceError as err:
        raise _map_hole_interaction_error(err) from err


@router.post(
    "/posts/{post_id}/comments",
    response_model=HoleCommentSchema,
    status_code=status.HTTP_201_CREATED,
    summary="消费独立小额匿名凭证发布评论",
)
def create_hole_comment(
    post_id: str,
    request: CreateHoleCommentRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=16, max_length=128),
    service: HoleInteractionService = Depends(get_hole_interaction_service),
) -> HoleCommentSchema:
    now = datetime.now(timezone.utc)
    try:
        comment = service.create_comment(
            post_id=post_id,
            content=request.content,
            credential=request.credential,
            idempotency_key=idempotency_key,
            now=now,
        )
        return HoleCommentSchema.model_validate(comment)
    except HoleInteractionServiceError as err:
        raise _map_hole_interaction_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe


@router.post(
    "/posts/{post_id}/likes",
    response_model=HoleLikeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="消费独立小额匿名凭证点赞",
)
def like_hole_post(
    post_id: str,
    request: LikeHolePostRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=16, max_length=128),
    service: HoleInteractionService = Depends(get_hole_interaction_service),
) -> HoleLikeResponse:
    now = datetime.now(timezone.utc)
    try:
        service.like_post(
            post_id=post_id,
            credential=request.credential,
            idempotency_key=idempotency_key,
            now=now,
        )
        return HoleLikeResponse()
    except HoleInteractionServiceError as err:
        raise _map_hole_interaction_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe


@router.get(
    "/revocations",
    response_model=RevocationPage,
    status_code=status.HTTP_200_OK,
    summary="公开查询 SM3 链式撤销记录",
    openapi_extra={"security": []},
)
def list_hole_revocations(
    page: int = Query(1, ge=1, description="当前页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    service: RevocationLogService = Depends(get_revocation_log_service),
) -> RevocationPage:
    try:
        return service.list_entries(page=page, page_size=page_size)
    except RevocationLogServiceError as err:
        raise _map_revocation_log_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe
