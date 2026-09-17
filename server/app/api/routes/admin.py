from datetime import datetime, timezone
import re
from typing import Literal

from fastapi import APIRouter, Depends, Header, Query, Response
from sqlalchemy.orm import Session

from app.api.routes.auth import get_private_key_cache
from app.api.routes.system import get_crypto_engine
from app.benchmarks.executor import BenchmarkExecutor, get_default_executor
from app.core.errors import ApiError
from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.db.session import SessionLocal, get_db
from app.models.audit import AuditLog
from app.schemas.auth import Accepted, UserPage, UserSummary
from app.schemas.benchmark import BenchmarkResultResponse, JobCreateRequest, JobResponse
from app.schemas.governance import (
    InspectMetadata,
    InspectMetadataPage,
    UserRoleRequest,
    UserStatusRequest,
    VoteAuditFlagRequest,
    WithdrawHolePostRequest,
)
from app.schemas.hole import RevocationEntry
from app.schemas.quota import QuotaPage
from app.schemas.system import SystemStatus
from app.security.auth_dependencies import CurrentUser, require_roles
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.account_lifecycle import AccountGovernanceError, AccountGovernanceService
from app.services.admin_audit import AdminAuditChainService
from app.services.admin_audit_export import AdminAuditExportError, AdminAuditExportService
from app.services.admin_drop_governance import AdminDropGovernanceError, AdminDropGovernanceService
from app.services.admin_inspect import AdminInspectQueryService
from app.services.admin_users import AdminUserQueryService
from app.services.benchmarks import BenchmarkService, BenchmarkServiceError
from app.services.hole_governance import HoleContentGovernanceService, HoleGovernanceError
from app.services.provider_reload import (
    ProviderOperationLock,
    ProviderReloadError,
    ProviderReloadService,
)
from app.services.quota import QuotaError, QuotaResetIdempotencyStore, QuotaService
from app.services.system_status import SystemStatusService
from app.services.vote_audit_flags import VoteAuditFlagError, VoteAuditFlagService


router = APIRouter(prefix="/admin", tags=["Admin"])
_quota_reset_idempotency = QuotaResetIdempotencyStore()
_global_provider_reload_lock = ProviderOperationLock(timeout=5.0)


def get_system_status_service(
    engine: CryptoEngine = Depends(get_crypto_engine),
) -> SystemStatusService:
    return SystemStatusService(engine)


def get_provider_reload_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
) -> ProviderReloadService:
    return ProviderReloadService(
        engine=engine,
        session=session,
        lock=_global_provider_reload_lock,
    )




def get_audit_chain_service(
    engine: CryptoEngine = Depends(get_crypto_engine),
) -> AdminAuditChainService:
    return AdminAuditChainService(engine)


def get_quota_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    audit_chain: AdminAuditChainService = Depends(get_audit_chain_service),
) -> QuotaService:
    return QuotaService(
        session,
        engine.sm3_digest,
        idempotency_store=_quota_reset_idempotency,
        audit_chain_service=audit_chain,
    )


def get_governance_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    key_cache: PrivateKeyUnlockCache = Depends(get_private_key_cache),
    audit_chain: AdminAuditChainService = Depends(get_audit_chain_service),
) -> AccountGovernanceService:
    return AccountGovernanceService(session, engine, key_cache, audit_chain_service=audit_chain)


def get_hole_content_governance_service(
    engine: CryptoEngine = Depends(get_crypto_engine),
    audit_chain: AdminAuditChainService = Depends(get_audit_chain_service),
) -> HoleContentGovernanceService:
    return HoleContentGovernanceService(
        session_factory=SessionLocal,
        crypto_engine=engine,
        audit_chain_service=audit_chain,
    )


def get_admin_user_query_service(
    session: Session = Depends(get_db),
) -> AdminUserQueryService:
    return AdminUserQueryService(session)


def get_admin_drop_governance_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    audit_chain: AdminAuditChainService = Depends(get_audit_chain_service),
) -> AdminDropGovernanceService:
    return AdminDropGovernanceService(session, engine, audit_chain_service=audit_chain)


def get_vote_audit_flag_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    audit_chain: AdminAuditChainService = Depends(get_audit_chain_service),
) -> VoteAuditFlagService:
    return VoteAuditFlagService(session, engine, audit_chain_service=audit_chain)


def get_admin_inspect_query_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    audit_chain: AdminAuditChainService = Depends(get_audit_chain_service),
) -> AdminInspectQueryService:
    return AdminInspectQueryService(session, engine, audit_chain_service=audit_chain)


def get_admin_audit_export_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    audit_chain: AdminAuditChainService = Depends(get_audit_chain_service),
) -> AdminAuditExportService:
    return AdminAuditExportService(session, engine, audit_chain_service=audit_chain)


def _quota_error(error: QuotaError) -> ApiError:
    mappings = {
        "not_found": (404, "NOT_FOUND", "资源不存在"),
        "exhausted": (429, "QUOTA_EXHAUSTED", "额度已用尽，请在下一周期后重试"),
        "resource_invalid": (422, "VALIDATION_ERROR", "参数不合法"),
        "period_invalid": (422, "VALIDATION_ERROR", "参数不合法"),
        "idempotency_invalid": (422, "VALIDATION_ERROR", "参数不合法"),
        "conflict": (409, "CONFLICT", "请求已处理"),
        "pending_deletion": (409, "CONFLICT", "账号注销处理中"),
    }
    status, code, message = mappings.get(error.code, (500, "INTERNAL_ERROR", "服务器内部错误"))
    return ApiError(status, code, message)


def _governance_error(error: AccountGovernanceError) -> ApiError:
    mappings = {
        "not_found": (404, "NOT_FOUND", "资源不存在"),
        "status_invalid": (422, "VALIDATION_ERROR", "参数不合法"),
        "role_invalid": (422, "VALIDATION_ERROR", "参数不合法"),
        "reason_invalid": (422, "VALIDATION_ERROR", "参数不合法"),
        "system_user": (409, "CONFLICT", "系统账号不可操作"),
        "last_active_teacher": (409, "CONFLICT", "操作会破坏系统管理能力"),
        "pending_deletion": (409, "CONFLICT", "账号注销处理中"),
        "credentials_invalid": (401, "UNAUTHORIZED", "未授权"),
        "unavailable": (503, "PROVIDER_UNAVAILABLE", "服务暂不可用"),
    }
    status, code, message = mappings.get(error.code, (500, "INTERNAL_ERROR", "服务器内部错误"))
    return ApiError(status, code, message)


def _hole_governance_error(error: HoleGovernanceError) -> ApiError:
    mappings = {
        "post_not_found": (404, "NOT_FOUND", "资源不存在"),
        "unauthorized": (401, "UNAUTHORIZED", "未授权"),
        "forbidden": (403, "FORBIDDEN", "权限不足"),
        "invalid_reason": (422, "VALIDATION_ERROR", "参数不合法"),
        "invalid_param": (422, "VALIDATION_ERROR", "参数不合法"),
        "conflict": (409, "CONFLICT", "帖子状态冲突"),
        "engine_unavailable": (503, "PROVIDER_UNAVAILABLE", "密码引擎服务不可用"),
        "integrity_error": (500, "INTERNAL_ERROR", "数据完整性异常"),
    }
    status, code, message = mappings.get(error.code, (500, "INTERNAL_ERROR", "服务器内部错误"))
    return ApiError(status, code, error.message or message)


def _summary(user) -> UserSummary:
    return UserSummary.model_validate(
        {
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "status": user.status,
            "pqc_mode": user.pqc_pubkey is not None,
            "created_at": user.created_at,
        }
    )


@router.get("/users", response_model=UserPage)
def list_admin_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: AdminUserQueryService = Depends(get_admin_user_query_service),
) -> UserPage:
    dto = service.list_users(page=page, page_size=page_size)
    return UserPage(
        items=[
            UserSummary(
                id=u.id,
                email=u.email or "",
                role=u.role,
                status=u.status,
                pqc_mode=u.pqc_mode,
                created_at=u.created_at,
            )
            for u in dto.items
        ],
        page=dto.page,
        page_size=dto.page_size,
        total=dto.total,
    )


@router.patch("/users/{user_id}/role", response_model=UserSummary)
def update_user_role(
    user_id: str,
    request: UserRoleRequest,
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: AccountGovernanceService = Depends(get_governance_service),
) -> UserSummary:
    now = datetime.now(timezone.utc)
    try:
        user = service.update_role(
            actor_id=identity.user_id,
            target_id=user_id,
            new_role=request.role,  # type: ignore
            reason=request.reason,
            now=now,
        )
        return _summary(user)
    except AccountGovernanceError as error:
        raise _governance_error(error) from None


@router.post("/users/{user_id}/quotas/reset", response_model=QuotaPage)
async def reset_user_quotas(
    user_id: str,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: QuotaService = Depends(get_quota_service),
) -> QuotaPage:
    now = datetime.now(timezone.utc)
    try:
        return QuotaPage(items=service.reset(user_id, identity.user_id, idempotency_key, now), resets_at=service.resets_at(now))
    except QuotaError as error:
        raise _quota_error(error) from None


@router.patch("/users/{user_id}/status", response_model=UserSummary)
async def update_user_status(
    user_id: str,
    request: UserStatusRequest,
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: AccountGovernanceService = Depends(get_governance_service),
) -> UserSummary:
    try:
        return _summary(service.update_status(identity.user_id, user_id, request.status, request.reason, datetime.now(timezone.utc)))
    except AccountGovernanceError as error:
        raise _governance_error(error) from None


@router.get("/engine", response_model=SystemStatus)
async def get_engine_details(
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: SystemStatusService = Depends(get_system_status_service),
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
) -> SystemStatus:
    status = service.get_status()
    detail_content = (
        f"provider.status.view|{identity.user_id}|{status.api}|{status.engine}|{status.version}"
    ).encode("utf-8")
    detail_hash = engine.sm3_digest(detail_content)
    session.add(
        AuditLog(
            actor=identity.user_id,
            action="provider.status.view",
            target="engine",
            detail_hash=detail_hash,
        )
    )
    session.commit()
    return status


@router.post("/providers/reload", response_model=SystemStatus)
async def reload_pqc_provider(
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: ProviderReloadService = Depends(get_provider_reload_service),
) -> SystemStatus:
    try:
        return await service.reload(
            actor_id=identity.user_id,
            idempotency_key=idempotency_key,
            now=datetime.now(timezone.utc),
        )
    except ProviderReloadError as error:
        raise ApiError(error.status_code, error.code, error.message) from None
    except CryptoBridgeError:
        raise ApiError(503, "PROVIDER_UNAVAILABLE", "密码引擎服务不可用") from None
    except Exception:
        raise ApiError(500, "INTERNAL_ERROR", "服务器内部错误") from None




def get_benchmark_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    executor: BenchmarkExecutor = Depends(get_default_executor),
) -> BenchmarkService:
    return BenchmarkService(session, engine, executor)


@router.post("/benchmarks", response_model=JobResponse, status_code=202)
async def create_benchmark_job(
    request: JobCreateRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: BenchmarkService = Depends(get_benchmark_service),
) -> JobResponse:
    now = datetime.now(timezone.utc)
    try:
        return service.create_job(
            actor_id=identity.user_id,
            iterations=request.iterations,
            include_pqc=request.include_pqc,
            idempotency_key=idempotency_key,
            now=now,
        )
    except BenchmarkServiceError as error:
        raise ApiError(error.status_code, error.code, error.message) from None
    except CryptoBridgeError:
        raise ApiError(503, "PROVIDER_UNAVAILABLE", "密码引擎服务不可用") from None


@router.get("/benchmarks/{benchmark_id}", response_model=BenchmarkResultResponse)
async def get_benchmark_job(
    benchmark_id: str,
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: BenchmarkService = Depends(get_benchmark_service),
) -> BenchmarkResultResponse:
    try:
        return service.get_job(benchmark_id)
    except BenchmarkServiceError as error:
        raise ApiError(error.status_code, error.code, error.message) from None
    except CryptoBridgeError:
        raise ApiError(503, "PROVIDER_UNAVAILABLE", "密码引擎服务不可用") from None


@router.get("/benchmarks/{benchmark_id}/export")
async def export_benchmark_job(
    benchmark_id: str,
    format: Literal["csv", "json"] = Query(...),
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: BenchmarkService = Depends(get_benchmark_service),
) -> Response:
    try:
        media_type, filename, content = service.export_job(benchmark_id, format, actor_id=identity.user_id)
        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
        return Response(content=content, media_type=media_type, headers=headers)
    except BenchmarkServiceError as error:
        raise ApiError(error.status_code, error.code, error.message) from None
    except CryptoBridgeError:
        raise ApiError(503, "PROVIDER_UNAVAILABLE", "密码引擎服务不可用") from None


@router.post(
    "/hole/posts/{post_id}/withdraw",
    response_model=RevocationEntry,
    status_code=200,
    summary="撤下违规帖子并追加链式撤销记录",
)
def withdraw_hole_post(
    post_id: str,
    request: WithdrawHolePostRequest,
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: HoleContentGovernanceService = Depends(get_hole_content_governance_service),
) -> RevocationEntry:
    now = datetime.now(timezone.utc)
    try:
        dto = service.withdraw_post(
            post_id=post_id,
            reason=request.reason,
            operator_id=identity.user_id,
            now=now,
        )
        return RevocationEntry(
            sn=dto.sn,
            reason=dto.reason,
            hash_prev=dto.hash_prev,
            hash_curr=dto.hash_curr,
            timestamp=dto.timestamp,
        )
    except HoleGovernanceError as error:
        raise _hole_governance_error(error) from None
    except CryptoBridgeError as cbe:
        raise ApiError(503, "PROVIDER_UNAVAILABLE", "密码引擎服务不可用") from cbe
    except Exception as exc:
        raise ApiError(500, "INTERNAL_ERROR", "服务器内部错误") from exc


@router.post(
    "/drops/{code}/destroy",
    status_code=204,
    summary="管理员强制销毁密信密文材料",
)
def destroy_drop(
    code: str,
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: AdminDropGovernanceService = Depends(get_admin_drop_governance_service),
) -> Response:
    now = datetime.now(timezone.utc)
    try:
        service.destroy(code=code, actor_id=identity.user_id, now=now)
        return Response(status_code=204)
    except AdminDropGovernanceError as error:
        if error.code == "not_found":
            raise ApiError(404, "NOT_FOUND", "密信不存在") from None
        raise ApiError(500, "INTERNAL_ERROR", "服务器内部错误") from None


@router.post(
    "/votes/{vote_id}/audit-flags",
    response_model=Accepted,
    status_code=201,
    summary="标记异常投票供审计，不改变匿名选票归属",
)
def flag_vote_for_audit(
    vote_id: str,
    request: VoteAuditFlagRequest,
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: VoteAuditFlagService = Depends(get_vote_audit_flag_service),
) -> Accepted:
    now = datetime.now(timezone.utc)
    try:
        service.flag(
            vote_id=vote_id,
            actor_id=identity.user_id,
            reason=request.reason,
            now=now,
        )
        return Accepted(accepted=True)
    except VoteAuditFlagError as error:
        if error.code == "not_found":
            raise ApiError(404, "NOT_FOUND", "投票不存在") from None
        if error.code == "validation_error":
            raise ApiError(422, "VALIDATION_ERROR", "参数不合法") from None
        raise ApiError(500, "INTERNAL_ERROR", "服务器内部错误") from None


@router.get(
    "/inspect-records",
    response_model=InspectMetadataPage,
    summary="查询他人透视记录元信息，不返回敏感中间值",
)
def list_inspect_records(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: AdminInspectQueryService = Depends(get_admin_inspect_query_service),
) -> InspectMetadataPage:
    now = datetime.now(timezone.utc)
    dto = service.list_metadata(
        page=page,
        page_size=page_size,
        actor_id=identity.user_id,
        now=now,
    )
    return InspectMetadataPage(
        items=[
            InspectMetadata(
                id=item.id,
                operation=item.operation,
                owner_user_id=item.owner_user_id,
                created_at=item.created_at,
            )
            for item in dto.items
        ],
        page=dto.page,
        page_size=dto.page_size,
        total=dto.total,
    )


@router.get(
    "/audit/export",
    summary="导出经 SM3 链式哈希保护的管理员审计记录",
)
def export_admin_audit(
    format: str = Query(..., pattern=r"^(csv|json)$"),
    identity: CurrentUser = Depends(require_roles("admin", "teacher")),
    service: AdminAuditExportService = Depends(get_admin_audit_export_service),
):
    now = datetime.now(timezone.utc)
    try:
        data = service.export(
            format=format,
            actor_id=identity.user_id,
            now=now,
        )
        if format == "csv":
            return Response(content=data, media_type="text/csv")
        return data
    except AdminAuditExportError as error:
        if error.code == "validation_error":
            raise ApiError(422, "VALIDATION_ERROR", "参数不合法") from None
        if error.code == "integrity_error":
            raise ApiError(500, "INTERNAL_ERROR", "数据完整性异常") from None
        raise ApiError(500, "INTERNAL_ERROR", "服务器内部错误") from None
