from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, Header, Query, Response, UploadFile
from sqlalchemy.orm import Session

from app.api.routes.auth import get_private_key_cache, get_session_service
from app.api.routes.system import get_crypto_engine
from app.core.errors import ApiError
from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.db.session import get_db
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.pki.dependencies import build_platform_ca_service
from app.pki.errors import PkiConfigurationError, PkiValidationError
from app.pki.service import PlatformCAService
from app.pki.types import USER_IDENTITY_KEY_USAGE
from app.schemas.auth import Accepted, UserSummary
from app.schemas.governance import DeleteAccountRequest
from app.schemas.keyring import (
    CertificateVerificationResponse,
    KeyringPasswordRequest,
    KeyringRotationRequest,
    KeyringSummary,
)
from app.schemas.notification import NotificationPage
from app.schemas.quota import QuotaPage
from app.schemas.session import DeviceSessionPage
from app.security.auth_dependencies import CurrentUser, require_roles
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.account_lifecycle import (
    AccountGovernanceError,
    AccountGovernanceService,
)
from app.services.keyring import KeyringError, KeyringService, RotationIdempotencyStore
from app.services.notification import NotificationService
from app.services.quota import QuotaError, QuotaService
from app.services.sessions import SessionError, SessionService

router = APIRouter(prefix="/me", tags=["Me"])
_rotation_idempotency = RotationIdempotencyStore()


def get_keyring_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    key_cache: PrivateKeyUnlockCache = Depends(get_private_key_cache),
) -> KeyringService:
    return KeyringService(
        session,
        engine,
        key_cache,
        platform_ca=build_platform_ca_service(session, engine),
        idempotency_store=_rotation_idempotency,
    )


def get_me_quota_service(session: Session = Depends(get_db), engine: CryptoEngine = Depends(get_crypto_engine)) -> QuotaService:
    return QuotaService(session, engine.sm3_digest)


def get_platform_ca_service(
    session: Session = Depends(get_db), engine: CryptoEngine = Depends(get_crypto_engine)
) -> PlatformCAService:
    return build_platform_ca_service(session, engine)


def get_account_governance_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    key_cache: PrivateKeyUnlockCache = Depends(get_private_key_cache),
    platform_ca: PlatformCAService = Depends(get_platform_ca_service),
) -> AccountGovernanceService:
    return AccountGovernanceService(session, engine, key_cache, platform_ca=platform_ca)


def _keyring_error(error: KeyringError) -> ApiError:
    mappings = {
        "credentials_invalid": (401, "UNAUTHORIZED", "口令错误"),
        "backup_invalid": (400, "BACKUP_INVALID", "备份文件无效"),
        "conflict": (409, "CONFLICT", "当前密钥环状态不允许该操作"),
        "unavailable": (503, "PROVIDER_UNAVAILABLE", "服务暂不可用"),
    }
    status, code, message = mappings.get(error.code, (500, "INTERNAL_ERROR", "服务器内部错误"))
    return ApiError(status, code, message)


@router.get("", response_model=UserSummary)
async def get_me(
    identity: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    session: Session = Depends(get_db),
) -> UserSummary:
    user = session.get(User, identity.user_id)
    if user is None or user.email is None:
        raise ApiError(401, "UNAUTHORIZED", "未授权")
    return UserSummary(
        id=user.id,
        email=user.email,
        role=user.role,
        status=user.status,
        pqc_mode=user.pqc_pubkey is not None and user.enc_pqc_sk is not None,
        created_at=user.created_at,
    )


@router.get("/keyring", response_model=KeyringSummary)
async def get_keyring(
    identity: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: KeyringService = Depends(get_keyring_service),
) -> KeyringSummary:
    try:
        return service.summary(identity.user_id, datetime.now(timezone.utc))
    except KeyringError as error:
        raise _keyring_error(error) from None


@router.get("/certificate/verify", response_model=CertificateVerificationResponse)
async def verify_own_certificate(
    identity: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    session: Session = Depends(get_db),
    platform_ca: PlatformCAService = Depends(get_platform_ca_service),
) -> CertificateVerificationResponse:
    verified_at = datetime.now(timezone.utc)
    user = session.get(User, identity.user_id)
    if user is None:
        raise ApiError(401, "UNAUTHORIZED", "未授权")
    if not user.cert_serial:
        return CertificateVerificationResponse(
            valid=False, state="invalid", serial=None, verified_at=verified_at
        )
    certificate = session.get(CertificateRecord, user.cert_serial)
    if certificate is None or certificate.subject_user_id != user.id:
        return CertificateVerificationResponse(
            valid=False,
            state="invalid",
            serial=user.cert_serial,
            verified_at=verified_at,
        )
    try:
        result = platform_ca.verify_certificate(
            certificate.certificate_der,
            verified_at,
            USER_IDENTITY_KEY_USAGE,
        )
    except (CryptoBridgeError, PkiConfigurationError, PkiValidationError):
        raise ApiError(503, "PROVIDER_UNAVAILABLE", "证书验证服务暂不可用") from None
    return CertificateVerificationResponse(
        valid=result.valid,
        state=result.state,
        serial=result.serial,
        verified_at=verified_at,
    )


@router.post("/keyring/export")
async def export_keyring(
    request: KeyringPasswordRequest,
    identity: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: KeyringService = Depends(get_keyring_service),
) -> Response:
    try:
        backup = service.export(identity.user_id, request.password)
    except KeyringError as error:
        raise _keyring_error(error) from None
    return Response(
        content=backup,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=keyring-backup.pem"},
    )


@router.post("/keyring/import", response_model=KeyringSummary)
async def import_keyring(
    backup: UploadFile = File(...),
    password: str = Form(..., min_length=1, max_length=128),
    identity: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: KeyringService = Depends(get_keyring_service),
) -> KeyringSummary:
    payload = await backup.read(256 * 1024 + 1)
    if len(payload) > 256 * 1024:
        raise ApiError(413, "PAYLOAD_TOO_LARGE", "备份文件超过限制")
    try:
        return service.import_backup(identity.user_id, payload, password)
    except KeyringError as error:
        raise _keyring_error(error) from None


@router.post("/keyring/rotate", response_model=KeyringSummary)
async def rotate_keyring(
    request: KeyringRotationRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    identity: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: KeyringService = Depends(get_keyring_service),
) -> KeyringSummary:
    if request.acknowledge_inflight_loss is not True:
        raise ApiError(409, "CONFIRMATION_REQUIRED", "请确认在途密信可能无法解封")
    try:
        return service.rotate(
            identity.user_id, request.password, idempotency_key, datetime.now(timezone.utc)
        )
    except KeyringError as error:
        raise _keyring_error(error) from None


@router.get("/sessions", response_model=DeviceSessionPage)
async def list_sessions(
    identity: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: SessionService = Depends(get_session_service),
) -> DeviceSessionPage:
    return DeviceSessionPage(items=service.list_for_user(identity.user_id, identity.session_id))


@router.delete("/sessions/{session_id}", status_code=204)
async def revoke_session(
    session_id: str,
    identity: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: SessionService = Depends(get_session_service),
) -> None:
    try:
        service.revoke_for_user(identity.user_id, session_id)
    except SessionError as error:
        if error.code == "not_found":
            raise ApiError(404, "NOT_FOUND", "资源不存在") from None
        raise ApiError(500, "INTERNAL_ERROR", "服务器内部错误") from None


@router.get("/quotas", response_model=QuotaPage)
async def get_quotas(
    identity: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: QuotaService = Depends(get_me_quota_service),
) -> QuotaPage:
    now = datetime.now(timezone.utc)
    try:
        return QuotaPage(items=service.get(identity.user_id, now), resets_at=service.resets_at(now))
    except QuotaError as error:
        raise ApiError(500, "INTERNAL_ERROR", "服务器内部错误") from error


@router.delete("/account", response_model=Accepted, status_code=202)
async def delete_account(
    request: DeleteAccountRequest,
    identity: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: AccountGovernanceService = Depends(get_account_governance_service),
) -> Accepted:
    try:
        service.delete_account(identity.user_id, request.password, request.confirm, datetime.now(timezone.utc))
    except AccountGovernanceError as error:
        mappings = {
            "credentials_invalid": (401, "UNAUTHORIZED", "未授权"),
            "not_found": (404, "NOT_FOUND", "资源不存在"),
            "unavailable": (503, "PROVIDER_UNAVAILABLE", "服务暂不可用"),
        }
        status, code, message = mappings.get(error.code, (500, "INTERNAL_ERROR", "服务器内部错误"))
        raise ApiError(status, code, message) from None
    return Accepted()


def get_notification_service(
    session: Session = Depends(get_db),
) -> NotificationService:
    return NotificationService(session)


@router.get("/notifications", response_model=NotificationPage)
async def list_notifications(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    identity: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: NotificationService = Depends(get_notification_service),
) -> NotificationPage:
    return service.list_for_user(
        user_id=identity.user_id,
        page=page,
        page_size=page_size,
    )
