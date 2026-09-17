import os
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Header, Response, UploadFile, status
from sqlalchemy.orm import Session

from app.api.routes.auth import get_private_key_cache
from app.core.errors import ApiError, crypto_error_to_api_error
from app.crypto.dependencies import get_crypto_engine
from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.crypto.types import MAX_DROP_CONTENT_SIZE
from app.db.session import get_db
from app.models.user import User
from app.pki.dependencies import build_platform_ca_service
from app.schemas.drop import (
    CreateDropResponse,
    CreateTextDropRequest,
    DropMetadataResponse,
    ExtractDropRequest,
    TtlPolicy,
)
from app.security.auth_dependencies import CurrentUser, require_roles
from app.security.key_cache import PrivateKeyUnlockCache
from app.services.drop import DropService, DropServiceError
from app.services.extract_cooldown import (
    ExtractAttemptGuard,
    SqlAlchemyExtractCooldownGuard,
)
from app.services.quota import QuotaService
from app.services.recipient_provider import (
    DefaultRecipientPrivateKeyProvider,
    FileRecipientPrivateKeyProvider,
    RecipientPrivateKeyProvider,
)
from app.services.recipient_resolver import (
    ConfiguredRecipientKeyResolver,
    DefaultRecipientKeyResolver,
    RecipientKeyResolver,
)

router = APIRouter(prefix="/drops", tags=["Drops"])

CHUNK_SIZE = 64 * 1024
MAX_FILE_BYTES = MAX_DROP_CONTENT_SIZE  # 104,857,600 (100 MiB)


def _configured_recipient_user_id() -> str | None:
    value = os.getenv("CRYPTOCAMPUS_DROP_RECIPIENT_USER_ID", "")
    try:
        return value if value and str(UUID(value)) == value.lower() else None
    except ValueError:
        return None


def get_recipient_key_resolver(
    engine: CryptoEngine = Depends(get_crypto_engine),
) -> RecipientKeyResolver:
    recipient_user_id = _configured_recipient_user_id()
    if recipient_user_id is None:
        return DefaultRecipientKeyResolver()
    return ConfiguredRecipientKeyResolver(recipient_user_id, engine)


def get_recipient_private_key_provider(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
) -> RecipientPrivateKeyProvider:
    recipient_user_id = _configured_recipient_user_id()
    if recipient_user_id is None:
        return DefaultRecipientPrivateKeyProvider()
    user = session.get(User, recipient_user_id)
    if user is None or user.status != "active" or not user.pubkey:
        return DefaultRecipientPrivateKeyProvider()
    try:
        fingerprint = engine.sm3_digest(user.pubkey)
    except CryptoBridgeError:
        return DefaultRecipientPrivateKeyProvider()
    return FileRecipientPrivateKeyProvider(
        recipient_user_id=recipient_user_id,
        sm2_key_fingerprint=fingerprint,
        sm2_private_key_path=Path(
            os.getenv(
                "CRYPTOCAMPUS_DROP_RECIPIENT_SM2_KEY_FILE",
                "/run/secrets/cryptocampus/drop_recipient_sm2.key",
            )
        ),
    )


def get_extract_cooldown_guard(
    session: Session = Depends(get_db),
) -> ExtractAttemptGuard:
    return SqlAlchemyExtractCooldownGuard(session)


def get_drop_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    resolver: RecipientKeyResolver = Depends(get_recipient_key_resolver),
    key_cache: PrivateKeyUnlockCache = Depends(get_private_key_cache),
    key_provider: RecipientPrivateKeyProvider = Depends(get_recipient_private_key_provider),
    cooldown_guard: ExtractAttemptGuard = Depends(get_extract_cooldown_guard),
) -> DropService:
    quota_service = QuotaService(session, engine.sm3_digest)
    return DropService(
        session=session,
        crypto_engine=engine,
        key_cache=key_cache,
        quota_service=quota_service,
        recipient_resolver=resolver,
        recipient_provider=key_provider,
        ca_service=build_platform_ca_service(session, engine),
        cooldown_guard=cooldown_guard,
    )



def _map_drop_error(err: DropServiceError) -> ApiError:
    if err.code == "idempotency_conflict":
        return ApiError(status_code=409, code="CONFLICT", message="幂等请求冲突或重复提交")
    if err.code == "quota_exhausted":
        return ApiError(status_code=429, code="RATE_LIMITED", message="密信配额已用尽")
    if err.code in ("not_found", "cooling_down"):
        return ApiError(status_code=404, code="NOT_FOUND", message=err.message or "密信不存在或链接已失效")
    if err.code in (
        "recipient_resolution_failed",
        "recipient_keys_invalid",
        "invalid_content",
        "content_too_long",
        "invalid_file",
        "invalid_idempotency_key",
        "invalid_ttl_policy",
        "invalid_access_password",
        "invalid_access_code",
        "invalid_envelope",
        "unsupported_envelope_version",
        "password_required",
    ):
        return ApiError(status_code=422, code="VALIDATION_ERROR", message=err.message or "请求参数校验失败")
    if err.code in ("file_too_large", "payload_too_large"):
        return ApiError(status_code=413, code="PAYLOAD_TOO_LARGE", message="文件大小超过 100 MiB 限制")
    if err.code in ("unauthorized", "key_not_unlocked", "key_unavailable"):
        return ApiError(status_code=401, code="UNAUTHORIZED", message=err.message or "用户未授权或私钥不可用")
    if err.code in ("certificate_invalid", "signature_invalid", "unseal_failed", "kdf_failed"):
        return ApiError(status_code=404, code="NOT_FOUND", message="密信校验失败或已被销毁")
    if err.code == "engine_unavailable":
        return ApiError(status_code=503, code="PROVIDER_UNAVAILABLE", message="密码引擎服务不可用")
    return ApiError(status_code=500, code="INTERNAL_ERROR", message="密信服务异常")



@router.post(
    "/text",
    response_model=CreateDropResponse,
    status_code=status.HTTP_201_CREATED,
    summary="创建文字密信",
)
def create_text_drop(
    request: CreateTextDropRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=16, max_length=128),
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: DropService = Depends(get_drop_service),
) -> CreateDropResponse:
    try:
        return service.create_text_drop(
            sender_id=current_user.user_id,
            content=request.content,
            ttl_policy=request.ttl_policy,
            pqc_mode=request.pqc_mode,
            idempotency_key=idempotency_key,
            access_password=request.access_password,
        )
    except DropServiceError as err:
        raise _map_drop_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe


@router.post(
    "/file",
    response_model=CreateDropResponse,
    status_code=status.HTTP_201_CREATED,
    summary="创建文件密信，最大 100 MiB",
)
async def create_file_drop(
    file: UploadFile = File(...),
    ttl_policy: TtlPolicy = Form(...),
    pqc_mode: bool = Form(...),
    access_password: str | None = Form(default=None),
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=16, max_length=128),
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: DropService = Depends(get_drop_service),
) -> CreateDropResponse:
    if access_password is not None and len(access_password) > 128:
        raise ApiError(422, "VALIDATION_ERROR", "访问口令长度超过 128 字符限制")
    if access_password == "":
        access_password = None

    chunks: list[bytes] = []
    total_bytes = 0
    try:
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_FILE_BYTES:
                chunks.clear()
                raise ApiError(413, "PAYLOAD_TOO_LARGE", "文件大小超过 100 MiB 限制")
            chunks.append(chunk)
        file_bytes = b"".join(chunks)
    finally:
        chunks.clear()

    raw_filename = file.filename or "attachment.bin"
    clean_filename = Path(raw_filename).name[:255]

    try:
        return service.create_file_drop(
            sender_id=current_user.user_id,
            file_bytes=file_bytes,
            filename=clean_filename,
            ttl_policy=ttl_policy,
            pqc_mode=pqc_mode,
            idempotency_key=idempotency_key,
            access_password=access_password,
        )
    except DropServiceError as err:
        raise _map_drop_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe
    finally:
        del file_bytes


@router.get(
    "/{code}",
    response_model=DropMetadataResponse,
    status_code=status.HTTP_200_OK,
    summary="公开获取密信元数据，不返回密文或明文",
)
def get_drop_metadata(
    code: str,
    service: DropService = Depends(get_drop_service),
) -> DropMetadataResponse:
    try:
        return service.get_drop_metadata(code=code)
    except DropServiceError as err:
        raise _map_drop_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe


@router.post(
    "/{code}/extract",
    status_code=status.HTTP_200_OK,
    summary="使用提取码和可选口令解密密信",
)
def extract_drop(
    code: str,
    request: ExtractDropRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=16, max_length=128),
    accept: str | None = Header(default=None, alias="Accept"),
    service: DropService = Depends(get_drop_service),
):
    try:
        meta, file_bytes = service.extract_drop(
            code=code,
            access_code=request.access_code,
            access_password=request.access_password,
            idempotency_key=idempotency_key,
        )
        if meta.kind == "file" and (accept == "application/octet-stream" or file_bytes is not None and not meta.content):
            headers = {
                "X-Signature-Valid": "true" if meta.signature_valid else "false",
                "X-Certificate-Valid": "true" if meta.certificate_valid else "false",
                "X-Inspect-Record-Id": meta.inspect_record_id,
            }
            if meta.filename:
                headers["Content-Disposition"] = f'attachment; filename="{meta.filename}"'
            return Response(
                content=file_bytes or b"",
                media_type="application/octet-stream",
                headers=headers,
            )
        return meta
    except DropServiceError as err:
        raise _map_drop_error(err) from err
    except CryptoBridgeError as cbe:
        raise crypto_error_to_api_error(cbe) from cbe

