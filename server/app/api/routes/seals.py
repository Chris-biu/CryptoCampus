from fastapi import APIRouter, Depends, File, Form, Header, Response, UploadFile
from sqlalchemy.orm import Session

from app.api.routes.auth import get_crypto_engine, get_private_key_cache
from app.core.config import Settings, get_settings
from app.core.errors import ApiError
from app.crypto.engine import CryptoEngine
from app.db.session import get_db
from app.pki.dependencies import build_platform_ca_service
from app.pki.service import PlatformCAService
from app.schemas.seal import SealResponse
from app.schemas.verification import VerificationResult
from app.security.auth_dependencies import CurrentUser, require_roles
from app.security.key_cache import PrivateKeyUnlockCacheProtocol
from app.services.seals import (
    SealService,
    SealSignerMaterialProvider,
    get_default_seal_signer_material_provider,
)
from app.services.verifications import FiveStepVerificationService

router = APIRouter(tags=["Verify"])


def get_platform_ca_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
) -> PlatformCAService:
    return build_platform_ca_service(session, engine)


def get_seal_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    ca_service: PlatformCAService = Depends(get_platform_ca_service),
    key_cache: PrivateKeyUnlockCacheProtocol = Depends(get_private_key_cache),
    material_provider: SealSignerMaterialProvider = Depends(
        get_default_seal_signer_material_provider
    ),
    settings: Settings = Depends(get_settings),
) -> SealService:
    return SealService(
        session=session,
        crypto_engine=engine,
        ca_service=ca_service,
        key_cache=key_cache,
        seal_material_provider=material_provider,
        max_bytes=settings.seal_and_verify_max_bytes,
    )


def get_verification_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    settings: Settings = Depends(get_settings),
) -> FiveStepVerificationService:
    return FiveStepVerificationService(session, engine, settings.seal_and_verify_max_bytes)


async def _read_bounded_upload(file: UploadFile, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(65536):
        total += len(chunk)
        if total > limit:
            raise ApiError(413, "PAYLOAD_TOO_LARGE", f"文件大小超过限制（当前上限 {limit} 字节）")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post(
    "/seals",
    status_code=201,
    response_model=SealResponse,
    summary="对文件摘要和时间戳签章",
)
async def create_seal(
    file: UploadFile = File(..., description="二进制上传文件"),
    seal_profile: str = Form(..., description="签章主体类型"),
    pqc_mode: bool = Form(..., description="是否使用抗量子签章"),
    output_format: str = Form(..., description="输出格式"),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
        description="幂等键 (16~128 字符)",
    ),
    current_user: CurrentUser = Depends(require_roles("student", "admin", "teacher")),
    service: SealService = Depends(get_seal_service),
) -> SealResponse:
    if idempotency_key is None or not (16 <= len(idempotency_key) <= 128):
        raise ApiError(
            status_code=422,
            code="VALIDATION_ERROR",
            message="Idempotency-Key 长度必须为 16 至 128 个字符",
        )

    return service.create_seal(
        current_user=current_user,
        file_bytes=file,
        seal_profile=seal_profile,
        pqc_mode=pqc_mode,
        output_format=output_format,
        idempotency_key=idempotency_key,
    )


@router.get(
    "/seals/{seal_id}",
    response_model=SealResponse,
    summary="通过二维码标识公开获取签章元数据",
)
def get_seal(
    seal_id: str,
    service: SealService = Depends(get_seal_service),
) -> SealResponse:
    return service.get_seal(seal_id)


@router.get(
    "/seals/{seal_id}/sidecar",
    summary="下载侧车签章文件",
)
def download_seal_sidecar(
    seal_id: str,
    service: SealService = Depends(get_seal_service),
) -> Response:
    sidecar_bytes, filename = service.get_sidecar(seal_id)
    return Response(
        content=sidecar_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post(
    "/verifications",
    response_model=VerificationResult,
    summary="公开执行文件五步验真",
)
async def verify_file(
    file: UploadFile = File(..., description="待验证文件"),
    seal: UploadFile = File(..., description="签章侧车"),
    service: FiveStepVerificationService = Depends(get_verification_service),
) -> VerificationResult:
    file_bytes = await _read_bounded_upload(file, service.max_bytes)
    seal_bytes = await _read_bounded_upload(seal, 131072)
    return service.verify(file_bytes, seal_bytes)
