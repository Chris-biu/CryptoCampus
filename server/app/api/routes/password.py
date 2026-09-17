from dataclasses import dataclass

from fastapi import APIRouter, Depends

from app.api.routes.auth import get_private_key_cache
from app.api.routes.system import get_crypto_engine
from app.core.errors import ApiError, crypto_error_to_api_error
from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.db.session import get_db
from app.schemas.password import ChangePasswordRequest
from app.security.key_cache import PrivateKeyUnlockCacheProtocol
from app.services.password_change import PasswordChangeError, PasswordChangeService
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class CurrentIdentity:
    user_id: str


def get_current_identity() -> CurrentIdentity:
    raise ApiError(401, "UNAUTHORIZED", "未授权")


def get_password_change_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    key_cache: PrivateKeyUnlockCacheProtocol = Depends(get_private_key_cache),
) -> PasswordChangeService:
    return PasswordChangeService(session, engine, key_cache)


router = APIRouter(prefix="/me", tags=["Me"])


@router.patch("/password", status_code=204)
async def change_password(
    request: ChangePasswordRequest,
    identity: CurrentIdentity = Depends(get_current_identity),
    service: PasswordChangeService = Depends(get_password_change_service),
) -> None:
    try:
        service.change(identity.user_id, request.current_password, request.new_password)
    except PasswordChangeError as error:
        mappings = {
            "INVALID_CREDENTIALS": (401, "AUTH_INVALID_CREDENTIALS", "邮箱或密码错误"),
            "VALIDATION_ERROR": (422, "VALIDATION_ERROR", "参数不合法"),
            "PROVIDER_UNAVAILABLE": (503, "PROVIDER_UNAVAILABLE", "服务暂不可用"),
            "CRYPTO_ERROR": (500, "CRYPTO_INTERNAL_ERROR", "密码引擎内部错误"),
            "INTERNAL_ERROR": (500, "INTERNAL_ERROR", "服务器内部错误"),
        }
        status, code, message = mappings.get(
            error.code, (500, "INTERNAL_ERROR", "服务器内部错误")
        )
        raise ApiError(status, code, message) from None
    except CryptoBridgeError as error:
        raise crypto_error_to_api_error(error) from None
