from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.schemas.common import ErrorResponse


class ApiError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}


class DropServiceError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        self.message = message or code
        super().__init__(self.message)


_CRYPTO_ERROR_MAPPING: dict[BridgeErrorCode, tuple[int, str, str]] = {
    BridgeErrorCode.INVALID_ARGUMENT: (422, "VALIDATION_ERROR", "参数不合法"),
    BridgeErrorCode.AUTH_FAILED: (401, "CRYPTO_AUTH_FAILED", "凭据校验失败"),
    BridgeErrorCode.INTEGRITY_FAILED: (409, "CRYPTO_INTEGRITY_FAILED", "完整性校验失败"),
    BridgeErrorCode.CERT_INVALID: (409, "CERTIFICATE_INVALID", "证书无效"),
    BridgeErrorCode.CERT_REVOKED: (409, "CERTIFICATE_REVOKED", "证书已吊销"),
    BridgeErrorCode.REPLAYED: (409, "REPLAY_DETECTED", "检测到重复使用"),
    BridgeErrorCode.QUOTA_REJECTED: (429, "QUOTA_REJECTED", "额度不足"),
    BridgeErrorCode.UNSUPPORTED: (503, "CRYPTO_UNSUPPORTED", "当前密码能力不支持"),
    BridgeErrorCode.PROVIDER_UNAVAILABLE: (503, "PROVIDER_UNAVAILABLE", "密码引擎不可用"),
}

_CRYPTO_INTERNAL_API_ERROR = (500, "CRYPTO_INTERNAL_ERROR", "密码引擎内部错误")


def crypto_error_to_api_error(error: CryptoBridgeError) -> ApiError:
    status_code, code, message = _CRYPTO_ERROR_MAPPING.get(
        error.code, _CRYPTO_INTERNAL_API_ERROR
    )
    return ApiError(status_code=status_code, code=code, message=message)


def _error_response(
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    error = ErrorResponse(
        code=code,
        message=message,
        request_id=str(uuid4()),
        details=details or {},
    )
    return JSONResponse(status_code=status_code, content=error.model_dump())


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def handle_api_error(_: Request, exception: ApiError) -> JSONResponse:
        return _error_response(
            status_code=exception.status_code,
            code=exception.code,
            message=exception.message,
            details=exception.details,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        _: Request, __: RequestValidationError
    ) -> JSONResponse:
        return _error_response(
            status_code=422,
            code="VALIDATION_ERROR",
            message="请求参数校验失败",
        )

    @app.exception_handler(Exception)
    async def handle_internal_error(_: Request, __: Exception) -> JSONResponse:
        return _error_response(
            status_code=500,
            code="INTERNAL_ERROR",
            message="服务器内部错误",
        )
