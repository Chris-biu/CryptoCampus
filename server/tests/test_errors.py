from fastapi import FastAPI
from fastapi.testclient import TestClient

import pytest

from app.core.errors import ApiError, crypto_error_to_api_error, install_exception_handlers
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError


def create_test_app() -> FastAPI:
    app = FastAPI()
    install_exception_handlers(app)

    @app.get("/api-error")
    async def raise_api_error() -> None:
        raise ApiError(400, "BAD_REQUEST", "请求不合法")

    @app.get("/runtime-error")
    async def raise_runtime_error() -> None:
        raise RuntimeError("secret-value")

    @app.get("/validation/{value}")
    async def validate_path(value: int) -> dict[str, int]:
        return {"value": value}

    return app


def test_api_error_uses_contract_response() -> None:
    response = TestClient(create_test_app()).get("/api-error")
    body = response.json()

    assert response.status_code == 400
    assert body["code"] == "BAD_REQUEST"
    assert body["message"] == "请求不合法"
    assert isinstance(body["request_id"], str)
    assert body["request_id"]
    assert body["details"] == {}


def test_validation_error_uses_contract_response() -> None:
    response = TestClient(create_test_app()).get("/validation/not-an-integer")
    body = response.json()

    assert response.status_code == 422
    assert body["code"] == "VALIDATION_ERROR"
    assert body["message"] == "请求参数校验失败"
    assert isinstance(body["request_id"], str)
    assert body["request_id"]
    assert body["details"] == {}


def test_internal_error_does_not_leak_exception_details() -> None:
    client = TestClient(create_test_app(), raise_server_exceptions=False)

    response = client.get("/runtime-error")

    assert response.status_code == 500
    assert response.json()["code"] == "INTERNAL_ERROR"
    assert response.json()["message"] == "服务器内部错误"
    assert "secret-value" not in response.text


@pytest.mark.parametrize(
    ("bridge_code", "status_code", "api_code", "message"),
    [
        (BridgeErrorCode.INVALID_ARGUMENT, 422, "VALIDATION_ERROR", "参数不合法"),
        (BridgeErrorCode.BUFFER_TOO_SMALL, 500, "CRYPTO_INTERNAL_ERROR", "密码引擎内部错误"),
        (BridgeErrorCode.AUTH_FAILED, 401, "CRYPTO_AUTH_FAILED", "凭据校验失败"),
        (BridgeErrorCode.INTEGRITY_FAILED, 409, "CRYPTO_INTEGRITY_FAILED", "完整性校验失败"),
        (BridgeErrorCode.CERT_INVALID, 409, "CERTIFICATE_INVALID", "证书无效"),
        (BridgeErrorCode.CERT_REVOKED, 409, "CERTIFICATE_REVOKED", "证书已吊销"),
        (BridgeErrorCode.REPLAYED, 409, "REPLAY_DETECTED", "检测到重复使用"),
        (BridgeErrorCode.QUOTA_REJECTED, 429, "QUOTA_REJECTED", "额度不足"),
        (BridgeErrorCode.UNSUPPORTED, 503, "CRYPTO_UNSUPPORTED", "当前密码能力不支持"),
        (BridgeErrorCode.PROVIDER_UNAVAILABLE, 503, "PROVIDER_UNAVAILABLE", "密码引擎不可用"),
        (BridgeErrorCode.RANDOM_FAILED, 500, "CRYPTO_INTERNAL_ERROR", "密码引擎内部错误"),
        (BridgeErrorCode.MEMORY_FAILED, 500, "CRYPTO_INTERNAL_ERROR", "密码引擎内部错误"),
        (BridgeErrorCode.INTERNAL_ERROR, 500, "CRYPTO_INTERNAL_ERROR", "密码引擎内部错误"),
    ],
)
def test_crypto_error_uses_fixed_http_mapping(
    bridge_code: BridgeErrorCode,
    status_code: int,
    api_code: str,
    message: str,
) -> None:
    api_error = crypto_error_to_api_error(CryptoBridgeError(bridge_code))

    assert api_error.status_code == status_code
    assert api_error.code == api_code
    assert api_error.message == message
    assert api_error.details == {}


def test_crypto_error_mapping_does_not_use_exception_text() -> None:
    error = CryptoBridgeError(BridgeErrorCode.INTERNAL_ERROR)
    error.args = ("untrusted-text",)

    api_error = crypto_error_to_api_error(error)

    assert api_error.message == "密码引擎内部错误"
    assert "untrusted-text" not in api_error.message
