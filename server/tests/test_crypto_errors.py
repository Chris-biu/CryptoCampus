import pytest

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError


@pytest.mark.parametrize(
    ("code", "message"),
    [
        (BridgeErrorCode.INVALID_ARGUMENT, "参数不合法"),
        (BridgeErrorCode.BUFFER_TOO_SMALL, "输出缓冲区不足"),
        (BridgeErrorCode.AUTH_FAILED, "凭据校验失败"),
        (BridgeErrorCode.INTEGRITY_FAILED, "完整性校验失败"),
        (BridgeErrorCode.CERT_INVALID, "证书无效"),
        (BridgeErrorCode.CERT_REVOKED, "证书已吊销"),
        (BridgeErrorCode.REPLAYED, "检测到重复使用"),
        (BridgeErrorCode.QUOTA_REJECTED, "额度不足"),
        (BridgeErrorCode.UNSUPPORTED, "当前密码能力不支持"),
        (BridgeErrorCode.PROVIDER_UNAVAILABLE, "密码引擎不可用"),
        (BridgeErrorCode.RANDOM_FAILED, "安全随机数失败"),
        (BridgeErrorCode.MEMORY_FAILED, "安全内存失败"),
        (BridgeErrorCode.INTERNAL_ERROR, "密码引擎内部错误"),
    ],
)
def test_crypto_bridge_error_uses_fixed_redacted_message(
    code: BridgeErrorCode, message: str
) -> None:
    error = CryptoBridgeError(code)

    assert error.code is code
    assert str(error) == message


def test_crypto_bridge_error_does_not_accept_dynamic_message() -> None:
    with pytest.raises(TypeError):
        CryptoBridgeError(BridgeErrorCode.INTERNAL_ERROR, "dynamic")  # type: ignore[call-arg]
