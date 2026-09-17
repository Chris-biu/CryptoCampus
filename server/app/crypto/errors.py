from enum import IntEnum


class BridgeErrorCode(IntEnum):
    OK = 0
    INVALID_ARGUMENT = -1001
    BUFFER_TOO_SMALL = -1002
    AUTH_FAILED = -1003
    INTEGRITY_FAILED = -1004
    CERT_INVALID = -1005
    CERT_REVOKED = -1006
    REPLAYED = -1007
    QUOTA_REJECTED = -1008
    UNSUPPORTED = -1009
    PROVIDER_UNAVAILABLE = -1010
    RANDOM_FAILED = -1011
    MEMORY_FAILED = -1012
    INTERNAL_ERROR = -1099


_ERROR_MESSAGES: dict[BridgeErrorCode, str] = {
    BridgeErrorCode.INVALID_ARGUMENT: "参数不合法",
    BridgeErrorCode.BUFFER_TOO_SMALL: "输出缓冲区不足",
    BridgeErrorCode.AUTH_FAILED: "凭据校验失败",
    BridgeErrorCode.INTEGRITY_FAILED: "完整性校验失败",
    BridgeErrorCode.CERT_INVALID: "证书无效",
    BridgeErrorCode.CERT_REVOKED: "证书已吊销",
    BridgeErrorCode.REPLAYED: "检测到重复使用",
    BridgeErrorCode.QUOTA_REJECTED: "额度不足",
    BridgeErrorCode.UNSUPPORTED: "当前密码能力不支持",
    BridgeErrorCode.PROVIDER_UNAVAILABLE: "密码引擎不可用",
    BridgeErrorCode.RANDOM_FAILED: "安全随机数失败",
    BridgeErrorCode.MEMORY_FAILED: "安全内存失败",
    BridgeErrorCode.INTERNAL_ERROR: "密码引擎内部错误",
}


class CryptoBridgeError(Exception):
    def __init__(self, code: BridgeErrorCode) -> None:
        self.code = code
        super().__init__(_ERROR_MESSAGES.get(code, "密码引擎内部错误"))
