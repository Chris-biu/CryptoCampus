import secrets
from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from app.crypto.types import SM2_PRIVATE_KEY_SIZE


@runtime_checkable
class RecipientPrivateKeyProvider(Protocol):
    """收件人已解锁受控私钥提供者接口。

    必须遵循最小特权与零信任原则：
    1. 只能返回由收件人授权解锁的受控内存私钥；
    2. 严禁从管理员身份读取任意用户 enc_sk；
    3. 严禁把私钥放入 HTTP 请求或响应；
    4. 若收件人未授权取得私钥或指纹不匹配，返回 None，保持失败关闭（Fail Closed）。
    """

    def get_unlocked_private_key(
        self, *, recipient_user_id: str, key_fingerprint: bytes, now: datetime
    ) -> bytes | None: ...


class DefaultRecipientPrivateKeyProvider:
    """生产环境默认实现：未显式配置安全授权上下文时，默认安全关闭。"""

    def get_unlocked_private_key(
        self, *, recipient_user_id: str, key_fingerprint: bytes, now: datetime
    ) -> bytes | None:
        return None


class FileRecipientPrivateKeyProvider:
    """Read one deployment-authorized recipient key after identity binding checks."""

    def __init__(
        self,
        *,
        recipient_user_id: str,
        sm2_key_fingerprint: bytes,
        sm2_private_key_path: Path,
    ) -> None:
        self._recipient_user_id = recipient_user_id
        self._sm2_key_fingerprint = sm2_key_fingerprint
        self._sm2_private_key_path = sm2_private_key_path

    def get_unlocked_private_key(
        self, *, recipient_user_id: str, key_fingerprint: bytes, now: datetime
    ) -> bytes | None:
        del now
        if (
            recipient_user_id != self._recipient_user_id
            or not isinstance(key_fingerprint, bytes)
            or not secrets.compare_digest(key_fingerprint, self._sm2_key_fingerprint)
        ):
            return None
        try:
            if (
                not self._sm2_private_key_path.is_file()
                or self._sm2_private_key_path.stat().st_size != SM2_PRIVATE_KEY_SIZE
            ):
                return None
            private_key = self._sm2_private_key_path.read_bytes()
            return private_key if len(private_key) == SM2_PRIVATE_KEY_SIZE else None
        except OSError:
            return None


class MockRecipientPrivateKeyProvider:
    """测试专用桩：受控注入测试私钥，严格检验收件人 ID 与密钥指纹。"""

    def __init__(self) -> None:
        self._keys: dict[tuple[str, bytes], bytes] = {}

    def set_key(
        self, recipient_user_id: str, key_fingerprint: bytes, private_key: bytes
    ) -> None:
        self._keys[(recipient_user_id, key_fingerprint)] = private_key

    def get_unlocked_private_key(
        self, *, recipient_user_id: str, key_fingerprint: bytes, now: datetime
    ) -> bytes | None:
        return self._keys.get((recipient_user_id, key_fingerprint))
