from app.crypto.engine import CryptoEngine
from app.crypto.unavailable import UnavailableCryptoEngine


def _load_real_engine() -> CryptoEngine | None:
    """尝试加载真实 openHiTLS 引擎；任何失败都回退（fail-closed）。

    CI 的 app_verify / 单元测试不会构建 libcc_bridge.so，因此这里会
    稳定回退到 UnavailableCryptoEngine；测试通过依赖注入覆盖本函数。
    生产部署（deploy/runtime/lib 有 .so）时自动启用真实引擎。
    """
    try:
        from app.crypto.hitls import HitlsCryptoEngine

        return HitlsCryptoEngine()
    except Exception:
        return None


_DEFAULT_CRYPTO_ENGINE: CryptoEngine = _load_real_engine() or UnavailableCryptoEngine()


def get_crypto_engine() -> CryptoEngine:
    return _DEFAULT_CRYPTO_ENGINE