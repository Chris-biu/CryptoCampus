from collections.abc import Mapping
import logging
from typing import Any, Protocol

from app.core.config import get_settings
from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.crypto.types import ProviderStatus
from app.schemas.system import SystemStatus

logger = logging.getLogger(__name__)

ALLOWED_CAPABILITIES: frozenset[str] = frozenset(
    {
        "sm2",
        "sm3",
        "sm4_gcm",
        "hkdf_sm3",
        "pki",
        "envelope",
        "blind_signature",
        "ml_kem_768",
        "ml_dsa_65",
        "pqc",
        "tlcp",
    }
)
REQUIRED_CORE_CAPABILITIES: frozenset[str] = frozenset(
    {"sm2", "sm3", "sm4_gcm"}
)


def map_provider_status_to_system_status(
    provider_status: Any,
    app_version: str,
) -> SystemStatus:
    if not isinstance(provider_status, ProviderStatus):
        return _offline_status(app_version)

    if provider_status.state not in ("online", "offline", "degraded"):
        return _offline_status(app_version)

    if not isinstance(provider_status.capabilities, (dict, Mapping)):
        return _offline_status(app_version)

    filtered_capabilities: dict[str, bool] = {}
    for key, val in provider_status.capabilities.items():
        if not isinstance(key, str) or type(val) is not bool:
            logger.warning("Illegal capability type encountered in provider status")
            return _offline_status(app_version)
        if key not in ALLOWED_CAPABILITIES:
            logger.warning("Ignoring unknown capability key: %s", key)
            continue
        filtered_capabilities[key] = val

    if provider_status.state == "offline":
        return _offline_status(app_version)

    if provider_status.state == "degraded":
        return SystemStatus(
            api="degraded",
            engine="degraded",
            version=app_version,
            tlcp="unknown",
            providers=filtered_capabilities,
        )

    # provider_status.state == "online"
    all_core_ok = all(
        filtered_capabilities.get(core) is True
        for core in REQUIRED_CORE_CAPABILITIES
    )
    if all_core_ok:
        api_state = "ok"
        engine_state = "online"
    else:
        api_state = "degraded"
        engine_state = "degraded"

    return SystemStatus(
        api=api_state,
        engine=engine_state,
        version=app_version,
        tlcp="unknown",
        providers=filtered_capabilities,
    )


def _offline_status(app_version: str | None = None) -> SystemStatus:
    return SystemStatus(
        api="degraded",
        engine="offline",
        version=app_version or get_settings().app_version,
        tlcp="unknown",
        providers={},
    )


class SystemStatusProvider(Protocol):
    async def get_status(self) -> SystemStatus:
        """Return the current public system status."""


class UnavailableSystemStatusProvider:
    async def get_status(self) -> SystemStatus:
        return _offline_status()


class SystemStatusService:
    def __init__(self, engine: CryptoEngine) -> None:
        self._engine = engine

    def get_status(self) -> SystemStatus:
        try:
            provider_status = self._engine.provider_status()
            return map_provider_status_to_system_status(
                provider_status, get_settings().app_version
            )
        except CryptoBridgeError:
            return _offline_status()
        except Exception as exc:
            logger.warning(
                "Unexpected error retrieving provider status: %s",
                exc.__class__.__name__,
            )
            return _offline_status()

    async def get_status_async(self) -> SystemStatus:
        return self.get_status()


class CryptoEngineSystemStatusProvider:
    def __init__(self, engine: CryptoEngine) -> None:
        self._service = SystemStatusService(engine)

    async def get_status(self) -> SystemStatus:
        return self._service.get_status()
