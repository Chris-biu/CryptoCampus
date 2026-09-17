import asyncio

from app.core.config import get_settings
from app.crypto.dependencies import get_crypto_engine
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import ProviderStatus
from app.schemas.system import SystemStatus
from app.services.system_status import (
    CryptoEngineSystemStatusProvider,
    UnavailableSystemStatusProvider,
)


def test_default_settings_match_contract() -> None:
    settings = get_settings()

    assert settings.app_name == "CryptoCampus API"
    assert settings.app_version == "1.0.0"
    assert settings.api_prefix == "/api/v1"


def test_database_url_can_be_overridden(monkeypatch) -> None:
    monkeypatch.setenv("CRYPTOCAMPUS_DATABASE_URL", "sqlite+pysqlite:///test.db")

    assert get_settings().database_url == "sqlite+pysqlite:///test.db"


def test_system_status_rejects_unknown_fields() -> None:
    try:
        SystemStatus(
            api="degraded",
            engine="offline",
            version="1.0.0",
            tlcp="unknown",
            providers={},
            secret="must-not-be-accepted",
        )
    except ValueError:
        return

    raise AssertionError("SystemStatus must reject unknown fields")


def test_unavailable_provider_reports_degraded_status() -> None:
    status = asyncio.run(UnavailableSystemStatusProvider().get_status())

    assert status.api == "degraded"
    assert status.engine == "offline"
    assert status.version == "1.0.0"
    assert status.tlcp == "unknown"
    assert status.providers == {}


def test_engine_status_provider_maps_engine_state_and_capabilities() -> None:
    engine = MockCryptoEngine(
        status=ProviderStatus(
            state="online",
            version="test",
            provider="mock",
            capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
        )
    )

    status = asyncio.run(CryptoEngineSystemStatusProvider(engine).get_status())

    assert status.api == "ok"
    assert status.engine == "online"
    assert status.version == "1.0.0"
    assert status.tlcp == "unknown"
    assert status.providers == {"sm2": True, "sm3": True, "sm4_gcm": True}



def test_engine_status_provider_keeps_degraded_engine_state() -> None:
    engine = MockCryptoEngine(
        status=ProviderStatus(
            state="degraded",
            version="test",
            provider="mock",
            capabilities={},
        )
    )

    status = asyncio.run(CryptoEngineSystemStatusProvider(engine).get_status())

    assert status.api == "degraded"
    assert status.engine == "degraded"
    assert status.providers == {}


def test_engine_status_provider_safely_degrades_when_status_lookup_fails(
    monkeypatch,
) -> None:
    engine = MockCryptoEngine()

    def fail_status_lookup() -> ProviderStatus:
        raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE)

    monkeypatch.setattr(engine, "provider_status", fail_status_lookup)

    status = asyncio.run(CryptoEngineSystemStatusProvider(engine).get_status())

    assert status.api == "degraded"
    assert status.engine == "offline"
    assert status.version == "1.0.0"
    assert status.tlcp == "unknown"
    assert status.providers == {}


def test_system_status_endpoint_matches_contract(client) -> None:
    response = client.get("/api/v1/system/status")

    assert response.status_code == 200
    assert response.json() == {
        "api": "degraded",
        "engine": "offline",
        "version": "1.0.0",
        "tlcp": "unknown",
        "providers": {},
    }


def test_system_status_endpoint_uses_injected_crypto_engine(client) -> None:
    client.app.dependency_overrides[get_crypto_engine] = lambda: MockCryptoEngine(
        status=ProviderStatus(
            state="online",
            version="test",
            provider="mock",
            capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
        )
    )

    response = client.get("/api/v1/system/status")

    assert response.status_code == 200
    assert response.json() == {
        "api": "ok",
        "engine": "online",
        "version": "1.0.0",
        "tlcp": "unknown",
        "providers": {"sm2": True, "sm3": True, "sm4_gcm": True},
    }



def test_openapi_contains_system_status(client) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert "/api/v1/system/status" in response.json()["paths"]


def test_swagger_docs_are_available(client) -> None:
    response = client.get("/docs")

    assert response.status_code == 200
