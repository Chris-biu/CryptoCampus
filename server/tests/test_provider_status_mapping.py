import pytest

from app.crypto.types import ProviderStatus
from app.services.system_status import (
    ALLOWED_CAPABILITIES,
    REQUIRED_CORE_CAPABILITIES,
    map_provider_status_to_system_status,
)


def test_online_with_all_core_capabilities_maps_to_ok_and_online() -> None:
    status = ProviderStatus(
        state="online",
        version="1.0",
        provider="mock",
        capabilities={"sm2": True, "sm3": True, "sm4_gcm": True, "ml_kem_768": True},
    )
    result = map_provider_status_to_system_status(status, "1.0.0")

    assert result.api == "ok"
    assert result.engine == "online"
    assert result.version == "1.0.0"
    assert result.tlcp == "unknown"
    assert result.providers == {
        "sm2": True,
        "sm3": True,
        "sm4_gcm": True,
        "ml_kem_768": True,
    }


@pytest.mark.parametrize("missing_core", list(REQUIRED_CORE_CAPABILITIES))
def test_online_with_any_core_capability_false_maps_to_degraded(missing_core: str) -> None:
    caps = {core: True for core in REQUIRED_CORE_CAPABILITIES}
    caps[missing_core] = False
    status = ProviderStatus(
        state="online",
        version="1.0",
        provider="mock",
        capabilities=caps,
    )
    result = map_provider_status_to_system_status(status, "1.0.0")

    assert result.api == "degraded"
    assert result.engine == "degraded"
    assert result.providers[missing_core] is False


def test_degraded_state_maps_to_degraded_and_degraded() -> None:
    status = ProviderStatus(
        state="degraded",
        version="1.0",
        provider="mock",
        capabilities={"sm2": True, "sm3": True},
    )
    result = map_provider_status_to_system_status(status, "1.0.0")

    assert result.api == "degraded"
    assert result.engine == "degraded"
    assert result.providers == {"sm2": True, "sm3": True}


def test_offline_state_maps_to_degraded_offline_and_empty_providers() -> None:
    status = ProviderStatus(
        state="offline",
        version="unknown",
        provider="unavailable",
        capabilities={"sm2": True, "sm3": True},
    )
    result = map_provider_status_to_system_status(status, "1.0.0")

    assert result.api == "degraded"
    assert result.engine == "offline"
    assert result.providers == {}


def test_unknown_capability_keys_are_filtered(caplog) -> None:
    status = ProviderStatus(
        state="online",
        version="1.0",
        provider="mock",
        capabilities={
            "sm2": True,
            "sm3": True,
            "sm4_gcm": True,
            "secret_crypto_lib": True,
            "internal_path": True,
        },
    )
    result = map_provider_status_to_system_status(status, "1.0.0")

    assert "secret_crypto_lib" not in result.providers
    assert "internal_path" not in result.providers
    assert set(result.providers.keys()).issubset(ALLOWED_CAPABILITIES)
    assert result.api == "ok"
    assert result.engine == "online"


def test_public_extended_capabilities_are_preserved() -> None:
    status = ProviderStatus(
        state="online",
        version="1.0",
        provider="hitls",
        capabilities={
            "sm2": True,
            "sm3": True,
            "sm4_gcm": True,
            "hkdf_sm3": True,
            "pki": True,
            "envelope": True,
            "blind_signature": True,
            "pqc": False,
        },
    )

    result = map_provider_status_to_system_status(status, "1.0.0")

    assert result.providers["blind_signature"] is True
    assert result.providers["pqc"] is False
    assert result.api == "ok"


@pytest.mark.parametrize(
    "invalid_status",
    [
        None,
        "not-a-status",
        ProviderStatus(
            state="invalid_state",  # type: ignore[arg-type]
            version="1.0",
            provider="mock",
            capabilities={},
        ),
        ProviderStatus(
            state="online",
            version="1.0",
            provider="mock",
            capabilities={"sm2": "true"},  # type: ignore[dict-item]
        ),
        ProviderStatus(
            state="online",
            version="1.0",
            provider="mock",
            capabilities={"sm2": 1},  # type: ignore[dict-item]
        ),
    ],
)
def test_illegal_status_or_types_safely_maps_to_offline(invalid_status) -> None:
    result = map_provider_status_to_system_status(invalid_status, "1.0.0")
    assert result.api == "degraded"
    assert result.engine == "offline"
    assert result.providers == {}
