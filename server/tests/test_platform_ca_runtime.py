from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest
from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.pki.material import (
    FilePlatformCAMaterialProvider,
    get_runtime_platform_ca_material_provider,
)


def _write_material(directory: Path) -> tuple[Path, Path, Path, str]:
    system_user_id = str(uuid4())
    manifest = directory / "platform_ca.json"
    certificate = directory / "platform_ca.der"
    private_key = directory / "platform_ca.key"
    manifest.write_text(
        json.dumps(
            {
                "system_user_id": system_user_id,
                "certificate_serial": "ca-runtime-1",
                "not_before": 1,
                "not_after": 2_000_000_000,
            }
        ),
        encoding="utf-8",
    )
    certificate.write_bytes(b"runtime-ca-certificate")
    private_key.write_bytes(b"k" * 32)
    return manifest, certificate, private_key, system_user_id


def test_file_provider_loads_complete_material(tmp_path: Path) -> None:
    manifest, certificate, private_key, system_user_id = _write_material(tmp_path)
    provider = FilePlatformCAMaterialProvider(manifest, certificate, private_key)

    with provider.unlocked() as material:
        assert material.system_user_id == system_user_id
        assert material.certificate_serial == "ca-runtime-1"
        assert material.certificate_der == b"runtime-ca-certificate"
        assert material.private_key == b"k" * 32
        assert "k" * 32 not in repr(material)


def test_file_provider_missing_file_fails_closed(tmp_path: Path) -> None:
    provider = FilePlatformCAMaterialProvider(
        tmp_path / "missing.json",
        tmp_path / "missing.der",
        tmp_path / "missing.key",
    )

    with pytest.raises(CryptoBridgeError) as raised:
        with provider.unlocked():
            pass

    assert raised.value.code is BridgeErrorCode.PROVIDER_UNAVAILABLE


@pytest.mark.parametrize(
    "mutate",
    [
        lambda manifest, certificate, key: manifest.write_text("{}", encoding="utf-8"),
        lambda manifest, certificate, key: key.write_bytes(b"short"),
        lambda manifest, certificate, key: certificate.write_bytes(b""),
    ],
)
def test_file_provider_rejects_invalid_material(tmp_path: Path, mutate) -> None:
    manifest, certificate, private_key, _ = _write_material(tmp_path)
    mutate(manifest, certificate, private_key)
    provider = FilePlatformCAMaterialProvider(manifest, certificate, private_key)

    with pytest.raises(CryptoBridgeError) as raised:
        with provider.unlocked():
            pass

    assert raised.value.code is BridgeErrorCode.INVALID_ARGUMENT


def test_runtime_provider_uses_configured_read_only_paths(
    tmp_path: Path, monkeypatch
) -> None:
    manifest, certificate, private_key, _ = _write_material(tmp_path)
    monkeypatch.setenv("CRYPTOCAMPUS_PLATFORM_CA_MANIFEST_FILE", str(manifest))
    monkeypatch.setenv("CRYPTOCAMPUS_PLATFORM_CA_CERT_FILE", str(certificate))
    monkeypatch.setenv("CRYPTOCAMPUS_PLATFORM_CA_KEY_FILE", str(private_key))

    provider = get_runtime_platform_ca_material_provider()

    with provider.unlocked() as material:
        assert material.certificate_serial == "ca-runtime-1"
