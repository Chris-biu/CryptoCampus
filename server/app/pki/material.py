import json
import os
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Iterator, Protocol, runtime_checkable
from uuid import UUID

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import MAX_DER_CERTIFICATE_SIZE, SM2_PRIVATE_KEY_SIZE
from app.pki.types import PlatformCAMaterial

_MAX_MANIFEST_SIZE = 4096
_MANIFEST_FIELDS = frozenset(
    {
        "system_user_id",
        "certificate_serial",
        "not_before",
        "not_after",
    }
)


@runtime_checkable
class PlatformCAMaterialProvider(Protocol):
    def unlocked(self) -> AbstractContextManager[PlatformCAMaterial]: ...


class UnavailablePlatformCAMaterialProvider:
    @contextmanager
    def unlocked(self) -> Iterator[PlatformCAMaterial]:
        raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE)
        yield


class FilePlatformCAMaterialProvider:
    """Load platform CA material from deployment-owned, read-only files."""

    def __init__(
        self,
        manifest_path: Path,
        certificate_path: Path,
        private_key_path: Path,
    ) -> None:
        self._manifest_path = manifest_path
        self._certificate_path = certificate_path
        self._private_key_path = private_key_path

    @contextmanager
    def unlocked(self) -> Iterator[PlatformCAMaterial]:
        manifest = self._load_manifest()
        certificate_der = self._read_bounded(
            self._certificate_path, MAX_DER_CERTIFICATE_SIZE
        )
        private_key = self._read_bounded(
            self._private_key_path, SM2_PRIVATE_KEY_SIZE
        )
        if len(private_key) != SM2_PRIVATE_KEY_SIZE:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        material = PlatformCAMaterial(
            system_user_id=manifest["system_user_id"],
            certificate_serial=manifest["certificate_serial"],
            certificate_der=certificate_der,
            not_before=manifest["not_before"],
            not_after=manifest["not_after"],
            private_key=private_key,
        )
        yield material

    def _load_manifest(self) -> dict[str, str | int]:
        raw = self._read_bounded(self._manifest_path, _MAX_MANIFEST_SIZE)
        try:
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or set(value) != _MANIFEST_FIELDS:
                raise ValueError
            system_user_id = value["system_user_id"]
            certificate_serial = value["certificate_serial"]
            not_before = value["not_before"]
            not_after = value["not_after"]
            if (
                not isinstance(system_user_id, str)
                or str(UUID(system_user_id)) != system_user_id.lower()
                or not isinstance(certificate_serial, str)
                or type(not_before) is not int
                or type(not_after) is not int
            ):
                raise ValueError
            return {
                "system_user_id": system_user_id,
                "certificate_serial": certificate_serial,
                "not_before": not_before,
                "not_after": not_after,
            }
        except (KeyError, TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT) from error

    @staticmethod
    def _read_bounded(path: Path, maximum: int) -> bytes:
        try:
            if not path.is_file():
                raise OSError
            size = path.stat().st_size
            if size <= 0 or size > maximum:
                raise ValueError
            payload = path.read_bytes()
            if len(payload) != size:
                raise OSError
            return payload
        except OSError as error:
            raise CryptoBridgeError(BridgeErrorCode.PROVIDER_UNAVAILABLE) from error
        except ValueError as error:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT) from error


def get_runtime_platform_ca_material_provider() -> PlatformCAMaterialProvider:
    return FilePlatformCAMaterialProvider(
        Path(
            os.getenv(
                "CRYPTOCAMPUS_PLATFORM_CA_MANIFEST_FILE",
                "/run/secrets/cryptocampus/platform_ca.json",
            )
        ),
        Path(
            os.getenv(
                "CRYPTOCAMPUS_PLATFORM_CA_CERT_FILE",
                "/run/secrets/cryptocampus/platform_ca.der",
            )
        ),
        Path(
            os.getenv(
                "CRYPTOCAMPUS_PLATFORM_CA_KEY_FILE",
                "/run/secrets/cryptocampus/platform_ca.key",
            )
        ),
    )
