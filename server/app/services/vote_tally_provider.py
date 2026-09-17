import json
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable
from uuid import UUID

from app.crypto.types import (
    MAX_DER_CERTIFICATE_SIZE,
    SM2_PRIVATE_KEY_SIZE,
    SM2_PUBLIC_KEY_SIZE,
)


class VoteTallyMaterialUnavailableError(Exception):
    def __init__(
        self, code: str = "engine_unavailable", message: str = "计票台签名材料不可用"
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class VoteTallyMaterial:
    system_user_id: str
    certificate_serial: str
    certificate_der: bytes
    public_key: bytes
    private_key: bytes = field(repr=False)


@runtime_checkable
class VoteTallyMaterialProvider(Protocol):
    @contextmanager
    def unlocked(self) -> Iterator[VoteTallyMaterial]: ...


class DefaultVoteTallyMaterialProvider:
    @contextmanager
    def unlocked(self) -> Iterator[VoteTallyMaterial]:
        raise VoteTallyMaterialUnavailableError(
            "engine_unavailable", "计票台系统密钥或证书不可用"
        )
        yield  # type: ignore[unreachable]


class FileVoteTallyMaterialProvider:
    """Load the isolated tally identity from a read-only deployment directory."""

    _MANIFEST_NAME = "tally.json"
    _CERTIFICATE_NAME = "tally.der"
    _PUBLIC_KEY_NAME = "tally.pub"
    _PRIVATE_KEY_NAME = "tally.key"

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    @contextmanager
    def unlocked(self) -> Iterator[VoteTallyMaterial]:
        private_key = b""
        try:
            manifest_path = self._directory / self._MANIFEST_NAME
            certificate_path = self._directory / self._CERTIFICATE_NAME
            public_key_path = self._directory / self._PUBLIC_KEY_NAME
            private_key_path = self._directory / self._PRIVATE_KEY_NAME
            if (
                not manifest_path.is_file()
                or not certificate_path.is_file()
                or not public_key_path.is_file()
                or not private_key_path.is_file()
                or not 0 < manifest_path.stat().st_size <= 2048
                or not 0 < certificate_path.stat().st_size <= MAX_DER_CERTIFICATE_SIZE
                or public_key_path.stat().st_size != SM2_PUBLIC_KEY_SIZE
                or private_key_path.stat().st_size != SM2_PRIVATE_KEY_SIZE
            ):
                raise ValueError("incomplete tally material")

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict) or set(manifest) != {
                "system_user_id",
                "certificate_serial",
            }:
                raise ValueError("invalid tally manifest")
            system_user_id = manifest["system_user_id"]
            certificate_serial = manifest["certificate_serial"]
            if (
                not isinstance(system_user_id, str)
                or str(UUID(system_user_id)) != system_user_id.lower()
                or not isinstance(certificate_serial, str)
                or re.fullmatch(r"[A-Za-z0-9:-]{1,128}", certificate_serial) is None
            ):
                raise ValueError("invalid tally identity")

            certificate_der = certificate_path.read_bytes()
            public_key = public_key_path.read_bytes()
            private_key = private_key_path.read_bytes()
            if (
                not certificate_der
                or len(certificate_der) > MAX_DER_CERTIFICATE_SIZE
                or len(public_key) != SM2_PUBLIC_KEY_SIZE
                or public_key[0] != 0x04
                or len(private_key) != SM2_PRIVATE_KEY_SIZE
            ):
                raise ValueError("invalid tally key material")

            yield VoteTallyMaterial(
                system_user_id=system_user_id,
                certificate_serial=certificate_serial,
                certificate_der=certificate_der,
                public_key=public_key,
                private_key=private_key,
            )
        except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as err:
            raise VoteTallyMaterialUnavailableError(
                "engine_unavailable", "计票台系统密钥或证书不可用"
            ) from err
        finally:
            private_key = b""


_DEFAULT_VOTE_TALLY_PROVIDER = FileVoteTallyMaterialProvider(
    Path(
        os.getenv(
            "CRYPTOCAMPUS_VOTE_TALLY_MATERIAL_DIR",
            "/run/secrets/cryptocampus/vote_tally",
        )
    )
)


def get_vote_tally_provider() -> VoteTallyMaterialProvider:
    return _DEFAULT_VOTE_TALLY_PROVIDER
