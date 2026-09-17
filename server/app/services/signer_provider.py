import os
from pathlib import Path
from typing import Protocol, runtime_checkable

from app.crypto.types import SM2_PRIVATE_KEY_SIZE, SM2_PUBLIC_KEY_SIZE

_SERVICE_FILES = {
    "hole_post": ("hole_post.sk", "hole_post.pk"),
    "hole_comment": ("hole_comment.sk", "hole_comment.pk"),
    "hole_like": ("hole_like.sk", "hole_like.pk"),
}


@runtime_checkable
class ServerSignerKeyProvider(Protocol):
    def get_signer_private_key(self, service: str) -> bytes | None: ...


@runtime_checkable
class ServerSignerVerificationKeyProvider(Protocol):
    def get_signer_public_key(self, service: str) -> bytes | None: ...


class DefaultServerSignerKeyProvider:
    def get_signer_private_key(self, service: str) -> bytes | None:
        # Production default fail-closed: returns None until a controlled HSM/KMS
        # provider is configured. Never use user private keys or static test keys.
        return None

    def get_signer_public_key(self, service: str) -> bytes | None:
        # Production default fail-closed: returns None until a controlled HSM/KMS
        # provider is configured. Never use user public keys or static test keys.
        return None


class FileServerSignerKeyProvider:
    """Load service-isolated signing keys from a deployment-owned directory."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    def get_signer_private_key(self, service: str) -> bytes | None:
        filenames = _SERVICE_FILES.get(service)
        if filenames is None:
            return None
        return self._read_exact(filenames[0], SM2_PRIVATE_KEY_SIZE)

    def get_signer_public_key(self, service: str) -> bytes | None:
        filenames = _SERVICE_FILES.get(service)
        if filenames is None:
            return None
        public_key = self._read_exact(filenames[1], SM2_PUBLIC_KEY_SIZE)
        if public_key is None or public_key[0] != 0x04:
            return None
        return public_key

    def _read_exact(self, filename: str, expected_size: int) -> bytes | None:
        try:
            path = self._directory / filename
            if not path.is_file() or path.stat().st_size != expected_size:
                return None
            payload = path.read_bytes()
            return payload if len(payload) == expected_size else None
        except OSError:
            return None


_DEFAULT_SIGNER_KEY_PROVIDER = FileServerSignerKeyProvider(
    Path(
        os.getenv(
            "CRYPTOCAMPUS_HOLE_SIGNER_DIR",
            "/run/secrets/cryptocampus/hole_signers",
        )
    )
)


def get_signer_key_provider() -> ServerSignerKeyProvider:
    return _DEFAULT_SIGNER_KEY_PROVIDER


def get_signer_verification_key_provider() -> ServerSignerVerificationKeyProvider:
    return _DEFAULT_SIGNER_KEY_PROVIDER
