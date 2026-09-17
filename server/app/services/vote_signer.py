import os
from pathlib import Path
from threading import RLock
from typing import Protocol, runtime_checkable
from uuid import UUID

from app.crypto.engine import CryptoEngine
from app.crypto.types import SM2_PRIVATE_KEY_SIZE, SM2_PUBLIC_KEY_SIZE


@runtime_checkable
class VoteSignerMaterialProvider(Protocol):
    def get_signer_private_key(self, *, vote_id: str) -> bytes | None: ...
    def get_signer_public_key(self, *, vote_id: str) -> bytes | None: ...


class FileVoteSignerMaterialProvider:
    """按 vote_id 隔离并持久化签名密钥；目录必须由部署端控制。"""

    def __init__(self, directory: Path | None = None) -> None:
        self._directory = directory or Path(
            os.getenv("CRYPTOCAMPUS_VOTE_SIGNER_DIR", "/var/lib/cryptocampus/vote_signers")
        )
        self._lock = RLock()

    @staticmethod
    def _canonical_id(vote_id: str) -> str | None:
        try:
            return str(UUID(vote_id))
        except (ValueError, TypeError, AttributeError):
            return None

    def _path(self, vote_id: str, suffix: str) -> Path | None:
        canonical = self._canonical_id(vote_id)
        return self._directory / f"{canonical}.{suffix}" if canonical else None

    @staticmethod
    def _read_exact(path: Path | None, size: int) -> bytes | None:
        try:
            if path is None or not path.is_file() or path.stat().st_size != size:
                return None
            payload = path.read_bytes()
            return payload if len(payload) == size else None
        except OSError:
            return None

    def get_signer_private_key(self, *, vote_id: str) -> bytes | None:
        return self._read_exact(self._path(vote_id, "sk"), SM2_PRIVATE_KEY_SIZE)

    def get_signer_public_key(self, *, vote_id: str) -> bytes | None:
        key = self._read_exact(self._path(vote_id, "pk"), SM2_PUBLIC_KEY_SIZE)
        return key if key is not None and key[0] == 0x04 else None

    def ensure_keypair(self, *, vote_id: str, engine: CryptoEngine) -> bytes:
        private_path = self._path(vote_id, "sk")
        public_path = self._path(vote_id, "pk")
        if private_path is None or public_path is None:
            raise ValueError("vote_id 必须为 UUID")
        with self._lock:
            existing_private = self._read_exact(private_path, SM2_PRIVATE_KEY_SIZE)
            existing_public = self._read_exact(public_path, SM2_PUBLIC_KEY_SIZE)
            if existing_private is not None and existing_public is not None:
                return existing_public
            pair = engine.sm2_generate_keypair()
            if (
                len(pair.private_key) != SM2_PRIVATE_KEY_SIZE
                or len(pair.public_key) != SM2_PUBLIC_KEY_SIZE
                or pair.public_key[0] != 0x04
            ):
                raise ValueError("密码引擎返回的投票签名密钥无效")
            self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            private_tmp = private_path.with_suffix(".sk.tmp")
            public_tmp = public_path.with_suffix(".pk.tmp")
            private_tmp.write_bytes(pair.private_key)
            public_tmp.write_bytes(pair.public_key)
            try:
                os.chmod(private_tmp, 0o600)
                os.chmod(public_tmp, 0o644)
            except OSError:
                pass
            private_tmp.replace(private_path)
            public_tmp.replace(public_path)
            return pair.public_key


DefaultVoteSignerMaterialProvider = FileVoteSignerMaterialProvider

_DEFAULT_VOTE_SIGNER_PROVIDER = FileVoteSignerMaterialProvider(
    Path(os.getenv("CRYPTOCAMPUS_VOTE_SIGNER_DIR", "/var/lib/cryptocampus/vote_signers"))
)


def get_vote_signer_provider() -> VoteSignerMaterialProvider:
    return _DEFAULT_VOTE_SIGNER_PROVIDER
