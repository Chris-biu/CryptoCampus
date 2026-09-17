from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_SOURCE_FIELDS = ("publisher", "dataset", "received_at", "package_sha256")
PLACEHOLDER_MARKERS = ("placeholder", "example", "todo", "unknown", "待补", "示例")


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    if path.suffix == ".json":
        # Git may materialize text files with CRLF on Windows. KAT JSON
        # digests use Git's canonical LF representation on every OS.
        hasher.update(path.read_bytes().replace(b"\r\n", b"\n"))
        return hasher.hexdigest()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    normalized = value.strip()
    if any(marker in normalized.lower() for marker in PLACEHOLDER_MARKERS):
        raise ValueError(f"{field} contains a placeholder marker")
    return normalized


def verify(manifest_path: Path) -> None:
    manifest_path = manifest_path.resolve(strict=True)
    vector_root = manifest_path.parent
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")

    source = payload.get("source")
    if not isinstance(source, dict):
        raise ValueError("source must be an object")
    for field in REQUIRED_SOURCE_FIELDS:
        value = require_text(source.get(field), f"source.{field}")
        if field == "package_sha256" and not SHA256_PATTERN.fullmatch(value.lower()):
            raise ValueError("source.package_sha256 must be 64 lowercase hex characters")

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("artifacts must be a non-empty array")

    seen_paths: set[Path] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise ValueError(f"artifacts[{index}] must be an object")
        relative = Path(require_text(artifact.get("path"), f"artifacts[{index}].path"))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"artifacts[{index}].path must stay inside the vector directory")
        resolved = (vector_root / relative).resolve(strict=True)
        if vector_root not in resolved.parents or resolved == manifest_path:
            raise ValueError(f"artifacts[{index}].path resolves outside the vector directory")
        if resolved in seen_paths:
            raise ValueError(f"duplicate artifact path: {relative.as_posix()}")
        seen_paths.add(resolved)

        expected = require_text(artifact.get("sha256"), f"artifacts[{index}].sha256").lower()
        if not SHA256_PATTERN.fullmatch(expected):
            raise ValueError(f"artifacts[{index}].sha256 must be 64 lowercase hex characters")
        actual = digest(resolved)
        if actual != expected:
            raise ValueError(f"SHA-256 mismatch for {relative.as_posix()}")

        algorithms = artifact.get("algorithms")
        if not isinstance(algorithms, list) or not algorithms:
            raise ValueError(f"artifacts[{index}].algorithms must be a non-empty array")
        for algorithm_index, algorithm in enumerate(algorithms):
            require_text(algorithm, f"artifacts[{index}].algorithms[{algorithm_index}]")
        require_text(artifact.get("provenance"), f"artifacts[{index}].provenance")

    print(f"Verified {len(artifacts)} KAT artifact(s); manifest={digest(manifest_path)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify provenance and hashes for an official KAT manifest.")
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    verify(args.manifest)


if __name__ == "__main__":
    main()
