from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys
from zipfile import BadZipFile, ZipFile


TEXT_SUFFIXES = {
    ".html",
    ".json",
    ".log",
    ".md",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
MAX_TEXT_BYTES = 8 * 1024 * 1024
REDACTED = {"", "***", "<redacted>", "[redacted]", "redacted", "null", "none"}

PATTERNS = (
    (
        "private-key",
        re.compile(r"-----BEGIN (?:ENCRYPTED |EC |RSA )?PRIVATE KEY-----", re.IGNORECASE),
    ),
    (
        "authorization-token",
        re.compile(r"\bauthorization\s*[:=]\s*bearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    ),
    (
        "refresh-cookie",
        re.compile(r"\brefresh_token\s*=\s*([^;\s\"']+)", re.IGNORECASE),
    ),
    (
        "sensitive-field",
        re.compile(
            r'''["']?(?:password|current_password|new_password|refresh_token|private_key|kek|session_key)["']?\s*[:=]\s*["']([^"'\r\n]{1,512})["']''',
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class Finding:
    source: str
    line: int
    kind: str

    def __str__(self) -> str:
        return f"{self.source}:{self.line}: {self.kind}"


def scan_text(text: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(text):
            if kind in {"refresh-cookie", "sensitive-field"} and match.group(1).strip().lower() in REDACTED:
                continue
            findings.append(Finding(source, text.count("\n", 0, match.start()) + 1, kind))
    return findings


def _decode(payload: bytes) -> str | None:
    if len(payload) > MAX_TEXT_BYTES or b"\x00" in payload[:4096]:
        return None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_file(path: Path) -> list[Finding]:
    if path.suffix.lower() == ".zip":
        findings: list[Finding] = []
        try:
            with ZipFile(path) as archive:
                for member in archive.infolist():
                    if member.is_dir() or member.file_size > MAX_TEXT_BYTES:
                        continue
                    text = _decode(archive.read(member))
                    if text is not None:
                        findings.extend(scan_text(text, f"{path}!{member.filename}"))
        except BadZipFile:
            return [Finding(str(path), 1, "invalid-zip")]
        return findings
    if path.suffix.lower() not in TEXT_SUFFIXES:
        return []
    text = _decode(path.read_bytes())
    return scan_text(text, str(path)) if text is not None else []


def scan_roots(roots: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for root in roots:
        if not root.exists():
            continue
        paths = [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file())
        for path in paths:
            findings.extend(scan_file(path))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan test artifacts for high-confidence secrets")
    parser.add_argument("roots", nargs="+", type=Path)
    args = parser.parse_args(argv)
    findings = scan_roots(args.roots)
    for finding in findings:
        print(finding)
    if findings:
        print(f"sensitive artifact scan failed: {len(findings)} finding(s)")
        return 1
    print("sensitive artifact scan passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
