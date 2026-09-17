from pathlib import Path
from zipfile import ZipFile

from sensitive_scan import scan_file, scan_text


def test_scanner_detects_private_keys_bearer_tokens_and_refresh_cookies() -> None:
    payload = """
-----BEGIN PRIVATE KEY-----
Authorization: Bearer abcdefghijklmnopqrstuvwxyz
Set-Cookie: refresh_token=opaque-refresh-value; HttpOnly
"""

    assert {finding.kind for finding in scan_text(payload, "report.log")} == {
        "private-key",
        "authorization-token",
        "refresh-cookie",
    }


def test_scanner_allows_explicit_redaction_and_test_names() -> None:
    payload = """
password=[REDACTED]
refresh_token=<redacted>
test_change_password_rejects_invalid_payload
"""

    assert scan_text(payload, "junit.xml") == []


def test_scanner_checks_text_inside_playwright_trace_zip(tmp_path: Path) -> None:
    trace = tmp_path / "trace.zip"
    with ZipFile(trace, "w") as archive:
        archive.writestr("trace.network", '{"private_key":"should-never-be-here"}')

    findings = scan_file(trace)

    assert len(findings) == 1
    assert findings[0].kind == "sensitive-field"
    assert "trace.network" in findings[0].source
