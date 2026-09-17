from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.security.tokens import (
    PyJwtTokenCodec,
    TokenIssuerError,
    get_runtime_jwt_codec,
)

SECRET = b"a-real-deployment-secret-must-be-at-least-32-bytes"
NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)


def test_runtime_codec_roundtrip_and_required_claims() -> None:
    codec = PyJwtTokenCodec(SECRET)
    token = codec.issue_access_token(
        "00000000-0000-4000-8000-000000000001",
        "student",
        NOW,
        sid="session-1",
    )

    claims = codec.verify_access_token(token, NOW + timedelta(minutes=1))

    assert claims["sub"] == "00000000-0000-4000-8000-000000000001"
    assert claims["role"] == "student"
    assert claims["sid"] == "session-1"
    assert isinstance(claims["jti"], str)


def test_runtime_codec_rejects_tamper_expiry_and_algorithm_downgrade() -> None:
    codec = PyJwtTokenCodec(SECRET)
    token = codec.issue_access_token(
        "00000000-0000-4000-8000-000000000001", "teacher", NOW
    )
    parts = token.split(".")
    replacement = "A" if parts[2][0] != "A" else "B"
    tampered = f"{parts[0]}.{parts[1]}.{replacement}{parts[2][1:]}"
    unsigned = jwt.encode(
        {
            "sub": "00000000-0000-4000-8000-000000000001",
            "role": "teacher",
            "iat": int(NOW.timestamp()),
            "exp": int((NOW + timedelta(hours=2)).timestamp()),
            "jti": "unsigned",
        },
        key="",
        algorithm="none",
    )

    for invalid, verification_time in (
        (tampered, NOW),
        (token, NOW + timedelta(hours=2)),
        (unsigned, NOW),
    ):
        with pytest.raises(TokenIssuerError):
            codec.verify_access_token(invalid, verification_time)


@pytest.mark.parametrize("secret", [b"", b"too-short"])
def test_runtime_codec_rejects_weak_secret(secret: bytes) -> None:
    with pytest.raises(TokenIssuerError):
        PyJwtTokenCodec(secret)


def test_runtime_codec_loads_only_from_configured_secret_file(
    tmp_path, monkeypatch
) -> None:
    secret_file = tmp_path / "jwt_secret"
    secret_file.write_bytes(SECRET + b"\n")
    monkeypatch.setenv("CRYPTOCAMPUS_JWT_SECRET_FILE", str(secret_file))
    get_runtime_jwt_codec.cache_clear()
    try:
        codec = get_runtime_jwt_codec()
        token = codec.issue_access_token(
            "00000000-0000-4000-8000-000000000001", "admin", NOW
        )
        assert codec.verify_access_token(token, NOW)["role"] == "admin"
    finally:
        get_runtime_jwt_codec.cache_clear()


def test_runtime_codec_fails_closed_when_secret_file_is_missing(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv(
        "CRYPTOCAMPUS_JWT_SECRET_FILE", str(tmp_path / "missing-secret")
    )
    get_runtime_jwt_codec.cache_clear()
    try:
        with pytest.raises(TokenIssuerError):
            get_runtime_jwt_codec()
    finally:
        get_runtime_jwt_codec.cache_clear()
