from datetime import datetime, timedelta, timezone

import pytest

from app.security.tokens import JwtTokenIssuer, TokenIssuerError


def test_token_issuer_passes_required_claims_to_injected_encoder() -> None:
    captured: dict[str, object] = {}

    def encoder(claims: dict[str, object]) -> str:
        captured.update(claims)
        return "opaque-access-token"

    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    token = JwtTokenIssuer(encoder).issue_access_token("user-1", "student", now)

    assert token == "opaque-access-token"
    assert captured["sub"] == "user-1"
    assert captured["role"] == "student"
    assert captured["exp"] == int((now + timedelta(seconds=7200)).timestamp())
    assert captured["iat"] == int(now.timestamp())


def test_token_issuer_can_include_session_id_claim() -> None:
    captured: dict[str, object] = {}
    JwtTokenIssuer(lambda claims: captured.update(claims) or "token").issue_access_token(
        "user-1", "student", datetime(2030, 1, 1, tzinfo=timezone.utc), sid="session-1"
    )
    assert captured["sid"] == "session-1"


def test_token_issuer_maps_encoder_failure_to_fixed_error() -> None:
    def encoder(_: dict[str, object]) -> str:
        raise RuntimeError("secret details")

    with pytest.raises(TokenIssuerError) as raised:
        JwtTokenIssuer(encoder).issue_access_token(
            "user-1", "student", datetime.now(timezone.utc)
        )

    assert str(raised.value) == "token_issue_failed"
    assert "secret details" not in str(raised.value)
