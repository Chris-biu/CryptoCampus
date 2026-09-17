import os
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Protocol
from uuid import uuid4

import jwt


class TokenIssuerError(Exception):
    def __init__(self) -> None:
        super().__init__("token_issue_failed")


class AccessTokenIssuer(Protocol):
    def issue_access_token(
        self, user_id: str, role: str, now: datetime, sid: str | None = None
    ) -> str: ...


TokenIssuer = AccessTokenIssuer
SessionIssuer = AccessTokenIssuer


class TokenVerifier(Protocol):
    def verify_access_token(self, token: str, now: datetime) -> dict[str, object]: ...


class JwtEncoder(Protocol):
    def __call__(self, claims: dict[str, object]) -> str: ...


class JwtTokenIssuer:
    def __init__(self, encoder: Callable[[dict[str, object]], str]) -> None:
        self._encoder = encoder

    def issue_access_token(
        self, user_id: str, role: str, now: datetime, sid: str | None = None
    ) -> str:
        try:
            issued_at = now.astimezone(timezone.utc)
            claims: dict[str, object] = {
                "sub": user_id,
                "role": role,
                "iat": int(issued_at.timestamp()),
                "exp": int((issued_at + timedelta(hours=2)).timestamp()),
                "jti": str(uuid4()),
            }
            if sid is not None:
                claims["sid"] = sid
            token = self._encoder(claims)
            if not isinstance(token, str) or not token:
                raise ValueError
            return token
        except Exception as error:
            raise TokenIssuerError() from error


class PyJwtTokenCodec:
    """Approved-library JWT issuer/verifier backed by one deployment secret."""

    def __init__(self, secret: bytes) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise TokenIssuerError()
        self._secret = secret
        self._issuer = JwtTokenIssuer(self._encode)

    def _encode(self, claims: dict[str, object]) -> str:
        return jwt.encode(claims, self._secret, algorithm="HS256")

    def issue_access_token(
        self, user_id: str, role: str, now: datetime, sid: str | None = None
    ) -> str:
        return self._issuer.issue_access_token(user_id, role, now, sid)

    def verify_access_token(self, token: str, now: datetime) -> dict[str, object]:
        try:
            if not isinstance(token, str) or not token or len(token) > 8192:
                raise ValueError
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                options={
                    "require": ["sub", "role", "iat", "exp", "jti"],
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
            issued_at = claims.get("iat")
            expires_at = claims.get("exp")
            subject = claims.get("sub")
            role = claims.get("role")
            token_id = claims.get("jti")
            now_timestamp = int(now.astimezone(timezone.utc).timestamp())
            if (
                type(issued_at) is not int
                or type(expires_at) is not int
                or expires_at <= now_timestamp
                or issued_at > now_timestamp + 60
                or expires_at - issued_at != 7200
                or not isinstance(subject, str)
                or not subject
                or role not in {"student", "admin", "teacher"}
                or not isinstance(token_id, str)
                or not token_id
            ):
                raise ValueError
            session_id = claims.get("sid")
            if session_id is not None and (not isinstance(session_id, str) or not session_id):
                raise ValueError
            return dict(claims)
        except Exception as error:
            raise TokenIssuerError() from error


def _jwt_secret_path() -> Path:
    return Path(
        os.getenv(
            "CRYPTOCAMPUS_JWT_SECRET_FILE",
            "/run/secrets/cryptocampus/jwt_secret",
        )
    )


@lru_cache(maxsize=1)
def get_runtime_jwt_codec() -> PyJwtTokenCodec:
    try:
        path = _jwt_secret_path()
        if not path.is_file() or path.stat().st_size > 4096:
            raise ValueError
        secret = path.read_bytes().strip()
        return PyJwtTokenCodec(secret)
    except Exception as error:
        raise TokenIssuerError() from error
