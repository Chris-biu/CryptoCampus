from dataclasses import dataclass
import re


REFRESH_COOKIE_NAME = "refresh_token"
REFRESH_COOKIE_PATH = "/api/v1/auth"
REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,512}$")


class RefreshCookieError(ValueError):
    pass


@dataclass(frozen=True)
class RefreshCookie:
    name: str
    value: str
    httponly: bool = True
    secure: bool = True
    samesite: str = "lax"
    path: str = REFRESH_COOKIE_PATH
    max_age: int = REFRESH_TOKEN_MAX_AGE


def set_refresh_cookie(response, token: str) -> None:
    cookie = build_refresh_cookie(token)
    response.set_cookie(
        cookie.name,
        cookie.value,
        max_age=cookie.max_age,
        httponly=cookie.httponly,
        secure=cookie.secure,
        samesite=cookie.samesite,
        path=cookie.path,
    )


def clear_refresh_cookie(response) -> None:
    response.delete_cookie(REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH)


def parse_refresh_token(value: str | None) -> str:
    if not isinstance(value, str) or not _TOKEN_PATTERN.fullmatch(value):
        raise RefreshCookieError("invalid_refresh_cookie")
    return value


def build_refresh_cookie(token: str) -> RefreshCookie:
    return RefreshCookie(REFRESH_COOKIE_NAME, parse_refresh_token(token))
