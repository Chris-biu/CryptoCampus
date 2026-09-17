from dataclasses import dataclass
from datetime import datetime, timezone
from typing import NoReturn
from uuid import UUID

from fastapi import Depends, Header
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.db.session import get_db
from app.models.user import User
from app.security.tokens import TokenIssuerError, TokenVerifier, get_runtime_jwt_codec

HTTP_ROLES = frozenset({"student", "admin", "teacher"})


@dataclass(frozen=True)
class CurrentUser:
    user_id: str
    role: str
    status: str
    session_id: str | None = None


def _unauthorized() -> NoReturn:
    raise ApiError(401, "UNAUTHORIZED", "未授权")


def get_token_verifier() -> TokenVerifier:
    try:
        return get_runtime_jwt_codec()
    except TokenIssuerError:
        _unauthorized()


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        _unauthorized()
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        _unauthorized()
    return parts[1]


def authenticate_access_token(
    token: str,
    verifier: TokenVerifier,
    session: Session,
    now: datetime | None = None,
) -> CurrentUser:
    verification_time = now or datetime.now(timezone.utc)
    try:
        claims = verifier.verify_access_token(token, verification_time)
    except Exception:
        _unauthorized()
    if not isinstance(claims, dict):
        _unauthorized()

    subject = claims.get("sub")
    token_role = claims.get("role")
    if not isinstance(subject, str) or not isinstance(token_role, str):
        _unauthorized()
    try:
        UUID(subject)
    except (ValueError, AttributeError):
        _unauthorized()
    if token_role not in HTTP_ROLES:
        _unauthorized()

    user = session.get(User, subject)
    if user is None or user.status != "active":
        _unauthorized()
    if user.role not in HTTP_ROLES or user.role != token_role:
        _unauthorized()

    session_id = claims.get("sid")
    return CurrentUser(
        user_id=user.id,
        role=user.role,
        status=user.status,
        session_id=session_id if isinstance(session_id, str) else None,
    )


def get_current_user(
    authorization: str | None = Header(default=None, alias="Authorization"),
    verifier: TokenVerifier = Depends(get_token_verifier),
    session: Session = Depends(get_db),
) -> CurrentUser:
    token = _extract_bearer_token(authorization)
    return authenticate_access_token(token, verifier, session)


def require_authenticated_user(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    return current_user


def require_roles(*allowed_roles: str):
    if not allowed_roles or any(role not in HTTP_ROLES for role in allowed_roles):
        raise ValueError("allowed_roles must contain only HTTP roles")
    allowed = frozenset(allowed_roles)

    def dependency(
        current_user: CurrentUser = Depends(require_authenticated_user),
    ) -> CurrentUser:
        if current_user.role not in allowed:
            raise ApiError(403, "FORBIDDEN", "无权限")
        return current_user

    return dependency
