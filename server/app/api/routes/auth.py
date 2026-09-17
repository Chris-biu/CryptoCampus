from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.api.routes.system import get_crypto_engine
from app.core.errors import ApiError, crypto_error_to_api_error
from app.crypto.engine import CryptoEngine
from app.crypto.errors import CryptoBridgeError
from app.db.session import get_db
from app.pki.dependencies import build_platform_ca_service
from app.schemas.auth import (
    Accepted,
    AuthSession,
    LoginRequest,
    RegisterRequest,
    RequestCodeRequest,
    UserSummary,
)
from app.security.cookies import (
    RefreshCookieError,
    clear_refresh_cookie,
    parse_refresh_token,
    set_refresh_cookie,
)
from app.security.key_cache import PrivateKeyUnlockCache
from app.security.tokens import (
    AccessTokenIssuer,
    TokenIssuerError,
    get_runtime_jwt_codec,
)
from app.services.login import LoginError, LoginService
from app.services.registration import (
    AuthSession as RegistrationAuthSession,
)
from app.services.registration import (
    RegistrationError,
    RegistrationService,
    TokenIssuer,
)
from app.services.sessions import SessionError, SessionService
from app.services.smtp_verification import (
    get_runtime_demo_verification_code,
    get_runtime_verification_code_sender,
)
from app.services.verification_code import (
    VerificationCodeError,
    VerificationCodeService,
)
from app.services.verification_code_store import SqlAlchemyVerificationCodeStore


class _UnavailableTokenIssuer:
    def issue(self, user):
        raise RegistrationError("UNSUPPORTED", 503)


class _UnavailableAccessTokenIssuer:
    def issue_access_token(self, user_id: str, role: str, now: datetime) -> str:
        del user_id, role, now
        raise TokenIssuerError()


class _RegistrationJwtTokenIssuer:
    def __init__(self, issuer: AccessTokenIssuer) -> None:
        self._issuer = issuer

    def issue(self, user) -> RegistrationAuthSession:
        now = datetime.now(timezone.utc)
        return RegistrationAuthSession(
            access_token=self._issuer.issue_access_token(user.id, user.role, now),
            user={
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "status": user.status,
                "pqc_mode": user.pqc_pubkey is not None,
                "created_at": user.created_at,
            },
        )


_private_key_cache = PrivateKeyUnlockCache()


def get_verification_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
) -> VerificationCodeService:
    demo_code = get_runtime_demo_verification_code()
    return VerificationCodeService(
        sender=get_runtime_verification_code_sender(),
        store=SqlAlchemyVerificationCodeStore(session, engine),
        crypto_engine=engine,
        code_factory=(lambda: demo_code) if demo_code is not None else None,
    )


def get_token_issuer() -> TokenIssuer:
    try:
        return _RegistrationJwtTokenIssuer(get_runtime_jwt_codec())
    except TokenIssuerError:
        return _UnavailableTokenIssuer()


def get_access_token_issuer() -> AccessTokenIssuer:
    try:
        return get_runtime_jwt_codec()
    except TokenIssuerError:
        return _UnavailableAccessTokenIssuer()


def get_private_key_cache() -> PrivateKeyUnlockCache:
    return _private_key_cache


def get_registration_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    verification: VerificationCodeService = Depends(get_verification_service),
    token_issuer: TokenIssuer = Depends(get_token_issuer),
) -> RegistrationService:
    platform_ca = build_platform_ca_service(session, engine)
    return RegistrationService(
        session, engine, platform_ca, verification, token_issuer
    )


def get_login_service(
    session: Session = Depends(get_db),
    engine: CryptoEngine = Depends(get_crypto_engine),
    token_issuer: AccessTokenIssuer = Depends(get_access_token_issuer),
    key_cache: PrivateKeyUnlockCache = Depends(get_private_key_cache),
) -> LoginService:
    return LoginService(session, engine, token_issuer, key_cache, SessionService(session, engine))


def get_session_service(
    session: Session = Depends(get_db), engine: CryptoEngine = Depends(get_crypto_engine)
) -> SessionService:
    return SessionService(session, engine)


router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register/request-code", response_model=Accepted, status_code=202)
async def request_registration_code(
    request: RequestCodeRequest,
    service: VerificationCodeService = Depends(get_verification_service),
) -> Accepted:
    try:
        service.issue(request.email)
    except VerificationCodeError:
        raise ApiError(503, "PROVIDER_UNAVAILABLE", "服务暂不可用") from None
    return Accepted()


@router.post("/register", response_model=AuthSession, status_code=201)
async def register(
    request: RegisterRequest,
    service: RegistrationService = Depends(get_registration_service),
) -> AuthSession:
    try:
        session = service.register(request.email, request.password, request.verification_code)
    except RegistrationError as error:
        messages = {
            "EMAIL_EXISTS": (409, "CONFLICT", "邮箱已注册"),
            "UNSUPPORTED": (503, "UNSUPPORTED", "当前服务不支持"),
            "CREDENTIALS_INVALID": (422, "VALIDATION_ERROR", "凭据校验失败"),
            "VALIDATION_ERROR": (422, "VALIDATION_ERROR", "参数不合法"),
        }
        status, code, message = messages.get(error.code, (500, "INTERNAL_ERROR", "服务器内部错误"))
        raise ApiError(status, code, message) from None
    except CryptoBridgeError as error:
        raise crypto_error_to_api_error(error) from None
    payload = session.model_dump() if hasattr(session, "model_dump") else session
    user = payload.get("user", {})
    payload["user"] = UserSummary.model_validate({
        "id": user["id"], "email": user["email"], "role": user["role"],
        "status": user["status"], "pqc_mode": bool(user.get("pqc_mode", False)),
        "created_at": user["created_at"],
    })
    return AuthSession.model_validate(payload)


@router.post("/login", response_model=AuthSession)
async def login(
    request_context: Request,
    request: LoginRequest,
    response: Response,
    service: LoginService = Depends(get_login_service),
) -> AuthSession:
    try:
        if getattr(service, "session_service", None) is not None:
            session = service.login(
                request.email,
                request.password,
                datetime.now(timezone.utc),
                request.device_name or "unknown",
                request_context.client.host if request_context.client else "0.0.0.0",
            )
        else:
            session = service.login(request.email, request.password, datetime.now(timezone.utc))
    except LoginError as error:
        mappings = {
            "INVALID_CREDENTIALS": (401, "AUTH_INVALID_CREDENTIALS", "邮箱或密码错误"),
            "RATE_LIMITED": (429, "AUTH_RATE_LIMITED", "请求过于频繁"),
            "PROVIDER_UNAVAILABLE": (503, "PROVIDER_UNAVAILABLE", "服务暂不可用"),
            "INTERNAL_ERROR": (500, "INTERNAL_ERROR", "服务器内部错误"),
        }
        status, code, message = mappings.get(
            error.code, (500, "INTERNAL_ERROR", "服务器内部错误")
        )
        raise ApiError(status, code, message) from None
    payload = session.model_dump() if hasattr(session, "model_dump") else session
    user = payload.get("user", {})
    payload["user"] = UserSummary.model_validate(
        {
            "id": user["id"],
            "email": user["email"],
            "role": user["role"],
            "status": user["status"],
            "pqc_mode": bool(user.get("pqc_mode", False)),
            "created_at": user["created_at"],
        }
    )
    result = AuthSession.model_validate(payload)
    take_refresh_token = getattr(service, "take_refresh_token", None)
    if callable(take_refresh_token):
        refresh_token = take_refresh_token()
        if refresh_token:
            set_refresh_cookie(response, refresh_token)
    return result


@router.post("/refresh", response_model=AuthSession)
async def refresh(
    response: Response,
    request: Request,
    service: SessionService = Depends(get_session_service),
    token_issuer: AccessTokenIssuer = Depends(get_access_token_issuer),
) -> AuthSession:
    try:
        raw = parse_refresh_token(request.cookies.get("refresh_token"))
        new_token, record, user, access_token = service.refresh(
            raw,
            datetime.now(timezone.utc),
            request.headers.get("user-agent", "unknown")[:255],
            request.client.host if request.client else "0.0.0.0",
            token_issuer,
        )
        result = AuthSession(
            access_token=access_token,
            user=UserSummary.model_validate(
                {"id": user.id, "email": user.email, "role": user.role, "status": user.status,
                 "pqc_mode": user.pqc_pubkey is not None, "created_at": user.created_at}
            ),
        )
        set_refresh_cookie(response, new_token)
        return result
    except (RefreshCookieError, SessionError, TokenIssuerError):
        raise ApiError(401, "UNAUTHORIZED", "未授权") from None


@router.post("/logout", status_code=204)
async def logout(
    response: Response,
    request: Request,
    service: SessionService = Depends(get_session_service),
) -> None:
    try:
        service.revoke(parse_refresh_token(request.cookies.get("refresh_token")), datetime.now(timezone.utc))
    except (RefreshCookieError, SessionError):
        raise ApiError(401, "UNAUTHORIZED", "未授权") from None
    clear_refresh_cookie(response)
