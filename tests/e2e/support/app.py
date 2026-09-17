from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

from fastapi import Header


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SERVER_ROOT = PROJECT_ROOT / "server"
sys.path.insert(0, str(SERVER_ROOT))

from app.api.routes.auth import get_login_service, get_session_service  # noqa: E402
from app.api.routes.me import get_keyring_service, get_me_quota_service  # noqa: E402
from app.api.routes.system import get_crypto_engine  # noqa: E402
from app.core.errors import ApiError  # noqa: E402
from app.crypto.mock import MockCryptoEngine  # noqa: E402
from app.crypto.types import ProviderStatus  # noqa: E402
from app.main import create_app  # noqa: E402
from app.schemas.auth import AuthSession, UserSummary  # noqa: E402
from app.schemas.keyring import KeyringItem, KeyringSummary  # noqa: E402
from app.schemas.quota import Quota  # noqa: E402
from app.schemas.session import DeviceSession  # noqa: E402
from app.security.auth_dependencies import CurrentUser, require_authenticated_user  # noqa: E402
from app.services.login import LoginError  # noqa: E402


USER_ID = "00000000-0000-4000-8000-000000000050"
ACCESS_TOKEN = "e2e-access-token-redacted"
USER_EMAIL = "student50@campus.edu"
USER_PASSWORD = "[REDACTED]"
CREATED_AT = datetime(2026, 9, 1, tzinfo=timezone.utc)


def user_summary() -> UserSummary:
    return UserSummary(
        id=USER_ID,
        email=USER_EMAIL,
        role="student",
        status="active",
        pqc_mode=False,
        created_at=CREATED_AT,
    )


class LoginService:
    session_service = None

    def __init__(self) -> None:
        self.failures: dict[str, int] = {}

    def login(self, email: str, password: str, now: datetime) -> AuthSession:
        del now
        if email == USER_EMAIL and password == USER_PASSWORD:
            self.failures.pop(email, None)
            return AuthSession(access_token=ACCESS_TOKEN, user=user_summary())
        count = self.failures.get(email, 0) + 1
        self.failures[email] = count
        raise LoginError("RATE_LIMITED" if count >= 5 else "INVALID_CREDENTIALS")


class KeyringService:
    def summary(self, user_id: str, now: datetime) -> KeyringSummary:
        del user_id, now
        return KeyringSummary(
            items=[
                KeyringItem(
                    kind="sm2_identity",
                    algorithm="SM2",
                    fingerprint="12:34:…:50",
                    status="active",
                    expires_at=datetime(2027, 9, 1, tzinfo=timezone.utc),
                )
            ],
            unlocked_until=None,
        )


class SessionService:
    def list_for_user(self, user_id: str, current_session_id: str | None = None):
        del user_id, current_session_id
        return [
            DeviceSession(
                id="e2e-session-50",
                device="Desktop Chrome",
                ip_masked="127.0.*.*",
                last_active_at=datetime.now(timezone.utc),
                current=True,
            )
        ]


class QuotaService:
    def get(self, user_id: str, now: datetime):
        del user_id, now
        return [Quota(resource="drop", used=1, limit=10)]

    def resets_at(self, now: datetime) -> datetime:
        return now + timedelta(days=1)


login_service = LoginService()
crypto_engine = MockCryptoEngine(
    status=ProviderStatus(
        state="online",
        version="e2e-controlled-provider",
        provider="e2e",
        capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
    )
)


def authenticated_user(authorization: str | None = Header(default=None, alias="Authorization")):
    if authorization != f"Bearer {ACCESS_TOKEN}":
        raise ApiError(401, "UNAUTHORIZED", "未授权")
    return CurrentUser(USER_ID, "student", "active", "e2e-session-50")


app = create_app()
app.dependency_overrides[get_crypto_engine] = lambda: crypto_engine
app.dependency_overrides[get_login_service] = lambda: login_service
app.dependency_overrides[require_authenticated_user] = authenticated_user
app.dependency_overrides[get_keyring_service] = lambda: KeyringService()
app.dependency_overrides[get_session_service] = lambda: SessionService()
app.dependency_overrides[get_me_quota_service] = lambda: QuotaService()
