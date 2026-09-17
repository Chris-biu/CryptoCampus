"""Opt-in local browser harness: production services and real openHiTLS.

Never use this module as a production entry point. It seeds disposable users
and replaces only deployment-owned material/storage dependencies.
"""

import os
import secrets
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

if os.getenv("CC_RUN_REAL_E2E") != "1":
    raise RuntimeError("real E2E harness must be explicitly enabled")
password = os.environ["CC_REAL_E2E_PASSWORD"]
os.environ["CRYPTOCAMPUS_CAMPUS_EMAIL_DOMAINS"] = "campus.edu"
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "real_crypto"))

from harness import isolated_runtime  # noqa: E402
from fastapi import Depends  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from app.api.routes.auth import get_access_token_issuer, get_private_key_cache  # noqa: E402
from app.api.routes.drops import get_drop_service  # noqa: E402
from app.api.routes.seals import get_platform_ca_service  # noqa: E402
from app.db.session import create_session_factory, get_db  # noqa: E402
from app.main import create_app  # noqa: E402
from app.pki.service import PlatformCAService  # noqa: E402
from app.security.auth_dependencies import get_token_verifier  # noqa: E402
from app.services.drop import DropService  # noqa: E402
from app.services.quota import QuotaService  # noqa: E402
from app.services.recipient_resolver import ConfiguredRecipientKeyResolver  # noqa: E402

temporary = TemporaryDirectory(prefix="cryptocampus-real-e2e-")
scope = isolated_runtime(Path(temporary.name))
runtime = scope.__enter__()
runtime.register("desktop", password)
recipient, recipient_password = runtime.register("recipient")
runtime.unlock(recipient, recipient_password)
recipient_id = recipient.id
recipient_fingerprint = runtime.crypto.sm3_digest(recipient.pubkey)
password = recipient_password = None
session_factory = create_session_factory(runtime.session.get_bind())


class UnlockedRecipient:
    def get_unlocked_private_key(self, *, recipient_user_id, key_fingerprint, now):
        if recipient_user_id != recipient_id or not secrets.compare_digest(
            key_fingerprint,
            recipient_fingerprint,
        ):
            return None
        return runtime.cache.get(recipient_id, now)


def database():
    with session_factory() as session:
        yield session


def ca_service(session: Session = Depends(get_db)):
    return PlatformCAService(session, runtime.crypto, runtime.ca.material_provider)


def drops(session: Session = Depends(get_db)):
    return DropService(
        session,
        runtime.crypto,
        runtime.cache,
        QuotaService(session, runtime.crypto.sm3_digest),
        ConfiguredRecipientKeyResolver(recipient_id, runtime.crypto),
        UnlockedRecipient(),
        PlatformCAService(session, runtime.crypto, runtime.ca.material_provider),
    )


@asynccontextmanager
async def lifespan(app):
    try:
        yield
    finally:
        scope.__exit__(None, None, None)
        temporary.cleanup()


app = create_app()
app.router.lifespan_context = lifespan
app.dependency_overrides[get_db] = database
app.dependency_overrides[get_token_verifier] = lambda: runtime.codec
app.dependency_overrides[get_access_token_issuer] = lambda: runtime.codec
app.dependency_overrides[get_private_key_cache] = lambda: runtime.cache
app.dependency_overrides[get_drop_service] = drops
app.dependency_overrides[get_platform_ca_service] = ca_service
