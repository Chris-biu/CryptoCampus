"""Service integration fixtures using real openHiTLS and ephemeral identities."""

import ctypes
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.api.routes.auth import _RegistrationJwtTokenIssuer
from app.crypto.hitls import HitlsCryptoEngine, _bridge, _raise_for
from app.db.session import create_db_engine, create_session_factory, init_database
from app.models.user import User
from app.pki.service import PlatformCAService
from app.pki.types import PlatformCAMaterial
from app.security.key_cache import PrivateKeyUnlockCache
from app.security.tokens import PyJwtTokenCodec
from app.services.login import LoginService
from app.services.registration import RegistrationService
from app.services.sessions import SessionService
from app.services.verification_code import InMemoryVerificationCodeStore


class EphemeralCA:
    """Test-only root bootstrap through the bridge's existing self-sign API."""

    def __init__(self, crypto, now):
        keypair = crypto.sm2_generate_keypair()
        user_id = str(uuid4())
        csr_der = crypto.csr_create(
            keypair.private_key, keypair.public_key, user_id, "system"
        )
        csr, key = _bridge.ro(csr_der), _bridge.ro(keypair.private_key)
        cert, serial = _bridge.allocate(16384), _bridge.allocate(16)
        start, end = int(now.timestamp()) - 3600, int(now.timestamp()) + 730 * 86400
        _raise_for(
            crypto._lib.cc_bridge_cert_sign(
                csr.struct.data,
                len(csr_der),
                None,
                0,
                key.struct.data,
                32,
                start,
                end,
                0x0004 | 0x0002,
                ctypes.byref(cert.struct),
                ctypes.byref(serial.struct),
            )
        )
        self.material = PlatformCAMaterial(
            user_id,
            serial.data.hex(),
            cert.data,
            start,
            end,
            keypair.private_key,
        )

    @contextmanager
    def unlocked(self):
        yield self.material


class BusinessRuntime:
    def __init__(self, session, crypto, ca, now):
        self.session, self.crypto, self.ca, self.now = session, crypto, ca, now
        self.cache = PrivateKeyUnlockCache()
        self.codec = PyJwtTokenCodec(secrets.token_bytes(32))
        self.codes = InMemoryVerificationCodeStore(crypto)
        self.registration = RegistrationService(
            session,
            crypto,
            ca,
            self.codes,
            _RegistrationJwtTokenIssuer(self.codec),
        )
        self.login = LoginService(
            session,
            crypto,
            self.codec,
            self.cache,
            SessionService(session, crypto),
        )

    def register(self, name, password=None):
        email = f"{name}@campus.edu"
        password = password or "Qa9!" + secrets.token_urlsafe(24)
        code = f"{secrets.randbelow(1_000_000):06d}"
        self.codes.issue(email, code, self.now + timedelta(minutes=10))
        result = self.registration.register(email, password, code)
        self.session.commit()
        # Registration signs at its own current time; later operations must not
        # verify the new certificate at the earlier fixture-creation instant.
        self.now = datetime.now(timezone.utc)
        return self.session.get(User, result.user["id"]), password

    def unlock(self, user, password):
        result = self.login.login(
            user.email, password, self.now, "regression", "127.0.0.1"
        )
        self.session.commit()
        return result


@contextmanager
def isolated_runtime(tmp_path):
    crypto = HitlsCryptoEngine()  # Missing real library is a failure, never a skip.
    now = datetime.now(timezone.utc)
    database = create_db_engine(f"sqlite+pysqlite:///{tmp_path / 'business.db'}")
    init_database(database)
    try:
        with create_session_factory(database)() as session:
            provider = EphemeralCA(crypto, now)
            material = provider.material
            session.add(
                User(
                    id=material.system_user_id,
                    role="system",
                    status="active",
                    cert_serial=material.certificate_serial,
                )
            )
            session.commit()
            ca = PlatformCAService(session, crypto, provider)
            ca.register_platform_ca(now)
            session.commit()
            yield BusinessRuntime(session, crypto, ca, now)
    finally:
        database.dispose()
