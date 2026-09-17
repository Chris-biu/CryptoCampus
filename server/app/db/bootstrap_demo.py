"""Create a complete, real-crypto local demonstration environment.

This command is deliberately opt-in and refuses to run in production.  It
creates deployment-owned key material outside Git, a self-signed platform CA,
certificate-backed demo identities and the service identities needed by drops,
seals and vote settlement.  All cryptographic operations use HitlsCryptoEngine;
there is no mock or fabricated success path.
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping
from uuid import UUID

from sqlalchemy.orm import Session

from app.crypto.hitls import HitlsCryptoEngine
from app.crypto.types import SM4_KEY_SIZE
from app.db.session import SessionLocal, engine as database_engine, init_database
from app.models.user import User
from app.models.vote import VoteScopeMember, VoteScopeUnit
from app.pki.material import FilePlatformCAMaterialProvider
from app.pki.service import PlatformCAService

DEMO_CLASS_ID = "10000000-0000-4000-8000-000000000001"
DEMO_GROUP_ID = "20000000-0000-4000-8000-000000000001"
DEMO_SYSTEM_USER_ID = "30000000-0000-4000-8000-000000000001"
DEMO_STUDENT_USER_ID = "30000000-0000-4000-8000-000000000002"
DEMO_ADMIN_USER_ID = "30000000-0000-4000-8000-000000000003"
DEMO_TEACHER_USER_ID = "30000000-0000-4000-8000-000000000004"
DEMO_RECIPIENT_USER_ID = "30000000-0000-4000-8000-000000000005"
DEMO_DEPARTMENT_USER_ID = "30000000-0000-4000-8000-000000000006"
DEMO_ACADEMIC_USER_ID = "30000000-0000-4000-8000-000000000007"
DEMO_TALLY_USER_ID = "30000000-0000-4000-8000-000000000008"

DEMO_SCOPES = (
    (DEMO_CLASS_ID, "class", "演示班级：软件工程 2301"),
    (DEMO_GROUP_ID, "group", "演示群组：密码学兴趣小组"),
)


def require_demo_bootstrap_allowed(environ: Mapping[str, str]) -> None:
    environment = environ.get("CRYPTOCAMPUS_ENV", "").strip().lower()
    if environment in {"prod", "production"}:
        raise RuntimeError("生产环境禁止初始化演示身份与密钥")
    if environ.get("CRYPTOCAMPUS_ALLOW_DEMO_BOOTSTRAP") != "1":
        raise RuntimeError("必须显式设置 CRYPTOCAMPUS_ALLOW_DEMO_BOOTSTRAP=1")
    required = (
        "CRYPTOCAMPUS_DEMO_STUDENT_PASSWORD",
        "CRYPTOCAMPUS_DEMO_ADMIN_PASSWORD",
        "CRYPTOCAMPUS_DEMO_TEACHER_PASSWORD",
        "CRYPTOCAMPUS_DEMO_RECIPIENT_PASSWORD",
    )
    if any(not environ.get(name) for name in required):
        raise RuntimeError("必须通过环境变量提供全部演示账号口令")


def _write_secret(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(payload)
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(path)


def _write_json_secret(path: Path, payload: dict[str, object]) -> None:
    _write_secret(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8"),
    )


def _ca_provider(secrets_dir: Path) -> FilePlatformCAMaterialProvider:
    return FilePlatformCAMaterialProvider(
        secrets_dir / "platform_ca.json",
        secrets_dir / "platform_ca.der",
        secrets_dir / "platform_ca.key",
    )


def _ensure_platform_ca(
    session: Session,
    crypto: HitlsCryptoEngine,
    secrets_dir: Path,
    now: datetime,
) -> PlatformCAService:
    manifest_path = secrets_dir / "platform_ca.json"
    cert_path = secrets_dir / "platform_ca.der"
    key_path = secrets_dir / "platform_ca.key"
    if not (manifest_path.is_file() and cert_path.is_file() and key_path.is_file()):
        pair = crypto.sm2_generate_keypair()
        not_before = int((now - timedelta(minutes=5)).timestamp())
        not_after = int((now + timedelta(days=3650)).timestamp())
        csr = crypto.csr_create(
            pair.private_key,
            pair.public_key,
            DEMO_SYSTEM_USER_ID,
            "system",
        )
        certificate = crypto.cert_sign(
            csr,
            b"",
            pair.private_key,
            not_before,
            not_after,
            ("keyCertSign", "cRLSign"),
        )
        _write_secret(key_path, pair.private_key)
        _write_secret(cert_path, certificate.der)
        _write_json_secret(
            manifest_path,
            {
                "system_user_id": DEMO_SYSTEM_USER_ID,
                "certificate_serial": certificate.serial,
                "not_before": not_before,
                "not_after": not_after,
            },
        )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    system_user = session.get(User, DEMO_SYSTEM_USER_ID)
    if system_user is None:
        session.add(
            User(
                id=DEMO_SYSTEM_USER_ID,
                role="system",
                status="active",
                cert_serial=manifest["certificate_serial"],
            )
        )
    else:
        system_user.role = "system"
        system_user.status = "active"
        system_user.cert_serial = manifest["certificate_serial"]
    session.flush()

    service = PlatformCAService(session, crypto, _ca_provider(secrets_dir))
    service.register_platform_ca(now)
    session.commit()
    return service


def _create_or_refresh_identity(
    session: Session,
    crypto: HitlsCryptoEngine,
    ca: PlatformCAService,
    *,
    user_id: str,
    email: str | None,
    role: str,
    password: str | None,
    now: datetime,
) -> tuple[User, bytes, bytes, bytes]:
    UUID(user_id)
    user = session.get(User, user_id)
    if user is None and email:
        user = session.query(User).filter(User.email == email).one_or_none()
    if user is None:
        user = User(id=user_id)
        session.add(user)
    actual_user_id = user.id
    pair = crypto.sm2_generate_keypair()
    issued = ca.issue_user_certificate(
        actual_user_id,
        role,
        pair.private_key,
        pair.public_key,
        now - timedelta(minutes=1),
        now + timedelta(days=365),
    )
    user.email = email
    user.role = role
    user.status = "active"
    user.failed_login_count = 0
    user.locked_until = None
    user.pubkey = pair.public_key
    user.cert_serial = issued.certificate.serial
    if password is not None:
        password_bytes = password.encode("utf-8")
        salt_a = secrets.token_bytes(32)
        salt_k = secrets.token_bytes(32)
        kek = crypto.hkdf_sm3(password_bytes, salt_k, b"user-kek", SM4_KEY_SIZE)
        encrypted = crypto.sm4_gcm_encrypt(kek, pair.private_key)
        user.salt_a = salt_a
        user.auth_hash = crypto.sm3_hash_password(password_bytes, salt_a)
        user.salt_k = salt_k
        user.enc_sk = b"v1" + encrypted.nonce + encrypted.ciphertext + encrypted.tag
    session.flush()
    ca.record_issued_certificate(user, issued)
    session.flush()
    return user, pair.private_key, pair.public_key, issued.certificate.der


def bootstrap_demo(
    session: Session,
    crypto: HitlsCryptoEngine,
    secrets_dir: Path,
    environ: Mapping[str, str],
) -> dict[str, object]:
    require_demo_bootstrap_allowed(environ)
    now = datetime.now(timezone.utc)
    secrets_dir.mkdir(parents=True, exist_ok=True)
    ca = _ensure_platform_ca(session, crypto, secrets_dir, now)

    login_identities = (
        (
            DEMO_STUDENT_USER_ID,
            "student01@campus.edu",
            "student",
            environ["CRYPTOCAMPUS_DEMO_STUDENT_PASSWORD"],
        ),
        (
            DEMO_ADMIN_USER_ID,
            "admin01@campus.edu",
            "admin",
            environ["CRYPTOCAMPUS_DEMO_ADMIN_PASSWORD"],
        ),
        (
            DEMO_TEACHER_USER_ID,
            "teacher01@campus.edu",
            "teacher",
            environ["CRYPTOCAMPUS_DEMO_TEACHER_PASSWORD"],
        ),
        (
            DEMO_RECIPIENT_USER_ID,
            "recipient01@campus.edu",
            "teacher",
            environ["CRYPTOCAMPUS_DEMO_RECIPIENT_PASSWORD"],
        ),
    )
    material: dict[str, tuple[User, bytes, bytes, bytes]] = {}
    for user_id, email, role, password in login_identities:
        material[user_id] = _create_or_refresh_identity(
            session,
            crypto,
            ca,
            user_id=user_id,
            email=email,
            role=role,
            password=password,
            now=now,
        )

    recipient = material[DEMO_RECIPIENT_USER_ID]
    _write_secret(secrets_dir / "drop_recipient_sm2.key", recipient[1])

    for user_id, role, profile in (
        (DEMO_DEPARTMENT_USER_ID, "admin", "department"),
        (DEMO_ACADEMIC_USER_ID, "teacher", "academic"),
    ):
        identity = _create_or_refresh_identity(
            session,
            crypto,
            ca,
            user_id=user_id,
            email=None,
            role=role,
            password=None,
            now=now,
        )
        base = secrets_dir / "seal_materials"
        _write_json_secret(base / f"{profile}.json", {"user_id": identity[0].id})
        _write_secret(base / f"{profile}.der", identity[3])
        _write_secret(base / f"{profile}.key", identity[1])

    tally = _create_or_refresh_identity(
        session,
        crypto,
        ca,
        user_id=DEMO_TALLY_USER_ID,
        email=None,
        role="system",
        password=None,
        now=now,
    )
    tally_base = secrets_dir / "vote_tally"
    _write_json_secret(
        tally_base / "tally.json",
        {
            "system_user_id": tally[0].id,
            "certificate_serial": tally[0].cert_serial,
        },
    )
    _write_secret(tally_base / "tally.der", tally[3])
    _write_secret(tally_base / "tally.pub", tally[2])
    _write_secret(tally_base / "tally.key", tally[1])

    signer_base = secrets_dir / "hole_signers"
    for service in ("hole_post", "hole_comment", "hole_like"):
        pair = crypto.sm2_generate_keypair()
        _write_secret(signer_base / f"{service}.sk", pair.private_key)
        _write_secret(signer_base / f"{service}.pk", pair.public_key)

    jwt_path = secrets_dir / "jwt_secret"
    if not jwt_path.is_file() or jwt_path.stat().st_size < 32:
        _write_secret(jwt_path, secrets.token_bytes(48))

    members = [
        material[DEMO_STUDENT_USER_ID][0],
        material[DEMO_TEACHER_USER_ID][0],
        material[DEMO_ADMIN_USER_ID][0],
    ]
    for scope_id, kind, name in DEMO_SCOPES:
        scope = session.get(VoteScopeUnit, scope_id)
        if scope is None:
            scope = VoteScopeUnit(id=scope_id, kind=kind, name=name, active=True)
            session.add(scope)
            session.flush()
        for user in members:
            if (
                session.query(VoteScopeMember)
                .filter_by(scope_id=scope.id, user_id=user.id)
                .one_or_none()
                is None
            ):
                session.add(VoteScopeMember(scope_id=scope.id, user_id=user.id))

    session.commit()
    summary = {
        "student_email": "student01@campus.edu",
        "admin_email": "admin01@campus.edu",
        "teacher_email": "teacher01@campus.edu",
        "recipient_email": "recipient01@campus.edu",
        "drop_recipient_user_id": material[DEMO_RECIPIENT_USER_ID][0].id,
        "class_scope_id": DEMO_CLASS_ID,
        "group_scope_id": DEMO_GROUP_ID,
    }
    _write_json_secret(secrets_dir / "demo-accounts.json", summary)
    return summary


def main() -> None:
    require_demo_bootstrap_allowed(os.environ)
    init_database(database_engine)
    secrets_dir = Path(
        os.getenv("CRYPTOCAMPUS_DEMO_SECRETS_DIR", "/run/secrets/cryptocampus")
    )
    with SessionLocal() as session:
        result = bootstrap_demo(session, HitlsCryptoEngine(), secrets_dir, os.environ)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
