from __future__ import annotations

from datetime import datetime, timezone
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.routes.auth import get_crypto_engine
from app.api.routes.me import get_platform_ca_service
from app.crypto.mock import MockCryptoEngine
from app.db.session import get_db
from app.main import create_app
from app.models.certificate import CertificateRecord
from app.models.user import User
from app.pki.types import CertificateVerification
from app.security.auth_dependencies import CurrentUser, require_authenticated_user


def _user(db_session, *, pqc_enabled: bool) -> User:
    user = User(
        id=str(uuid.uuid4()),
        email=f"me-{uuid.uuid4().hex[:8]}@campus.edu",
        role="student",
        status="active",
        salt_a=b"secret-salt-a",
        auth_hash=b"secret-auth-hash",
        salt_k=b"secret-salt-k",
        enc_sk=b"secret-encrypted-private-key",
        pubkey=b"public-key",
        cert_serial=f"cert-{uuid.uuid4().hex}",
        pqc_pubkey=b"pqc-public-key" if pqc_enabled else None,
        enc_pqc_sk=b"secret-pqc-private-key" if pqc_enabled else None,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.mark.parametrize("pqc_enabled", [False, True])
def test_get_me_returns_only_public_profile(db_session, pqc_enabled: bool) -> None:
    user = _user(db_session, pqc_enabled=pqc_enabled)
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user.id, user.role, user.status
    )
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: MockCryptoEngine()

    response = TestClient(app).get("/api/v1/me")

    assert response.status_code == 200
    assert response.json() == {
        "id": user.id,
        "email": user.email,
        "role": "student",
        "status": "active",
        "pqc_mode": pqc_enabled,
        "created_at": user.created_at.isoformat().replace("+00:00", "Z"),
    }
    serialized = response.text
    for secret in (
        "salt_a",
        "auth_hash",
        "salt_k",
        "enc_sk",
        "enc_pqc_sk",
        "cert_serial",
    ):
        assert secret not in serialized


def test_get_me_rejects_missing_database_user(db_session) -> None:
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        str(uuid.uuid4()), "student", "active"
    )
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_crypto_engine] = lambda: MockCryptoEngine()

    response = TestClient(app).get("/api/v1/me")

    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


def test_verify_own_certificate_uses_platform_ca_and_returns_public_result(db_session) -> None:
    user = _user(db_session, pqc_enabled=False)
    now = datetime.now(timezone.utc)
    certificate = CertificateRecord(
        serial=user.cert_serial,
        subject_user_id=user.id,
        issuer_serial="platform-ca",
        kind="user_identity",
        certificate_der=b"real-certificate-der",
        key_usage="digitalSignature,keyEncipherment,keyAgreement",
        not_before=now.replace(year=now.year - 1),
        not_after=now.replace(year=now.year + 1),
        status="active",
    )
    db_session.add(certificate)
    db_session.commit()

    class FakePlatformCA:
        def verify_certificate(self, certificate_der, verification_time, required_key_usage):
            assert certificate_der == b"real-certificate-der"
            assert required_key_usage == ("digitalSignature", "keyEncipherment", "keyAgreement")
            return CertificateVerification(True, "active", user.cert_serial)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user.id, user.role, user.status
    )
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_platform_ca_service] = FakePlatformCA

    response = TestClient(app).get("/api/v1/me/certificate/verify")

    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert response.json()["state"] == "active"
    assert response.json()["serial"] == user.cert_serial
    assert "verified_at" in response.json()


def test_verify_own_certificate_reports_missing_certificate(db_session) -> None:
    user = _user(db_session, pqc_enabled=False)
    user.cert_serial = None
    db_session.commit()
    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user.id, user.role, user.status
    )
    app.dependency_overrides[get_db] = lambda: db_session

    response = TestClient(app).get("/api/v1/me/certificate/verify")

    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert response.json()["state"] == "invalid"
    assert response.json()["serial"] is None
