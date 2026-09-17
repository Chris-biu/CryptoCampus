import logging
import pytest
from fastapi.testclient import TestClient

from app.api.routes.system import get_crypto_engine
from app.crypto.mock import MockCryptoEngine
from app.crypto.types import ProviderStatus
from app.db.session import get_db
from app.main import create_app
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user


def test_reload_response_contains_no_sensitive_paths_or_secrets(db_session, caplog) -> None:
    admin = User(id="admin-sec-1", email="admin_sec@campus.edu", role="admin")
    db_session.add(admin)
    db_session.commit()

    engine = MockCryptoEngine(
        status=ProviderStatus(
            state="online",
            version="v1",
            provider="sensitive_mock_internal_path_/usr/local/lib/secret.so",
            capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
        )
    )
    engine.set_result("sm3_digest", b"\x99" * 32)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        admin.id, "admin", "active"
    )
    app.dependency_overrides[get_crypto_engine] = lambda: engine
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/api/v1/admin/providers/reload",
            headers={"Idempotency-Key": "security-key-000001"},
        )

    assert response.status_code == 200
    text = response.text.lower()
    # The response schema strictly forbids extra fields and only includes:
    # api, engine, version, tlcp, providers
    assert "secret.so" not in text
    assert "/usr/local" not in text
    assert "password" not in text

    # Also verify logs do not leak sensitive values
    log_text = caplog.text.lower()
    assert "security-key-000001" not in log_text


def test_engine_details_response_contains_no_sensitive_paths(db_session, caplog) -> None:
    admin = User(id="admin-sec-2", email="admin_sec2@campus.edu", role="admin")
    db_session.add(admin)
    db_session.commit()

    engine = MockCryptoEngine(
        status=ProviderStatus(
            state="online",
            version="v1",
            provider="internal_openhitls_library_c_program_files",
            capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
        )
    )
    engine.set_result("sm3_digest", b"\x88" * 32)

    app = create_app()
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        admin.id, "admin", "active"
    )
    app.dependency_overrides[get_crypto_engine] = lambda: engine
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    with caplog.at_level(logging.DEBUG):
        response = client.get("/api/v1/admin/engine")

    assert response.status_code == 200
    text = response.text.lower()
    assert "c_program_files" not in text
    assert "openhitls" not in text
