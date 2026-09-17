import re

import pytest

from app.api.routes.not_implemented import NOT_IMPLEMENTED_OPERATIONS
from app.security.auth_dependencies import (
    CurrentUser,
    get_token_verifier,
    require_authenticated_user,
)

from test_openapi_contract import validate_payload


def concrete_path(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "00000000-0000-4000-8000-000000000001", path)


def assert_safe_error(document: dict, response, status: int, code: str) -> None:
    assert response.status_code == status
    validate_payload(document, "Error", response.json())
    assert response.json()["code"] == code
    lowered = response.text.lower()
    assert "password" not in lowered
    assert "refresh_token" not in lowered
    assert "private_key" not in lowered


@pytest.mark.parametrize(
    ("method", "path", "roles"),
    [item for item in NOT_IMPLEMENTED_OPERATIONS if "guest" in item[2]],
)
def test_public_unimplemented_operations_return_explicit_501(
    client, canonical_openapi, method, path, roles
) -> None:
    del roles
    response = client.request(method, f"/api/v1{concrete_path(path)}")

    assert_safe_error(canonical_openapi, response, 501, "NOT_IMPLEMENTED")


@pytest.mark.parametrize(
    ("method", "path", "roles"),
    [item for item in NOT_IMPLEMENTED_OPERATIONS if "guest" not in item[2]],
)
def test_protected_unimplemented_operations_reject_missing_token_before_501(
    client, canonical_openapi, method, path, roles
) -> None:
    del roles
    response = client.request(method, f"/api/v1{concrete_path(path)}")

    assert_safe_error(canonical_openapi, response, 401, "UNAUTHORIZED")


class ExpiredVerifier:
    def verify_access_token(self, token, now):
        del token, now
        raise ValueError("expired token details must stay private")


def test_expired_token_is_401_and_does_not_leak_verifier_details(app, canonical_openapi) -> None:
    from fastapi.testclient import TestClient

    app.dependency_overrides[get_token_verifier] = ExpiredVerifier
    response = TestClient(app, raise_server_exceptions=False).get(
        "/api/v1/me", headers={"Authorization": "Bearer expired-secret"}
    )

    assert_safe_error(canonical_openapi, response, 401, "UNAUTHORIZED")
    assert "expired-secret" not in response.text
    assert "expired token details" not in response.text


@pytest.mark.parametrize(
    ("role", "expected_status", "expected_code"),
    [
        ("student", 403, "FORBIDDEN"),
        ("admin", 200, None),
        ("teacher", 200, None),
    ],
)
def test_admin_permission_matrix(app, canonical_openapi, role, expected_status, expected_code) -> None:
    from fastapi.testclient import TestClient

    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        "00000000-0000-4000-8000-000000000001", role, "active"
    )

    if expected_status == 200:
        from app.api.routes.system import get_crypto_engine
        from app.crypto.mock import MockCryptoEngine
        from app.crypto.types import ProviderStatus
        from app.db.session import get_db

        engine = MockCryptoEngine(
            status=ProviderStatus(
                state="online",
                version="integration-test",
                provider="mock",
                capabilities={"sm2": True, "sm3": True, "sm4_gcm": True},
            )
        )
        engine.set_result("sm3_digest", b"\x01" * 32)

        class NoOpSession:
            def add(self, value) -> None:
                del value

            def commit(self) -> None:
                return None

        app.dependency_overrides[get_crypto_engine] = lambda: engine
        app.dependency_overrides[get_db] = NoOpSession

    response = TestClient(app, raise_server_exceptions=False).get("/api/v1/admin/engine")

    if expected_status == 200:
        assert response.status_code == 200
        validate_payload(canonical_openapi, "SystemStatus", response.json())
    else:
        assert_safe_error(canonical_openapi, response, expected_status, expected_code)


@pytest.mark.parametrize("role", ["student", "admin", "teacher"])
def test_personal_permission_matrix_allows_supported_roles_to_read_profile(
    app, role
) -> None:
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    from app.db.session import get_db

    user_id = "00000000-0000-4000-8000-000000000001"
    app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id, role, "active"
    )

    class ProfileSession:
        def get(self, model, key):
            del model
            assert key == user_id
            return SimpleNamespace(
                id=user_id,
                email="profile@campus.edu",
                role=role,
                status="active",
                pqc_pubkey=None,
                enc_pqc_sk=None,
                created_at=datetime.now(timezone.utc),
            )

    app.dependency_overrides[get_db] = ProfileSession
    response = TestClient(app, raise_server_exceptions=False).get("/api/v1/me")

    assert response.status_code == 200
    assert set(response.json()) == {
        "id", "email", "role", "status", "pqc_mode", "created_at"
    }
    assert response.json()["role"] == role


def test_unknown_api_path_remains_404(client) -> None:
    assert client.get("/api/v1/not-in-contract").status_code == 404
