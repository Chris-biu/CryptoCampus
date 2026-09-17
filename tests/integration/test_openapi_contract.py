from collections import Counter

from jsonschema import Draft202012Validator
from openapi_spec_validator import validate

from app.api.routes.not_implemented import NOT_IMPLEMENTED_OPERATIONS


HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


def operations(document: dict):
    for path, path_item in document["paths"].items():
        for method, operation in path_item.items():
            if method in HTTP_METHODS:
                yield method.upper(), path, operation


def validate_payload(document: dict, schema_name: str, payload: dict) -> None:
    schema = document["components"]["schemas"][schema_name]
    Draft202012Validator(schema).validate(payload)


def test_canonical_openapi_is_valid_and_has_unique_operation_ids(canonical_openapi) -> None:
    validate(canonical_openapi)
    operation_ids = [item[2]["operationId"] for item in operations(canonical_openapi)]
    duplicates = [name for name, count in Counter(operation_ids).items() if count > 1]
    assert duplicates == []


def test_every_operation_declares_a_supported_permission_contract(canonical_openapi) -> None:
    supported = {"guest", "student", "admin", "teacher"}
    for method, path, operation in operations(canonical_openapi):
        roles = operation.get("x-required-roles")
        assert isinstance(roles, list) and roles, f"{method} {path} lacks x-required-roles"
        assert set(roles) <= supported, f"{method} {path} has unsupported roles"
        if "guest" in roles:
            assert operation.get("x-jwt") is False


def test_runtime_routes_and_unimplemented_registry_cover_the_contract(app, canonical_openapi) -> None:
    contract = {(method, path) for method, path, _ in operations(canonical_openapi)}
    implemented = {
        (method, path.removeprefix("/api/v1"))
        for method, path, _ in operations(app.openapi())
        if path.startswith("/api/v1")
    }
    placeholders = {(method, path) for method, path, _ in NOT_IMPLEMENTED_OPERATIONS}

    assert implemented | placeholders == contract
    assert implemented.isdisjoint(placeholders)
    assert placeholders <= contract
    assert len(placeholders) == len(NOT_IMPLEMENTED_OPERATIONS)


def test_public_system_status_matches_the_canonical_response(client, canonical_openapi) -> None:
    response = client.get("/api/v1/system/status")

    assert response.status_code == 200
    validate_payload(canonical_openapi, "SystemStatus", response.json())


def test_validation_errors_match_the_canonical_error_shape(client, canonical_openapi) -> None:
    response = client.post("/api/v1/auth/register", json={})

    assert response.status_code == 422
    validate_payload(canonical_openapi, "Error", response.json())
    assert response.json()["code"] == "VALIDATION_ERROR"
    assert set(response.json()) == {"code", "message", "request_id", "details"}
