import json
import uuid
import pytest
from fastapi.testclient import TestClient

from app.db.session import get_db
from app.models.inspect import InspectRecordEntity, InspectStepEntity
from app.models.user import User
from app.security.auth_dependencies import CurrentUser, require_authenticated_user


@pytest.fixture
def student_user(db_session):
    student = User(
        id=str(uuid.uuid4()),
        email="student_inspect_test@example.com",
        role="student",
        status="active",
        auth_hash=b"00" * 16,
        salt_a=b"00" * 16,
        salt_k=b"11" * 16,
    )
    db_session.add(student)
    db_session.commit()
    return student


@pytest.fixture
def other_student_user(db_session):
    other = User(
        id=str(uuid.uuid4()),
        email="other_student_test@example.com",
        role="student",
        status="active",
        auth_hash=b"22" * 16,
        salt_a=b"22" * 16,
        salt_k=b"33" * 16,
    )
    db_session.add(other)
    db_session.commit()
    return other


def test_inspect_records_requires_auth(client: TestClient):
    res = client.get("/api/v1/inspect/records")
    assert res.status_code == 401


def test_list_and_get_inspect_records(client: TestClient, db_session, student_user, other_student_user):
    my_user_id = student_user.id
    other_user_id = other_student_user.id

    # Create one record for me
    my_record_id = str(uuid.uuid4())
    my_record = InspectRecordEntity(
        id=my_record_id,
        owner_user_id=my_user_id,
        owner="self",
        operation="drop.envelope.create",
        status="passed",
        schema_version=1,
    )
    db_session.add(my_record)
    my_step = InspectStepEntity(
        record_id=my_record_id,
        order=1,
        name="封包",
        algorithm="SM4-GCM",
        result="passed",
        redacted_values_json=json.dumps({"content_bytes": 100, "pqc_mode": False, "digest_prefix": "0123456789abcdef", "recipient_cert_fingerprint": "cert123"}),
    )
    db_session.add(my_step)

    # Create one record for other
    other_record_id = str(uuid.uuid4())
    other_record = InspectRecordEntity(
        id=other_record_id,
        owner_user_id=other_user_id,
        owner="self",
        operation="drop.envelope.create",
        status="passed",
        schema_version=1,
    )
    db_session.add(other_record)
    db_session.commit()

    # Authenticate as student_user and route db to test db_session
    client.app.dependency_overrides[get_db] = lambda: db_session
    client.app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=my_user_id, role="student", status="active"
    )

    try:
        # 1. List my records
        res = client.get("/api/v1/inspect/records")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["id"] == my_record_id
        assert data["items"][0]["owner"] == "self"
        assert len(data["items"][0]["steps"]) == 1

        # 2. Get my record
        res_get = client.get(f"/api/v1/inspect/records/{my_record_id}")
        assert res_get.status_code == 200
        assert res_get.json()["id"] == my_record_id

        # 3. IDOR: Get other's record with my auth -> 403
        res_forbidden = client.get(f"/api/v1/inspect/records/{other_record_id}")
        assert res_forbidden.status_code == 403

        # 4. Get non-existent record -> 404
        res_not_found = client.get(f"/api/v1/inspect/records/{uuid.uuid4()}")
        assert res_not_found.status_code == 404
    finally:
        client.app.dependency_overrides.pop(require_authenticated_user, None)
        client.app.dependency_overrides.pop(get_db, None)


def test_export_inspect_report(client: TestClient, db_session, student_user, other_student_user):
    my_user_id = student_user.id
    other_user_id = other_student_user.id

    my_record_id = str(uuid.uuid4())
    my_record = InspectRecordEntity(
        id=my_record_id,
        owner_user_id=my_user_id,
        owner="self",
        operation="drop.envelope.create",
        status="passed",
        schema_version=1,
    )
    db_session.add(my_record)
    my_step = InspectStepEntity(
        record_id=my_record_id,
        order=1,
        name="封包",
        algorithm="SM4-GCM",
        result="passed",
        redacted_values_json=json.dumps({"content_bytes": 100, "pqc_mode": False, "digest_prefix": "0123456789abcdef", "recipient_cert_fingerprint": "cert123"}),
    )
    db_session.add(my_step)
    db_session.commit()

    # Success export as owner
    client.app.dependency_overrides[get_db] = lambda: db_session
    client.app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=my_user_id, role="student", status="active"
    )
    try:
        res = client.get(f"/api/v1/inspect/records/{my_record_id}/report")
        assert res.status_code == 200
        assert "text/markdown" in res.headers["content-type"]
        assert f'filename="{my_record_id}.md"' in res.headers["content-disposition"]
        assert "# CryptoCampus 密码透视实验记录" in res.text
        assert "## 安全边界" in res.text

        # IDOR check as other user
        client.app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
            user_id=other_user_id, role="student", status="active"
        )
        res_forbidden = client.get(f"/api/v1/inspect/records/{my_record_id}/report")
        assert res_forbidden.status_code == 403
    finally:
        client.app.dependency_overrides.pop(require_authenticated_user, None)
        client.app.dependency_overrides.pop(get_db, None)


def test_run_experiments_endpoint(client: TestClient, student_user):
    client.app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=student_user.id, role="student", status="active"
    )
    try:
        # Run SM2 curve experiment
        res = client.post(
            "/api/v1/inspect/experiments",
            json={"experiment": "sm2_curve", "input": "sm2p256v1"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["experiment"] == "sm2_curve"
        assert data["passed"] is True
        assert "p" in data["redacted_values"]

        # Invalid experiment input -> 400
        res_bad = client.post(
            "/api/v1/inspect/experiments",
            json={"experiment": "sm2_curve", "input": "secp256k1"},
        )
        assert res_bad.status_code == 400
    finally:
        client.app.dependency_overrides.pop(require_authenticated_user, None)


def test_tlcp_handshake_endpoint_503_when_unavailable(client: TestClient, student_user):
    client.app.dependency_overrides[require_authenticated_user] = lambda: CurrentUser(
        user_id=student_user.id, role="student", status="active"
    )
    try:
        res = client.get("/api/v1/inspect/tlcp/handshake")
        assert res.status_code == 503
        assert res.json()["code"] == "PROVIDER_UNAVAILABLE"
    finally:
        client.app.dependency_overrides.pop(require_authenticated_user, None)
