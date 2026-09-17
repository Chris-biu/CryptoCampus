import secrets

import pytest

from app.models.drop import Drop
from app.services.drop import DropService, DropServiceError
from app.services.quota import QuotaService
from app.services.recipient_resolver import ConfiguredRecipientKeyResolver


class UnlockedRecipient:
    """Use only the real key that this test's recipient unlocked by logging in."""

    def __init__(self, runtime, user):
        self.runtime, self.user = runtime, user

    def get_unlocked_private_key(self, *, recipient_user_id, key_fingerprint, now):
        if recipient_user_id != self.user.id or not secrets.compare_digest(
            key_fingerprint,
            self.runtime.crypto.sm3_digest(self.user.pubkey),
        ):
            return None
        return self.runtime.cache.get(self.user.id, now)


@pytest.fixture
def drop_context(runtime):
    sender, password = runtime.register("sender")
    runtime.unlock(sender, password)
    recipient, password = runtime.register("recipient")
    runtime.unlock(recipient, password)
    service = DropService(
        session=runtime.session,
        crypto_engine=runtime.crypto,
        key_cache=runtime.cache,
        quota_service=QuotaService(runtime.session, runtime.crypto.sm3_digest),
        recipient_resolver=ConfiguredRecipientKeyResolver(recipient.id, runtime.crypto),
        recipient_provider=UnlockedRecipient(runtime, recipient),
        ca_service=runtime.ca,
    )
    return runtime, sender, service


@pytest.mark.parametrize("kind", ["text", "file"])
@pytest.mark.parametrize("ttl_policy", ["hours_24", "burn_after_read"])
def test_real_drop_roundtrip_and_burn_after_read(drop_context, kind, ttl_policy):
    runtime, sender, service = drop_context
    content = "跨层真实密码回归".encode()
    common = dict(
        sender_id=sender.id,
        ttl_policy=ttl_policy,
        pqc_mode=False,
        access_password="Drop9!" + secrets.token_urlsafe(16),
        idempotency_key=secrets.token_hex(16),
        now=runtime.now,
    )
    if kind == "text":
        created = service.create_text_drop(content=content.decode(), **common)
    else:
        created = service.create_file_drop(
            file_bytes=content, filename="proof.txt", **common
        )
    runtime.session.commit()
    record = runtime.session.get(Drop, created.id)
    assert record.ciphertext != content and record.tag and record.enc_key_sm2
    metadata, file_bytes = service.extract_drop(
        code=created.code,
        access_code=created.access_code,
        access_password=common["access_password"],
        idempotency_key=secrets.token_hex(16),
        now=runtime.now,
    )
    runtime.session.commit()
    assert metadata.signature_valid and metadata.certificate_valid
    assert (metadata.content.encode() if kind == "text" else file_bytes) == content
    if ttl_policy == "burn_after_read":
        runtime.session.refresh(record)
        assert record.ciphertext is None or not record.ciphertext
        with pytest.raises(DropServiceError) as replay:
            service.extract_drop(
                code=created.code,
                access_code=created.access_code,
                idempotency_key=secrets.token_hex(16),
                now=runtime.now,
            )
        assert replay.value.code == "not_found"


@pytest.mark.parametrize("field", ["ciphertext", "tag", "sender_signature"])
def test_real_drop_rejects_tampering_without_destroying_content(drop_context, field):
    runtime, sender, service = drop_context
    created = service.create_text_drop(
        sender_id=sender.id,
        content="Tamper detection",
        ttl_policy="burn_after_read",
        pqc_mode=False,
        access_password=None,
        idempotency_key=secrets.token_hex(16),
        now=runtime.now,
    )
    record = runtime.session.get(Drop, created.id)
    original = getattr(record, field)
    setattr(record, field, original[:-1] + bytes([original[-1] ^ 1]))
    runtime.session.commit()
    with pytest.raises(DropServiceError) as rejected:
        service.extract_drop(
            code=created.code,
            access_code=created.access_code,
            idempotency_key=secrets.token_hex(16),
            now=runtime.now,
        )
    assert rejected.value.code in {"signature_invalid", "unseal_failed"}
    assert record.status == "available" and record.ciphertext


def test_real_http_login_create_and_public_extract(drop_context):
    from fastapi.testclient import TestClient

    from app.api.routes.auth import get_login_service
    from app.api.routes.drops import get_drop_service
    from app.db.session import get_db
    from app.main import create_app
    from app.security.auth_dependencies import get_token_verifier

    runtime, sender, service = drop_context
    # Dependency wiring supplies isolated storage and already constructed real
    # services. Crypto methods, JWT verification and authorization run unchanged.
    app = create_app()
    app.dependency_overrides[get_db] = lambda: runtime.session
    app.dependency_overrides[get_token_verifier] = lambda: runtime.codec
    app.dependency_overrides[get_drop_service] = lambda: service
    app.dependency_overrides[get_login_service] = lambda: runtime.login
    http_user, password = runtime.register("http_sender")
    client = TestClient(app)
    try:
        payload = {
            "content": "HTTP real envelope",
            "ttl_policy": "hours_24",
            "pqc_mode": False,
        }
        headers = {"Idempotency-Key": secrets.token_hex(16)}
        assert (
            client.post("/api/v1/drops/text", json=payload, headers=headers).status_code
            == 401
        )
        login = client.post(
            "/api/v1/auth/login", json={"email": http_user.email, "password": password}
        )
        assert login.status_code == 200
        assert "refresh_token" in login.cookies
        headers["Authorization"] = "Bearer " + login.json()["access_token"]
        assert client.get("/api/v1/me", headers=headers).status_code == 200
        assert client.get("/api/v1/admin/users", headers=headers).status_code == 403
        created = client.post("/api/v1/drops/text", json=payload, headers=headers)
        assert created.status_code == 201
        link = created.json()
        metadata = client.get(f"/api/v1/drops/{link['code']}")
        assert metadata.status_code == 200 and "content" not in metadata.json()
        extracted = client.post(
            f"/api/v1/drops/{link['code']}/extract",
            json={"access_code": link["access_code"]},
            headers={"Idempotency-Key": secrets.token_hex(16)},
        )
        assert extracted.status_code == 200
        assert extracted.json()["content"] == payload["content"]
        assert (
            extracted.json()["signature_valid"]
            and extracted.json()["certificate_valid"]
        )
    finally:
        client.close()
