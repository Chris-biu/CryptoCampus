import json
import pytest
from app.core.errors import ApiError
from app.services.tlcp_handshake import FileTlcpHandshakeProvider


def test_tlcp_provider_file_missing(tmp_path):
    missing_file = tmp_path / "non_existent.json"
    provider = FileTlcpHandshakeProvider(data_path=missing_file)

    with pytest.raises(ApiError) as exc:
        provider.get_latest_redacted()
    assert exc.value.status_code == 503
    assert exc.value.code == "PROVIDER_UNAVAILABLE"


def test_tlcp_provider_valid_file(tmp_path):
    valid_data = {
        "protocol": "TLCP",
        "cipher_suite": "ECDHE_SM4_CBC_SM3",
        "signing_certificate": "sha256:1122334455667788",
        "encryption_certificate": "sha256:aabbccddeeff0011",
        "messages": [
            "ClientHello",
            "ServerHello",
            "Certificate",
            "ServerKeyExchange",
            "ServerHelloDone",
            "ClientKeyExchange",
            "ChangeCipherSpec",
            "Finished",
        ],
        "captured_at": "2026-09-10T10:00:00Z",
        "schema_version": 1,
    }
    data_file = tmp_path / "tlcp.json"
    data_file.write_text(json.dumps(valid_data), encoding="utf-8")

    provider = FileTlcpHandshakeProvider(data_path=data_file)
    result = provider.get_latest_redacted()
    assert result.protocol == "TLCP"
    assert result.cipher_suite == "ECDHE_SM4_CBC_SM3"
    assert len(result.messages) == 8
    # Extra fields like captured_at are discarded per OpenAPI schema
    assert not hasattr(result, "captured_at")


def test_tlcp_provider_rejects_sensitive_data(tmp_path):
    leaky_data = {
        "protocol": "TLCP",
        "cipher_suite": "ECDHE_SM4_CBC_SM3",
        "signing_certificate": "sha256:1122334455667788",
        "encryption_certificate": "sha256:aabbccddeeff0011",
        "messages": ["ClientHello", "ServerHello"],
        "captured_at": "2026-09-10T10:00:00Z",
        "schema_version": 1,
        "private_key": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6",
    }
    data_file = tmp_path / "tlcp_leaky.json"
    data_file.write_text(json.dumps(leaky_data), encoding="utf-8")

    provider = FileTlcpHandshakeProvider(data_path=data_file)
    with pytest.raises(ApiError) as exc:
        provider.get_latest_redacted()
    assert exc.value.status_code == 503
    assert exc.value.code == "PROVIDER_UNAVAILABLE"


def test_tlcp_provider_rejects_invalid_schema(tmp_path):
    invalid_data = {
        "protocol": "TLS 1.3",  # Not TLCP
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
    }
    data_file = tmp_path / "invalid.json"
    data_file.write_text(json.dumps(invalid_data), encoding="utf-8")

    provider = FileTlcpHandshakeProvider(data_path=data_file)
    with pytest.raises(ApiError) as exc:
        provider.get_latest_redacted()
    assert exc.value.status_code == 503
    assert exc.value.code == "PROVIDER_UNAVAILABLE"
