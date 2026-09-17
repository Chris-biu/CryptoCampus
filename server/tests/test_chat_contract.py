from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_chat_openapi_distinguishes_client_and_server_frames() -> None:
    contract = yaml.safe_load((ROOT / "docs/api/openapi.yaml").read_text(encoding="utf-8"))
    schemas = contract["components"]["schemas"]

    client_refs = {item["$ref"] for item in schemas["ChatClientFrame"]["oneOf"]}
    server_refs = {item["$ref"] for item in schemas["ChatServerFrame"]["oneOf"]}

    assert "#/components/schemas/ChatEncryptedMessageInput" in client_refs
    assert "#/components/schemas/EncryptedMessage" not in client_refs
    assert "#/components/schemas/EncryptedMessage" in server_refs
    assert schemas["ChatEncryptedMessageInput"]["additionalProperties"] is False
    assert {"id", "sender_id", "created_at"}.isdisjoint(
        schemas["ChatEncryptedMessageInput"]["properties"]
    )


def test_chat_protocol_freezes_token_and_key_ownership() -> None:
    protocol = (ROOT / "docs/chat/websocket-protocol.md").read_text(encoding="utf-8")

    assert "cryptocampus.chat.v1" in protocol
    assert "auth.b64u." in protocol
    assert "只返回 `cryptocampus.chat.v1`" in protocol
    assert "会话 ID 由服务端生成" in protocol
    assert "临时私钥和会话密钥由客户端生成并保存" in protocol


def test_chat_openapi_documents_creation_error_contract() -> None:
    contract = yaml.safe_load((ROOT / "docs/api/openapi.yaml").read_text(encoding="utf-8"))
    responses = contract["paths"]["/chat/sessions"]["post"]["responses"]

    assert {"201", "400", "401", "404", "409", "422", "503"}.issubset(responses)
