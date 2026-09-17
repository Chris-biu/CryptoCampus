from __future__ import annotations

from datetime import datetime, timezone
import uuid
import pytest
from pydantic import ValidationError

from app.schemas.inspect import (
    InspectEvent,
    InspectStepInput,
    validate_and_sanitize_step,
    DropEnvelopeCreateRedacted,
    DropEnvelopeOpenRedacted,
    DropDestroyRedacted,
    HoleCredentialIssueRedacted,
    HoleCredentialVerifyRedacted,
    VoteCredentialIssueRedacted,
    VoteBallotVerifyRedacted,
    VoteResultSignRedacted,
    SealCreateRedacted,
    SealVerifyRedacted,
    ChatSessionNegotiateRedacted,
)


def test_valid_drop_envelope_create_redacted():
    data = {
        "content_bytes": 1024,
        "pqc_mode": True,
        "digest_prefix": "0123456789abcdef",
        "recipient_cert_fingerprint": "SHA256:abc12345...",
    }
    model = DropEnvelopeCreateRedacted.model_validate(data)
    assert model.content_bytes == 1024
    assert model.pqc_mode is True
    assert model.digest_prefix == "0123456789abcdef"


def test_digest_prefix_must_be_exact_16_lowercase_hex():
    # 15 chars
    with pytest.raises(ValidationError):
        DropEnvelopeCreateRedacted(
            content_bytes=100,
            pqc_mode=False,
            digest_prefix="0123456789abcde",
            recipient_cert_fingerprint="abc",
        )

    # uppercase hex
    with pytest.raises(ValidationError):
        DropEnvelopeCreateRedacted(
            content_bytes=100,
            pqc_mode=False,
            digest_prefix="0123456789ABCDEF",
            recipient_cert_fingerprint="abc",
        )

    # non-hex
    with pytest.raises(ValidationError):
        DropEnvelopeCreateRedacted(
            content_bytes=100,
            pqc_mode=False,
            digest_prefix="0123456789abcdefg",
            recipient_cert_fingerprint="abc",
        )


def test_drop_envelope_create_rejects_forbidden_fields():
    forbidden_keys = [
        "filename",
        "plaintext",
        "content",
        "ciphertext",
        "private_key",
        "kek",
        "session_key",
        "token",
        "password",
    ]
    for key in forbidden_keys:
        data = {
            "content_bytes": 1024,
            "pqc_mode": True,
            "digest_prefix": "0123456789abcdef",
            "recipient_cert_fingerprint": "SHA256:abc...",
            key: "sensitive_data",
        }
        with pytest.raises(ValidationError):
            DropEnvelopeCreateRedacted.model_validate(data)


def test_hole_credential_verify_rejects_user_id_and_sn():
    forbidden_keys = ["user_id", "sn", "credential_sn", "blind_factor", "blinded_message", "token"]
    for key in forbidden_keys:
        data = {
            "service": "hole",
            "period": "2026-09",
            "signature_valid": True,
            "revoked": False,
            key: "leak_secret",
        }
        with pytest.raises(ValidationError):
            HoleCredentialVerifyRedacted.model_validate(data)


def test_vote_ballot_verify_rejects_voter_and_ip():
    forbidden_keys = ["voter", "voter_id", "user_id", "ip", "device", "token"]
    for key in forbidden_keys:
        data = {
            "vote_public_id": str(uuid.uuid4()),
            "signature_valid": True,
            "counted": True,
            key: "sensitive_ident",
        }
        with pytest.raises(ValidationError):
            VoteBallotVerifyRedacted.model_validate(data)


def test_inspect_event_unknown_operation_rejected():
    step = InspectStepInput(
        order=1,
        name="test step",
        algorithm="SM3",
        result="passed",
        redacted_values={"digest_prefix": "0123456789abcdef"},
    )
    with pytest.raises(ValidationError):
        InspectEvent(
            operation="unknown.operation",  # type: ignore
            owner_user_id=None,
            steps=(step,),
            occurred_at=datetime.now(timezone.utc),
        )


def test_inspect_step_order_bounds():
    with pytest.raises(ValidationError):
        InspectStepInput(
            order=0,
            name="test",
            algorithm="SM3",
            result="passed",
            redacted_values={},
        )

    with pytest.raises(ValidationError):
        InspectStepInput(
            order=33,
            name="test",
            algorithm="SM3",
            result="passed",
            redacted_values={},
        )


def test_validate_and_sanitize_step_json_limit():
    huge_str = "x" * 200
    # In drop.destroy, allowed keys are reason_code, ciphertext_bytes_cleared
    # Passing extra keys will fail validation
    with pytest.raises(ValidationError):
        validate_and_sanitize_step("drop.destroy", {"extra_key": huge_str})


def test_nested_structures_rejected():
    with pytest.raises(ValidationError):
        InspectStepInput(
            order=1,
            name="test",
            algorithm="SM3",
            result="passed",
            redacted_values={"nested": {"sub": 1}},  # type: ignore
        )
