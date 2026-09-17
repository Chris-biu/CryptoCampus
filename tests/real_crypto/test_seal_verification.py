import base64
import json
import secrets

import pytest

from app.security.auth_dependencies import CurrentUser
from app.services.seals import SealService
from app.services.verifications import FiveStepVerificationService


@pytest.mark.parametrize("tamper", [None, "file", "signature"])
def test_real_personal_seal_five_step_verification(runtime, tamper):
    user, password = runtime.register("signer")
    runtime.unlock(user, password)
    service = SealService(runtime.session, runtime.crypto, runtime.ca, runtime.cache)
    document = b"%PDF-1.4\n% CryptoCampus regression document\n%%EOF\n"
    seal = service.create_seal(
        CurrentUser(user.id, "student", "active"),
        document,
        mime_type="application/pdf",
        idempotency_key=secrets.token_hex(16),
    )
    sidecar, filename = service.get_sidecar(seal.id)
    assert filename.endswith(".ccseal")
    if tamper == "file":
        document += b"changed"
    elif tamper == "signature":
        payload = json.loads(sidecar)
        signature = base64.b64decode(payload["signature"])
        payload["signature"] = base64.b64encode(
            signature[:-1] + bytes([signature[-1] ^ 1]),
        ).decode("ascii")
        sidecar = json.dumps(payload).encode()
    result = FiveStepVerificationService(
        runtime.session, runtime.crypto, 10485760
    ).verify(
        document,
        sidecar,
    )
    assert result.valid is (tamper is None)
    steps = {step.name: step.passed for step in result.steps}
    assert steps["digest"] is (tamper != "file")
    assert steps["signature"] is (tamper != "signature")
    assert steps["certificate_chain"] and steps["timestamp"] and steps["revocation"]
