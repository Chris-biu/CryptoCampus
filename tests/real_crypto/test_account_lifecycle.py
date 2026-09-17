from datetime import timedelta

import pytest

from app.core.errors import ApiError
from app.models.certificate import CertificateRecord
from app.security.auth_dependencies import authenticate_access_token, require_roles
from app.services.login import LoginError


def test_real_registration_certificate_login_and_authorization(runtime):
    user, password = runtime.register("alice")
    certificate = runtime.session.get(CertificateRecord, user.cert_serial)
    assert runtime.ca.verify_certificate(
        certificate.certificate_der,
        runtime.now,
        ("digitalSignature",),
    ).valid
    assert user.salt_a != user.salt_k
    assert user.enc_sk.startswith(b"v1")
    assert len(user.auth_hash) == 32

    auth = runtime.unlock(user, password)
    unlocked = runtime.cache.get(user.id, runtime.now)
    assert unlocked is not None and len(unlocked) == 32
    assert unlocked not in user.enc_sk
    current = authenticate_access_token(
        auth.access_token, runtime.codec, runtime.session, runtime.now
    )
    assert current.user_id == user.id and current.session_id
    assert runtime.login.take_refresh_token()
    with pytest.raises(ApiError) as forbidden:
        require_roles("admin", "teacher")(current)
    assert forbidden.value.status_code == 403

    user.status = "frozen"
    runtime.session.commit()
    with pytest.raises(ApiError) as frozen:
        authenticate_access_token(
            auth.access_token, runtime.codec, runtime.session, runtime.now
        )
    assert frozen.value.status_code == 401


@pytest.mark.parametrize("damage", ["wrong_password", "encrypted_key_tag"])
def test_real_login_rejects_invalid_password_or_tampered_private_key(runtime, damage):
    user, password = runtime.register("alice")
    if damage == "wrong_password":
        password += "invalid"
    else:
        user.enc_sk = user.enc_sk[:-1] + bytes([user.enc_sk[-1] ^ 1])
        runtime.session.commit()
    with pytest.raises(LoginError):
        runtime.unlock(user, password)
    assert runtime.cache.get(user.id, runtime.now) is None
    assert runtime.login.take_refresh_token() is None


def test_real_ca_revocation_rejects_revoked_leaf_but_preserves_other_leaf(runtime):
    revoked, _ = runtime.register("revoked")
    valid, _ = runtime.register("valid")
    revoked_cert = runtime.session.get(CertificateRecord, revoked.cert_serial)
    valid_cert = runtime.session.get(CertificateRecord, valid.cert_serial)
    snapshot = runtime.ca.revoke_certificate(
        revoked.cert_serial,
        "regression revocation",
        revoked.id,
        runtime.now,
        runtime.now + timedelta(days=1),
    )
    runtime.session.commit()
    assert snapshot.crl_der
    denied = runtime.ca.verify_certificate(
        revoked_cert.certificate_der,
        runtime.now,
        ("digitalSignature",),
    )
    assert not denied.valid and denied.state == "revoked"
    assert runtime.ca.verify_certificate(
        valid_cert.certificate_der,
        runtime.now,
        ("digitalSignature",),
    ).valid
