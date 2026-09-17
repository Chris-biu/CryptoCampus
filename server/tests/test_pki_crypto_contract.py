import pytest

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import MAX_DER_CERTIFICATE_SIZE, MAX_DER_CRL_SIZE, CrlArtifact, SignedCertificate


def test_signed_certificate_rejects_oversized_der() -> None:
    with pytest.raises(CryptoBridgeError) as raised:
        SignedCertificate(
            der=b"x" * (MAX_DER_CERTIFICATE_SIZE + 1),
            serial="01",
            not_before=1,
            not_after=2,
        )

    assert raised.value.code is BridgeErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("serial", ["", "serial with spaces", "serial/"])
def test_signed_certificate_rejects_invalid_serial(serial: str) -> None:
    with pytest.raises(CryptoBridgeError) as raised:
        SignedCertificate(der=b"certificate", serial=serial, not_before=1, not_after=2)

    assert raised.value.code is BridgeErrorCode.INVALID_ARGUMENT


def test_signed_certificate_requires_increasing_times() -> None:
    with pytest.raises(CryptoBridgeError) as raised:
        SignedCertificate(der=b"certificate", serial="01", not_before=2, not_after=2)

    assert raised.value.code is BridgeErrorCode.INVALID_ARGUMENT


def test_crl_artifact_requires_increasing_times() -> None:
    with pytest.raises(CryptoBridgeError) as raised:
        CrlArtifact(der=b"crl", this_update=2, next_update=2)

    assert raised.value.code is BridgeErrorCode.INVALID_ARGUMENT


def test_crl_artifact_rejects_empty_and_oversized_der() -> None:
    for der in (b"", b"x" * (MAX_DER_CRL_SIZE + 1)):
        with pytest.raises(CryptoBridgeError) as raised:
            CrlArtifact(der=der, this_update=1, next_update=2)

        assert raised.value.code is BridgeErrorCode.INVALID_ARGUMENT
