import re
from typing import cast

from app.crypto.errors import BridgeErrorCode, CryptoBridgeError
from app.crypto.types import (
    GCM_NONCE_SIZE,
    GCM_TAG_SIZE,
    MAX_DER_CERTIFICATE_SIZE,
    MAX_DER_CRL_SIZE,
    MAX_DROP_CONTENT_SIZE,
    MLKEM_PRIVATE_KEY_SIZE,
    MLKEM_PUBLIC_KEY_SIZE,
    CrlArtifact,

    EnvelopeArtifact,
    SM2_PRIVATE_KEY_SIZE,
    SM2_PUBLIC_KEY_SIZE,
    SM2_SIGNATURE_SIZE,
    SM3_DIGEST_SIZE,
    SM4_KEY_SIZE,
    ProviderStatus,
    SignedCertificate,
    Sm2KeyPair,
    Sm4GcmCiphertext,
    require_exact_length,
)

_ALLOWED_CERTIFICATE_ROLES = {"student", "admin", "teacher", "system"}


class MockCryptoEngine:
    def __init__(self, *, status: ProviderStatus | None = None) -> None:
        self._status = status or ProviderStatus(
            state="online",
            version="test",
            provider="mock",
            capabilities={},
        )
        self._results: dict[str, object] = {}
        self._errors: dict[str, CryptoBridgeError] = {}
        self._calls: list[tuple[str, dict[str, int]]] = []

    def set_result(self, operation: str, value: object) -> None:
        self._results[operation] = value

    def set_error(self, operation: str, error: CryptoBridgeError) -> None:
        self._errors[operation] = error

    @property
    def calls(self) -> tuple[tuple[str, dict[str, int]], ...]:
        return tuple((operation, dict(lengths)) for operation, lengths in self._calls)

    def provider_status(self) -> ProviderStatus:
        return self._status

    def reload_pqc_provider(self) -> ProviderStatus:
        self._calls.append(("reload_pqc_provider", {}))
        if "reload_pqc_provider" in self._errors:
            raise self._errors["reload_pqc_provider"]
        if "reload_pqc_provider" in self._results:
            result = self._results["reload_pqc_provider"]
            if isinstance(result, ProviderStatus):
                self._status = result
                return result
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        return self._status


    def _operation(self, operation: str, lengths: dict[str, int]) -> object:
        self._calls.append((operation, lengths))
        if operation in self._errors:
            raise self._errors[operation]
        if operation in self._results:
            return self._results[operation]
        raise CryptoBridgeError(BridgeErrorCode.UNSUPPORTED)

    def sm3_digest(self, message: bytes) -> bytes:
        return cast(bytes, self._operation("sm3_digest", {"message": len(message)}))

    def sm3_hash_password(self, password_utf8: bytes, salt_a: bytes) -> bytes:
        return cast(
            bytes,
            self._operation(
                "sm3_hash_password",
                {"password_utf8": len(password_utf8), "salt_a": len(salt_a)},
            ),
        )

    def constant_time_equal(self, left: bytes, right: bytes) -> bool:
        return cast(
            bool,
            self._operation(
                "constant_time_equal", {"left": len(left), "right": len(right)}
            ),
        )

    def hkdf_sm3(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        return cast(
            bytes,
            self._operation(
                "hkdf_sm3",
                {
                    "ikm": len(ikm),
                    "salt": len(salt),
                    "info": len(info),
                    "length": length,
                },
            ),
        )

    def sm4_gcm_encrypt(
        self, key: bytes, plaintext: bytes, aad: bytes = b""
    ) -> Sm4GcmCiphertext:
        require_exact_length(key, SM4_KEY_SIZE)
        return cast(
            Sm4GcmCiphertext,
            self._operation(
                "sm4_gcm_encrypt",
                {"key": len(key), "plaintext": len(plaintext), "aad": len(aad)},
            ),
        )

    def sm4_gcm_decrypt(
        self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes
    ) -> bytes:
        require_exact_length(key, SM4_KEY_SIZE)
        require_exact_length(nonce, GCM_NONCE_SIZE)
        require_exact_length(tag, GCM_TAG_SIZE)
        return cast(
            bytes,
            self._operation(
                "sm4_gcm_decrypt",
                {
                    "key": len(key),
                    "nonce": len(nonce),
                    "ciphertext": len(ciphertext),
                    "aad": len(aad),
                    "tag": len(tag),
                },
            ),
        )

    def sm2_generate_keypair(self) -> Sm2KeyPair:
        return cast(Sm2KeyPair, self._operation("sm2_generate_keypair", {}))

    def sm2_sign(self, private_key: bytes, digest: bytes) -> bytes:
        require_exact_length(private_key, SM2_PRIVATE_KEY_SIZE)
        require_exact_length(digest, SM3_DIGEST_SIZE)
        return cast(
            bytes,
            self._operation(
                "sm2_sign",
                {"private_key": len(private_key), "digest": len(digest)},
            ),
        )

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool:
        require_exact_length(public_key, SM2_PUBLIC_KEY_SIZE)
        require_exact_length(digest, SM3_DIGEST_SIZE)
        require_exact_length(signature, SM2_SIGNATURE_SIZE)
        return cast(
            bool,
            self._operation(
                "sm2_verify",
                {
                    "public_key": len(public_key),
                    "digest": len(digest),
                    "signature": len(signature),
                },
            ),
        )

    def sm2_ecdh(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        require_exact_length(private_key, SM2_PRIVATE_KEY_SIZE)
        require_exact_length(peer_public_key, SM2_PUBLIC_KEY_SIZE)
        return cast(
            bytes,
            self._operation(
                "sm2_ecdh",
                {
                    "private_key": len(private_key),
                    "peer_public_key": len(peer_public_key),
                },
            ),
        )

    def csr_create(
        self, private_key: bytes, public_key: bytes, common_name: str, role: str
    ) -> bytes:
        require_exact_length(private_key, SM2_PRIVATE_KEY_SIZE)
        require_exact_length(public_key, SM2_PUBLIC_KEY_SIZE)
        if (
            not isinstance(common_name, str)
            or not common_name
            or not isinstance(role, str)
            or role not in _ALLOWED_CERTIFICATE_ROLES
        ):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        result = self._operation(
                "csr_create",
                {
                    "private_key": len(private_key),
                    "public_key": len(public_key),
                    "common_name": len(common_name),
                    "role": len(role),
                },
            )
        self._require_certificate_der(result)
        return cast(bytes, result)

    def cert_sign(
        self,
        csr_der: bytes,
        ca_certificate_der: bytes,
        ca_private_key: bytes,
        not_before: int,
        not_after: int,
        key_usage: tuple[str, ...],
    ) -> SignedCertificate:
        self._require_certificate_der(csr_der)
        self._require_certificate_der(ca_certificate_der)
        require_exact_length(ca_private_key, SM2_PRIVATE_KEY_SIZE)
        self._require_time_range(not_before, not_after)
        self._require_key_usage(key_usage)
        result = self._operation(
                "cert_sign",
                {
                    "csr_der": len(csr_der),
                    "ca_certificate_der": len(ca_certificate_der),
                    "ca_private_key": len(ca_private_key),
                    "key_usage": len(key_usage),
                },
            )
        if not isinstance(result, SignedCertificate):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        return result

    def cert_chain_verify(
        self,
        leaf_certificate_der: bytes,
        certificate_chain_der: tuple[bytes, ...],
        trust_root_der: bytes,
        verification_time: int,
        required_key_usage: tuple[str, ...],
    ) -> bool:
        self._require_certificate_der(leaf_certificate_der)
        self._require_certificate_der(trust_root_der)
        if not isinstance(certificate_chain_der, tuple) or type(verification_time) is not int:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        for certificate_der in certificate_chain_der:
            self._require_certificate_der(certificate_der)
        self._require_key_usage(required_key_usage)
        return cast(
            bool,
            self._operation(
                "cert_chain_verify",
                {
                    "leaf_certificate_der": len(leaf_certificate_der),
                    "certificate_chain_der": len(certificate_chain_der),
                    "trust_root_der": len(trust_root_der),
                    "required_key_usage": len(required_key_usage),
                },
            ),
        )

    def crl_create(
        self,
        revoked_serials: tuple[str, ...],
        ca_certificate_der: bytes,
        ca_private_key: bytes,
        this_update: int,
        next_update: int,
    ) -> CrlArtifact:
        if not isinstance(revoked_serials, tuple) or not all(
            isinstance(serial, str) and re.fullmatch(r"[A-Za-z0-9:-]{1,128}", serial)
            for serial in revoked_serials
        ):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        self._require_certificate_der(ca_certificate_der)
        require_exact_length(ca_private_key, SM2_PRIVATE_KEY_SIZE)
        self._require_time_range(this_update, next_update)
        result = self._operation(
                "crl_create",
                {
                    "revoked_serials": len(revoked_serials),
                    "ca_certificate_der": len(ca_certificate_der),
                    "ca_private_key": len(ca_private_key),
                },
            )
        if not isinstance(result, CrlArtifact):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        return result

    def crl_verify(
        self, certificate_der: bytes, crl_der: bytes, verification_time: int
    ) -> bool:
        self._require_certificate_der(certificate_der)
        if not isinstance(crl_der, bytes) or not crl_der or len(crl_der) > MAX_DER_CRL_SIZE:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        if type(verification_time) is not int:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        return cast(
            bool,
            self._operation(
                "crl_verify",
                {"certificate_der": len(certificate_der), "crl_der": len(crl_der)},
            ),
        )

    def envelope_seal(
        self,
        *,
        plaintext: bytes,
        recipient_sm2_public_key: bytes,
        pqc_mode: bool,
        recipient_mlkem_public_key: bytes | None,
        sender_private_key: bytes,
        sender_certificate_der: bytes,
        access_factor: bytes | None,
    ) -> EnvelopeArtifact:
        if not isinstance(plaintext, bytes) or not plaintext or len(plaintext) > MAX_DROP_CONTENT_SIZE:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(recipient_sm2_public_key, SM2_PUBLIC_KEY_SIZE)
        if not isinstance(pqc_mode, bool):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        if pqc_mode:
            if recipient_mlkem_public_key is None:
                raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
            require_exact_length(recipient_mlkem_public_key, MLKEM_PUBLIC_KEY_SIZE)
        else:
            if recipient_mlkem_public_key is not None:
                raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(sender_private_key, SM2_PRIVATE_KEY_SIZE)
        self._require_certificate_der(sender_certificate_der)
        if access_factor is not None:
            if not isinstance(access_factor, bytes) or not (16 <= len(access_factor) <= 32):
                raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        result = self._operation(
            "envelope_seal",
            {
                "plaintext": len(plaintext),
                "recipient_sm2_public_key": len(recipient_sm2_public_key),
                "recipient_mlkem_public_key": len(recipient_mlkem_public_key) if recipient_mlkem_public_key else 0,
                "sender_private_key": len(sender_private_key),
                "sender_certificate_der": len(sender_certificate_der),
                "access_factor": len(access_factor) if access_factor else 0,
            },
        )
        if not isinstance(result, EnvelopeArtifact):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        return result

    def envelope_open(
        self,
        *,
        envelope: EnvelopeArtifact,
        recipient_sm2_private_key: bytes,
        pqc_mode: bool,
        recipient_mlkem_private_key: bytes | None,
        access_factor: bytes | None,
    ) -> bytes:
        if not isinstance(envelope, EnvelopeArtifact):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(recipient_sm2_private_key, SM2_PRIVATE_KEY_SIZE)
        if not isinstance(pqc_mode, bool):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        if pqc_mode:
            if recipient_mlkem_private_key is None:
                raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
            require_exact_length(recipient_mlkem_private_key, MLKEM_PRIVATE_KEY_SIZE)
        else:
            if recipient_mlkem_private_key is not None:
                raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        if access_factor is not None:
            if not isinstance(access_factor, bytes) or not (16 <= len(access_factor) <= 32):
                raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        result = self._operation(
            "envelope_open",
            {
                "ciphertext": len(envelope.ciphertext),
                "recipient_sm2_private_key": len(recipient_sm2_private_key),
                "recipient_mlkem_private_key": len(recipient_mlkem_private_key) if recipient_mlkem_private_key else 0,
                "access_factor": len(access_factor) if access_factor else 0,
            },
        )
        if not isinstance(result, bytes) or not result or len(result) > MAX_DROP_CONTENT_SIZE:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        return result

    def blind_commit(self) -> tuple[bytes, bytes]:
        self._calls.append(("blind_commit", {}))
        if "blind_commit" in self._errors:
            raise self._errors["blind_commit"]
        if "blind_commit" in self._results:
            result = self._results["blind_commit"]
            if (
                isinstance(result, tuple)
                and len(result) == 2
                and isinstance(result[0], bytes)
                and len(result[0]) == 32
                and isinstance(result[1], bytes)
                and len(result[1]) == 65
                and result[1][0] == 0x04
            ):
                return result
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        return (b"\x01" * 32, b"\x04" + b"\x02" * 64)

    def blind_sign(
        self,
        *,
        blinded_message: bytes,
        signer_private_key: bytes,
        secret_k: bytes | None = None,
    ) -> bytes:
        if not isinstance(blinded_message, bytes) or not blinded_message:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(signer_private_key, SM2_PRIVATE_KEY_SIZE)
        if secret_k is not None:
            require_exact_length(secret_k, SM2_PRIVATE_KEY_SIZE)
        parameters = {
            "blinded_message": len(blinded_message),
            "signer_private_key": len(signer_private_key),
        }
        if secret_k is not None:
            parameters["secret_k"] = len(secret_k)
        result = self._operation("blind_sign", parameters)
        if not isinstance(result, bytes) or not result:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        return result

    def blind_verify(
        self,
        *,
        message: bytes,
        signature: bytes,
        signer_public_key: bytes,
    ) -> bool:
        if not isinstance(message, bytes) or not message:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        require_exact_length(signature, SM2_SIGNATURE_SIZE)
        require_exact_length(signer_public_key, SM2_PUBLIC_KEY_SIZE)
        result = self._operation(
            "blind_verify",
            {
                "message": len(message),
                "signature": len(signature),
                "signer_public_key": len(signer_public_key),
            },
        )
        if not isinstance(result, bool):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
        return result


    @staticmethod
    def _require_certificate_der(value: bytes) -> None:
        if not isinstance(value, bytes) or not value or len(value) > MAX_DER_CERTIFICATE_SIZE:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)

    @staticmethod
    def _require_time_range(not_before: int, not_after: int) -> None:
        if type(not_before) is not int or type(not_after) is not int or not_after <= not_before:
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)

    @staticmethod
    def _require_key_usage(key_usage: tuple[str, ...]) -> None:
        if not isinstance(key_usage, tuple) or not key_usage or not all(isinstance(value, str) and value for value in key_usage):
            raise CryptoBridgeError(BridgeErrorCode.INVALID_ARGUMENT)
