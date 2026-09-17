from typing import Protocol, runtime_checkable

from app.crypto.types import (
    CrlArtifact,
    EnvelopeArtifact,
    ProviderStatus,
    SignedCertificate,
    Sm2KeyPair,
    Sm4GcmCiphertext,
)


@runtime_checkable
class CryptoEngine(Protocol):
    def provider_status(self) -> ProviderStatus: ...

    def reload_pqc_provider(self) -> ProviderStatus: ...


    def sm3_digest(self, message: bytes) -> bytes: ...

    def sm3_hash_password(self, password_utf8: bytes, salt_a: bytes) -> bytes: ...

    def constant_time_equal(self, left: bytes, right: bytes) -> bool: ...

    def hkdf_sm3(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes: ...

    def sm4_gcm_encrypt(
        self, key: bytes, plaintext: bytes, aad: bytes = b""
    ) -> Sm4GcmCiphertext: ...

    def sm4_gcm_decrypt(
        self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes
    ) -> bytes: ...

    def sm2_generate_keypair(self) -> Sm2KeyPair: ...

    def sm2_sign(self, private_key: bytes, digest: bytes) -> bytes: ...

    def sm2_verify(self, public_key: bytes, digest: bytes, signature: bytes) -> bool: ...

    def sm2_ecdh(self, private_key: bytes, peer_public_key: bytes) -> bytes: ...

    def csr_create(
        self, private_key: bytes, public_key: bytes, common_name: str, role: str
    ) -> bytes: ...

    def cert_sign(
        self,
        csr_der: bytes,
        ca_certificate_der: bytes,
        ca_private_key: bytes,
        not_before: int,
        not_after: int,
        key_usage: tuple[str, ...],
    ) -> SignedCertificate: ...

    def cert_chain_verify(
        self,
        leaf_certificate_der: bytes,
        certificate_chain_der: tuple[bytes, ...],
        trust_root_der: bytes,
        verification_time: int,
        required_key_usage: tuple[str, ...],
    ) -> bool: ...

    def crl_create(
        self,
        revoked_serials: tuple[str, ...],
        ca_certificate_der: bytes,
        ca_private_key: bytes,
        this_update: int,
        next_update: int,
    ) -> CrlArtifact: ...

    def crl_verify(
        self, certificate_der: bytes, crl_der: bytes, verification_time: int
    ) -> bool: ...

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
    ) -> EnvelopeArtifact: ...

    def envelope_open(
        self,
        *,
        envelope: EnvelopeArtifact,
        recipient_sm2_private_key: bytes,
        pqc_mode: bool,
        recipient_mlkem_private_key: bytes | None,
        access_factor: bytes | None,
    ) -> bytes: ...

    def blind_commit(self) -> tuple[bytes, bytes]: ...

    def blind_sign(
        self,
        *,
        blinded_message: bytes,
        signer_private_key: bytes,
        secret_k: bytes | None = None,
    ) -> bytes: ...

    def blind_verify(
        self,
        *,
        message: bytes,
        signature: bytes,
        signer_public_key: bytes,
    ) -> bool: ...

