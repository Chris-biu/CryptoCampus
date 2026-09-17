from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.crypto.engine import CryptoEngine
from app.crypto.types import EnvelopeArtifact, Sm2KeyPair


# Fixed 4 KiB public benchmark vector (no sensitive data)
FIXED_PLAINTEXT_4K: bytes = bytes((i * 37 + 11) % 256 for i in range(4096))

# Fixed 32-byte SM3 KAT digest vector
FIXED_SM3_DIGEST_KAT: bytes = bytes.fromhex(
    "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
)


@dataclass
class Sm2SignContext:
    keypair: Sm2KeyPair
    digest: bytes
    last_signature: bytes | None = None

    def teardown(self) -> None:
        self.last_signature = None


@dataclass
class Sm2VerifyContext:
    keypair: Sm2KeyPair
    digest: bytes
    signature: bytes

    def teardown(self) -> None:
        pass


@dataclass
class Sm2EcdhContext:
    party_a: Sm2KeyPair
    party_b: Sm2KeyPair
    shared_secret: bytes | None = None

    def teardown(self) -> None:
        self.shared_secret = None


@dataclass
class Sm2EnvelopeSealContext:
    recipient_keypair: Sm2KeyPair
    sender_keypair: Sm2KeyPair
    plaintext: bytes
    last_envelope: EnvelopeArtifact | None = None

    def teardown(self) -> None:
        self.last_envelope = None


@dataclass
class Sm2EnvelopeOpenContext:
    recipient_keypair: Sm2KeyPair
    envelope: EnvelopeArtifact
    expected_plaintext: bytes
    opened_plaintext: bytes | None = None

    def teardown(self) -> None:
        self.opened_plaintext = None


@dataclass
class HybridEnvelopeSealContext:
    recipient_keypair: Sm2KeyPair
    sender_keypair: Sm2KeyPair
    plaintext: bytes
    last_envelope: EnvelopeArtifact | None = None

    def teardown(self) -> None:
        self.last_envelope = None


@dataclass
class HybridEnvelopeOpenContext:
    recipient_keypair: Sm2KeyPair
    envelope: EnvelopeArtifact
    expected_plaintext: bytes
    opened_plaintext: bytes | None = None

    def teardown(self) -> None:
        self.opened_plaintext = None
