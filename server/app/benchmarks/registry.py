from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.benchmarks.vectors import (
    FIXED_PLAINTEXT_4K,
    FIXED_SM3_DIGEST_KAT,
    HybridEnvelopeOpenContext,
    HybridEnvelopeSealContext,
    Sm2EcdhContext,
    Sm2EnvelopeOpenContext,
    Sm2EnvelopeSealContext,
    Sm2SignContext,
    Sm2VerifyContext,
)
from app.crypto.engine import CryptoEngine


@dataclass(frozen=True)
class BenchmarkOperation:
    name: str
    is_pqc: bool
    required_capability: str
    paired_with: str | None
    setup: Callable[[CryptoEngine], Any]
    run_once: Callable[[CryptoEngine, Any], None]
    verify: Callable[[CryptoEngine, Any], bool]
    teardown: Callable[[CryptoEngine, Any], None]


# 1. signature.sm2.sign
def _setup_sm2_sign(engine: CryptoEngine) -> Sm2SignContext:
    kp = engine.sm2_generate_keypair()
    return Sm2SignContext(keypair=kp, digest=FIXED_SM3_DIGEST_KAT)


def _run_sm2_sign(engine: CryptoEngine, ctx: Sm2SignContext) -> None:
    ctx.last_signature = engine.sm2_sign(ctx.keypair.private_key, ctx.digest)


def _verify_sm2_sign(engine: CryptoEngine, ctx: Sm2SignContext) -> bool:
    if ctx.last_signature is None:
        return False
    return engine.sm2_verify(ctx.keypair.public_key, ctx.digest, ctx.last_signature)


# 2. signature.sm2.verify
def _setup_sm2_verify(engine: CryptoEngine) -> Sm2VerifyContext:
    kp = engine.sm2_generate_keypair()
    sig = engine.sm2_sign(kp.private_key, FIXED_SM3_DIGEST_KAT)
    return Sm2VerifyContext(keypair=kp, digest=FIXED_SM3_DIGEST_KAT, signature=sig)


def _run_sm2_verify(engine: CryptoEngine, ctx: Sm2VerifyContext) -> None:
    valid = engine.sm2_verify(ctx.keypair.public_key, ctx.digest, ctx.signature)
    if not valid:
        raise ValueError("sm2_verify returned False")


def _verify_sm2_verify(engine: CryptoEngine, ctx: Sm2VerifyContext) -> bool:
    return True


# 3. handshake.sm2_ecdh
def _setup_sm2_ecdh(engine: CryptoEngine) -> Sm2EcdhContext:
    kp_a = engine.sm2_generate_keypair()
    kp_b = engine.sm2_generate_keypair()
    return Sm2EcdhContext(party_a=kp_a, party_b=kp_b)


def _run_sm2_ecdh(engine: CryptoEngine, ctx: Sm2EcdhContext) -> None:
    ctx.shared_secret = engine.sm2_ecdh(ctx.party_a.private_key, ctx.party_b.public_key)


def _verify_sm2_ecdh(engine: CryptoEngine, ctx: Sm2EcdhContext) -> bool:
    return ctx.shared_secret is not None and len(ctx.shared_secret) > 0


# 4. envelope.sm2.seal
def _setup_envelope_seal(engine: CryptoEngine) -> Sm2EnvelopeSealContext:
    recip = engine.sm2_generate_keypair()
    sender = engine.sm2_generate_keypair()
    return Sm2EnvelopeSealContext(
        recipient_keypair=recip,
        sender_keypair=sender,
        plaintext=FIXED_PLAINTEXT_4K,
    )


def _run_envelope_seal(engine: CryptoEngine, ctx: Sm2EnvelopeSealContext) -> None:
    ctx.last_envelope = engine.envelope_seal(
        plaintext=ctx.plaintext,
        recipient_sm2_public_key=ctx.recipient_keypair.public_key,
        pqc_mode=False,
        recipient_mlkem_public_key=None,
        sender_private_key=ctx.sender_keypair.private_key,
        sender_certificate_der=b"\x30\x03\x02\x01\x01",
        access_factor=None,
    )


def _verify_envelope_seal(engine: CryptoEngine, ctx: Sm2EnvelopeSealContext) -> bool:
    return ctx.last_envelope is not None


# 5. envelope.sm2.open
def _setup_envelope_open(engine: CryptoEngine) -> Sm2EnvelopeOpenContext:
    recip = engine.sm2_generate_keypair()
    sender = engine.sm2_generate_keypair()
    env = engine.envelope_seal(
        plaintext=FIXED_PLAINTEXT_4K,
        recipient_sm2_public_key=recip.public_key,
        pqc_mode=False,
        recipient_mlkem_public_key=None,
        sender_private_key=sender.private_key,
        sender_certificate_der=b"\x30\x03\x02\x01\x01",
        access_factor=None,
    )
    return Sm2EnvelopeOpenContext(
        recipient_keypair=recip,
        envelope=env,
        expected_plaintext=FIXED_PLAINTEXT_4K,
    )


def _run_envelope_open(engine: CryptoEngine, ctx: Sm2EnvelopeOpenContext) -> None:
    ctx.opened_plaintext = engine.envelope_open(
        envelope=ctx.envelope,
        recipient_sm2_private_key=ctx.recipient_keypair.private_key,
        pqc_mode=False,
        recipient_mlkem_private_key=None,
        access_factor=None,
    )


def _verify_envelope_open(engine: CryptoEngine, ctx: Sm2EnvelopeOpenContext) -> bool:
    return ctx.opened_plaintext == ctx.expected_plaintext


# 6. envelope.hybrid.seal (PQC)
def _setup_hybrid_seal(engine: CryptoEngine) -> HybridEnvelopeSealContext:
    recip = engine.sm2_generate_keypair()
    sender = engine.sm2_generate_keypair()
    return HybridEnvelopeSealContext(
        recipient_keypair=recip,
        sender_keypair=sender,
        plaintext=FIXED_PLAINTEXT_4K,
    )


def _run_hybrid_seal(engine: CryptoEngine, ctx: HybridEnvelopeSealContext) -> None:
    ctx.last_envelope = engine.envelope_seal(
        plaintext=ctx.plaintext,
        recipient_sm2_public_key=ctx.recipient_keypair.public_key,
        pqc_mode=True,
        recipient_mlkem_public_key=b"\x01" * 1184,
        sender_private_key=ctx.sender_keypair.private_key,
        sender_certificate_der=b"\x30\x03\x02\x01\x01",
        access_factor=None,
    )


def _verify_hybrid_seal(engine: CryptoEngine, ctx: HybridEnvelopeSealContext) -> bool:
    return ctx.last_envelope is not None


# 7. envelope.hybrid.open (PQC)
def _setup_hybrid_open(engine: CryptoEngine) -> HybridEnvelopeOpenContext:
    recip = engine.sm2_generate_keypair()
    sender = engine.sm2_generate_keypair()
    env = engine.envelope_seal(
        plaintext=FIXED_PLAINTEXT_4K,
        recipient_sm2_public_key=recip.public_key,
        pqc_mode=True,
        recipient_mlkem_public_key=b"\x01" * 1184,
        sender_private_key=sender.private_key,
        sender_certificate_der=b"\x30\x03\x02\x01\x01",
        access_factor=None,
    )
    return HybridEnvelopeOpenContext(
        recipient_keypair=recip,
        envelope=env,
        expected_plaintext=FIXED_PLAINTEXT_4K,
    )


def _run_hybrid_open(engine: CryptoEngine, ctx: HybridEnvelopeOpenContext) -> None:
    ctx.opened_plaintext = engine.envelope_open(
        envelope=ctx.envelope,
        recipient_sm2_private_key=ctx.recipient_keypair.private_key,
        pqc_mode=True,
        recipient_mlkem_private_key=b"\x02" * 2400,
        access_factor=None,
    )


def _verify_hybrid_open(engine: CryptoEngine, ctx: HybridEnvelopeOpenContext) -> bool:
    return ctx.opened_plaintext == ctx.expected_plaintext


# Fixed ordered operation registry
ALL_OPERATIONS: tuple[BenchmarkOperation, ...] = (
    BenchmarkOperation(
        name="envelope.sm2.seal",
        is_pqc=False,
        required_capability="envelope",
        paired_with=None,
        setup=_setup_envelope_seal,
        run_once=_run_envelope_seal,
        verify=_verify_envelope_seal,
        teardown=lambda engine, ctx: ctx.teardown(),
    ),
    BenchmarkOperation(
        name="envelope.sm2.open",
        is_pqc=False,
        required_capability="envelope",
        paired_with=None,
        setup=_setup_envelope_open,
        run_once=_run_envelope_open,
        verify=_verify_envelope_open,
        teardown=lambda engine, ctx: ctx.teardown(),
    ),
    BenchmarkOperation(
        name="signature.sm2.sign",
        is_pqc=False,
        required_capability="sm2",
        paired_with=None,
        setup=_setup_sm2_sign,
        run_once=_run_sm2_sign,
        verify=_verify_sm2_sign,
        teardown=lambda engine, ctx: ctx.teardown(),
    ),
    BenchmarkOperation(
        name="signature.sm2.verify",
        is_pqc=False,
        required_capability="sm2",
        paired_with=None,
        setup=_setup_sm2_verify,
        run_once=_run_sm2_verify,
        verify=_verify_sm2_verify,
        teardown=lambda engine, ctx: ctx.teardown(),
    ),
    BenchmarkOperation(
        name="handshake.sm2_ecdh",
        is_pqc=False,
        required_capability="sm2",
        paired_with=None,
        setup=_setup_sm2_ecdh,
        run_once=_run_sm2_ecdh,
        verify=_verify_sm2_ecdh,
        teardown=lambda engine, ctx: ctx.teardown(),
    ),
    BenchmarkOperation(
        name="envelope.hybrid.seal",
        is_pqc=True,
        required_capability="hybrid_envelope",
        paired_with="envelope.sm2.seal",
        setup=_setup_hybrid_seal,
        run_once=_run_hybrid_seal,
        verify=_verify_hybrid_seal,
        teardown=lambda engine, ctx: ctx.teardown(),
    ),
    BenchmarkOperation(
        name="envelope.hybrid.open",
        is_pqc=True,
        required_capability="hybrid_envelope",
        paired_with="envelope.sm2.open",
        setup=_setup_hybrid_open,
        run_once=_run_hybrid_open,
        verify=_verify_hybrid_open,
        teardown=lambda engine, ctx: ctx.teardown(),
    ),
)


def get_benchmark_operations(include_pqc: bool) -> list[BenchmarkOperation]:
    """Return ordered list of candidate operations."""
    if not include_pqc:
        return [op for op in ALL_OPERATIONS if not op.is_pqc]
    return list(ALL_OPERATIONS)
