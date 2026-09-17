from datetime import datetime, timedelta, timezone

import pytest

from app.services.verification_code import (
    InMemoryVerificationCodeStore,
    VerificationCodeError,
    VerificationCodeService,
)


class Engine:
    def sm3_digest(self, message: bytes) -> bytes:
        return b"digest:" + message


class Sender:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send(self, email: str, code: str) -> None:
        self.sent.append((email, code))


def test_code_is_one_time_and_plaintext_is_not_stored() -> None:
    sender = Sender()
    store = InMemoryVerificationCodeStore(Engine())
    service = VerificationCodeService(sender=sender, store=store, ttl=timedelta(minutes=5))

    service.issue("student@campus.edu", now=datetime.now(timezone.utc))
    code = sender.sent[0][1]
    assert service.consume("student@campus.edu", code, datetime.now(timezone.utc)) is True
    assert service.consume("student@campus.edu", code, datetime.now(timezone.utc)) is False
    assert code not in repr(store)


def test_expired_or_wrong_code_is_rejected() -> None:
    sender = Sender()
    store = InMemoryVerificationCodeStore(Engine())
    service = VerificationCodeService(sender=sender, store=store, ttl=timedelta(seconds=1))
    issued_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    service.issue("student@campus.edu", now=issued_at)
    code = sender.sent[0][1]
    assert service.consume("student@campus.edu", "000000", issued_at) is False
    assert service.consume("student@campus.edu", code, issued_at + timedelta(seconds=2)) is False


def test_sender_failure_does_not_leak_code() -> None:
    class FailingSender:
        def send(self, email: str, code: str) -> None:
            raise RuntimeError("smtp failed")

    service = VerificationCodeService(sender=FailingSender(), store=InMemoryVerificationCodeStore(Engine()))
    with pytest.raises(VerificationCodeError):
        service.issue("student@campus.edu")


def test_explicit_code_factory_supports_controlled_local_demo() -> None:
    sender = Sender()
    store = InMemoryVerificationCodeStore(Engine())
    service = VerificationCodeService(
        sender=sender,
        store=store,
        code_factory=lambda: "246810",
    )

    service.issue("student@campus.edu")

    assert sender.sent == [("student@campus.edu", "246810")]
    assert service.consume("student@campus.edu", "246810") is True
