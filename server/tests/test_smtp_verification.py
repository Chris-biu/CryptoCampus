from __future__ import annotations

import smtplib
from email.message import EmailMessage
from pathlib import Path

import pytest
from app.services.smtp_verification import (
    LocalDemoVerificationCodeSender,
    SmtpVerificationCodeSender,
    UnavailableVerificationCodeSender,
    get_runtime_verification_code_sender,
)
from app.services.verification_code import VerificationCodeError


class FakeSmtpClient:
    def __init__(self, host: str, port: int, *, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.calls: list[str] = []
        self.message: EmailMessage | None = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def ehlo(self) -> None:
        self.calls.append("ehlo")

    def starttls(self, *, context) -> None:
        assert context is TLS_CONTEXT
        self.calls.append("starttls")

    def login(self, username: str, password: str) -> None:
        assert (username, password) == ("mailer@example.edu", "smtp-secret")
        self.calls.append("login")

    def send_message(self, message: EmailMessage) -> None:
        self.message = message
        self.calls.append("send_message")


TLS_CONTEXT = object()


def test_sender_requires_tls_before_authentication_and_sends_code() -> None:
    clients: list[FakeSmtpClient] = []

    def factory(host: str, port: int, *, timeout: float) -> FakeSmtpClient:
        client = FakeSmtpClient(host, port, timeout=timeout)
        clients.append(client)
        return client

    sender = SmtpVerificationCodeSender(
        host="smtp.example.edu",
        port=587,
        username="mailer@example.edu",
        password="smtp-secret",
        from_address="mailer@example.edu",
        client_factory=factory,
        tls_context_factory=lambda: TLS_CONTEXT,
    )

    sender.send("student@example.edu", "123456")

    client = clients[0]
    assert (client.host, client.port, client.timeout) == ("smtp.example.edu", 587, 10.0)
    assert client.calls == ["ehlo", "starttls", "ehlo", "login", "send_message"]
    assert client.message is not None
    assert client.message["To"] == "student@example.edu"
    assert "123456" in client.message.get_content()
    assert "smtp-secret" not in client.message.as_string()


def test_sender_maps_transport_failure_without_exposing_secret() -> None:
    class FailingClient(FakeSmtpClient):
        def starttls(self, *, context) -> None:
            raise smtplib.SMTPException("transport detail")

    sender = SmtpVerificationCodeSender(
        host="smtp.example.edu",
        port=587,
        username="mailer@example.edu",
        password="smtp-secret",
        from_address="mailer@example.edu",
        client_factory=FailingClient,
    )

    with pytest.raises(VerificationCodeError) as raised:
        sender.send("student@example.edu", "123456")

    assert raised.value.args == ("sender_unavailable",)
    assert "smtp-secret" not in repr(sender)


def test_runtime_sender_loads_password_from_configured_file(
    tmp_path: Path, monkeypatch
) -> None:
    password_file = tmp_path / "smtp_password"
    password_file.write_text("smtp-secret\n", encoding="utf-8")
    monkeypatch.setenv("CRYPTOCAMPUS_SMTP_HOST", "smtp.example.edu")
    monkeypatch.setenv("CRYPTOCAMPUS_SMTP_USERNAME", "mailer@example.edu")
    monkeypatch.setenv("CRYPTOCAMPUS_SMTP_FROM", "mailer@example.edu")
    monkeypatch.setenv("CRYPTOCAMPUS_SMTP_PASSWORD_FILE", str(password_file))

    sender = get_runtime_verification_code_sender()

    assert isinstance(sender, SmtpVerificationCodeSender)
    assert "smtp-secret" not in repr(sender)


def test_runtime_sender_fails_closed_when_configuration_is_missing(monkeypatch) -> None:
    for name in (
        "CRYPTOCAMPUS_SMTP_HOST",
        "CRYPTOCAMPUS_SMTP_USERNAME",
        "CRYPTOCAMPUS_SMTP_FROM",
    ):
        monkeypatch.delenv(name, raising=False)

    sender = get_runtime_verification_code_sender()

    assert isinstance(sender, UnavailableVerificationCodeSender)
    with pytest.raises(VerificationCodeError):
        sender.send("student@example.edu", "123456")


def test_sender_rejects_header_injection() -> None:
    sender = SmtpVerificationCodeSender(
        host="smtp.example.edu",
        port=587,
        username="mailer@example.edu",
        password="smtp-secret",
        from_address="mailer@example.edu",
    )

    with pytest.raises(VerificationCodeError):
        sender.send("student@example.edu\r\nBcc: attacker@example.edu", "123456")


def test_runtime_sender_uses_local_demo_only_with_explicit_nonproduction_gate(monkeypatch) -> None:
    monkeypatch.setenv("CRYPTOCAMPUS_ENV", "development")
    monkeypatch.setenv("CRYPTOCAMPUS_ALLOW_DEMO_EMAIL", "1")
    monkeypatch.setenv("CRYPTOCAMPUS_DEMO_VERIFICATION_CODE", "246810")

    sender = get_runtime_verification_code_sender()

    assert isinstance(sender, LocalDemoVerificationCodeSender)
    sender.send("student@campus.edu", "246810")


def test_production_ignores_local_demo_email_gate(monkeypatch) -> None:
    monkeypatch.setenv("CRYPTOCAMPUS_ENV", "production")
    monkeypatch.setenv("CRYPTOCAMPUS_ALLOW_DEMO_EMAIL", "1")
    monkeypatch.setenv("CRYPTOCAMPUS_DEMO_VERIFICATION_CODE", "246810")
    monkeypatch.delenv("CRYPTOCAMPUS_SMTP_HOST", raising=False)
    monkeypatch.delenv("CRYPTOCAMPUS_SMTP_USERNAME", raising=False)

    assert isinstance(get_runtime_verification_code_sender(), UnavailableVerificationCodeSender)
