from __future__ import annotations

import os
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import parseaddr
from pathlib import Path
from typing import Callable, Protocol

from app.services.verification_code import (
    VerificationCodeError,
    VerificationCodeSender,
)

_MAX_PASSWORD_FILE_SIZE = 4096


class _SmtpClient(Protocol):
    def __enter__(self): ...

    def __exit__(self, exc_type, exc_value, traceback): ...

    def ehlo(self) -> object: ...

    def starttls(self, *, context: ssl.SSLContext) -> object: ...

    def login(self, username: str, password: str) -> object: ...

    def send_message(self, message: EmailMessage) -> object: ...


@dataclass(frozen=True)
class SmtpVerificationCodeSender:
    host: str
    port: int
    username: str
    password: str = field(repr=False)
    from_address: str = ""
    timeout_seconds: float = 10.0
    client_factory: Callable[..., _SmtpClient] = field(
        default=smtplib.SMTP, repr=False, compare=False
    )
    tls_context_factory: Callable[[], ssl.SSLContext] = field(
        default=ssl.create_default_context, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if (
            not _valid_host(self.host)
            or not (1 <= self.port <= 65535)
            or not _valid_username(self.username)
            or not self.password
            or len(self.password) > _MAX_PASSWORD_FILE_SIZE
            or not _valid_mailbox(self.from_address)
            or not (1 <= self.timeout_seconds <= 30)
        ):
            raise VerificationCodeError("smtp_configuration_invalid")

    def send(self, email: str, code: str) -> None:
        if not _valid_mailbox(email) or len(code) != 6 or not code.isdigit():
            raise VerificationCodeError("verification_message_invalid")
        message = EmailMessage()
        message["Subject"] = "CryptoCampus 注册验证码"
        message["From"] = self.from_address
        message["To"] = email
        message.set_content(
            f"您的 CryptoCampus 注册验证码是：{code}\n\n"
            "验证码 10 分钟内有效。若非本人操作，请忽略此邮件。"
        )
        try:
            with self.client_factory(
                self.host, self.port, timeout=self.timeout_seconds
            ) as client:
                client.ehlo()
                client.starttls(context=self.tls_context_factory())
                client.ehlo()
                client.login(self.username, self.password)
                client.send_message(message)
        except (OSError, smtplib.SMTPException, TimeoutError) as error:
            raise VerificationCodeError("sender_unavailable") from error


class UnavailableVerificationCodeSender:
    def send(self, email: str, code: str) -> None:
        del email, code
        raise VerificationCodeError("sender_unavailable")


class LocalDemoVerificationCodeSender:
    """Accept a code only in an explicitly enabled non-production demo."""

    def send(self, email: str, code: str) -> None:
        if not _valid_mailbox(email) or len(code) != 6 or not code.isdigit():
            raise VerificationCodeError("verification_message_invalid")


def get_runtime_demo_verification_code() -> str | None:
    environment = os.getenv("CRYPTOCAMPUS_ENV", "").strip().lower()
    if environment in {"prod", "production"}:
        return None
    if os.getenv("CRYPTOCAMPUS_ALLOW_DEMO_EMAIL") != "1":
        return None
    code = os.getenv("CRYPTOCAMPUS_DEMO_VERIFICATION_CODE", "")
    return code if len(code) == 6 and code.isdigit() else None


def get_runtime_verification_code_sender() -> VerificationCodeSender:
    if get_runtime_demo_verification_code() is not None:
        return LocalDemoVerificationCodeSender()
    try:
        host = os.environ["CRYPTOCAMPUS_SMTP_HOST"]
        port = int(os.getenv("CRYPTOCAMPUS_SMTP_PORT", "587"))
        username = os.environ["CRYPTOCAMPUS_SMTP_USERNAME"]
        from_address = os.getenv("CRYPTOCAMPUS_SMTP_FROM", username)
        password_path = Path(
            os.getenv(
                "CRYPTOCAMPUS_SMTP_PASSWORD_FILE",
                "/run/secrets/cryptocampus/smtp_password",
            )
        )
        if (
            not password_path.is_file()
            or password_path.stat().st_size <= 0
            or password_path.stat().st_size > _MAX_PASSWORD_FILE_SIZE
        ):
            raise ValueError
        password = password_path.read_text(encoding="utf-8").rstrip("\r\n")
        return SmtpVerificationCodeSender(
            host=host,
            port=port,
            username=username,
            password=password,
            from_address=from_address,
        )
    except (KeyError, OSError, UnicodeDecodeError, ValueError, VerificationCodeError):
        return UnavailableVerificationCodeSender()


def _valid_host(value: str) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 253
        and not any(character.isspace() for character in value)
        and "\r" not in value
        and "\n" not in value
    )


def _valid_mailbox(value: str) -> bool:
    if not isinstance(value, str) or not (3 <= len(value) <= 254):
        return False
    if "\r" in value or "\n" in value:
        return False
    display_name, parsed = parseaddr(value)
    return not display_name and parsed == value and "@" in parsed


def _valid_username(value: str) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 254
        and "\x00" not in value
        and "\r" not in value
        and "\n" not in value
    )
