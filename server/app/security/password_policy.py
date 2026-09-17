import os
import re


class PasswordPolicyError(ValueError):
    pass


_EMAIL_RE = re.compile(r"^[^\s@]+@([^\s@]+)$")


def normalize_campus_email(email: str) -> str:
    if not isinstance(email, str):
        raise PasswordPolicyError("email_invalid")
    normalized = email.strip().lower()
    if len(normalized) > 254:
        raise PasswordPolicyError("email_invalid")
    match = _EMAIL_RE.fullmatch(normalized)
    if match is None:
        raise PasswordPolicyError("email_invalid")
    configured = os.getenv("CRYPTOCAMPUS_CAMPUS_EMAIL_DOMAINS", "campus.edu")
    domains = {item.strip().lower().lstrip("@") for item in configured.split(",") if item.strip()}
    if match.group(1) not in domains:
        raise PasswordPolicyError("email_domain_invalid")
    return normalized


def validate_password(password: str) -> None:
    if (
        not isinstance(password, str)
        or not 10 <= len(password) <= 128
        or re.search(r"[a-z]", password) is None
        or re.search(r"[A-Z]", password) is None
        or re.search(r"[0-9]", password) is None
    ):
        raise PasswordPolicyError("password_policy_invalid")


def is_valid_password(password: str) -> bool:
    try:
        validate_password(password)
    except PasswordPolicyError:
        return False
    return True


normalize_email = normalize_campus_email
