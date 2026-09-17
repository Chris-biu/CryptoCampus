import pytest

from app.security.password_policy import PasswordPolicyError, normalize_campus_email, validate_password


def test_normalize_campus_email_strips_and_lowercases() -> None:
    assert normalize_campus_email("  Student@Campus.edu  ") == "student@campus.edu"


@pytest.mark.parametrize("email", ["user@example.com", "", "user@campus.edu extra"])
def test_normalize_campus_email_rejects_non_campus(email: str) -> None:
    with pytest.raises(PasswordPolicyError):
        normalize_campus_email(email)


@pytest.mark.parametrize("password", ["shortA123", "lowercase1234", "UPPERCASE1234", "NoDigitsHereAA"])
def test_validate_password_requires_length_and_character_classes(password: str) -> None:
    with pytest.raises(PasswordPolicyError):
        validate_password(password)


def test_validate_password_accepts_policy_boundary() -> None:
    assert validate_password("a" * 8 + "A1") is None
    assert validate_password("a" * 126 + "A1") is None
