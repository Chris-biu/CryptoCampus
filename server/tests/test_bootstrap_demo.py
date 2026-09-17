import pytest

from app.db.bootstrap_demo import require_demo_bootstrap_allowed


def _complete_environment() -> dict[str, str]:
    return {
        "CRYPTOCAMPUS_ENV": "development",
        "CRYPTOCAMPUS_ALLOW_DEMO_BOOTSTRAP": "1",
        "CRYPTOCAMPUS_DEMO_STUDENT_PASSWORD": "student-password",
        "CRYPTOCAMPUS_DEMO_ADMIN_PASSWORD": "admin-password",
        "CRYPTOCAMPUS_DEMO_TEACHER_PASSWORD": "teacher-password",
        "CRYPTOCAMPUS_DEMO_RECIPIENT_PASSWORD": "recipient-password",
    }


def test_demo_bootstrap_requires_explicit_opt_in() -> None:
    environment = _complete_environment()
    del environment["CRYPTOCAMPUS_ALLOW_DEMO_BOOTSTRAP"]

    with pytest.raises(RuntimeError, match="显式设置"):
        require_demo_bootstrap_allowed(environment)


def test_demo_bootstrap_is_forbidden_in_production() -> None:
    environment = _complete_environment()
    environment["CRYPTOCAMPUS_ENV"] = "production"

    with pytest.raises(RuntimeError, match="生产环境禁止"):
        require_demo_bootstrap_allowed(environment)


def test_demo_bootstrap_requires_all_passwords() -> None:
    environment = _complete_environment()
    del environment["CRYPTOCAMPUS_DEMO_TEACHER_PASSWORD"]

    with pytest.raises(RuntimeError, match="全部演示账号口令"):
        require_demo_bootstrap_allowed(environment)


def test_demo_bootstrap_allows_complete_development_configuration() -> None:
    require_demo_bootstrap_allowed(_complete_environment())
