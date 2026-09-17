import pytest

from harness import isolated_runtime


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOCAMPUS_CAMPUS_EMAIL_DOMAINS", "campus.edu")
    with isolated_runtime(tmp_path) as instance:
        yield instance
