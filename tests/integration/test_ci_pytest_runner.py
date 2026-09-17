import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def runner():
    path = Path(__file__).resolve().parents[1] / "ci" / "run_pytest.py"
    spec = importlib.util.spec_from_file_location("ci_pytest_runner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_uses_tmpfs_only_when_writable_and_large_enough(runner, monkeypatch):
    monkeypatch.setattr(runner.sys, "platform", "linux")
    monkeypatch.setattr(runner.Path, "is_dir", lambda path: True)
    monkeypatch.setattr(runner.os, "access", lambda path, flags: True)
    monkeypatch.setattr(
        runner.shutil, "disk_usage", lambda path: SimpleNamespace(free=64 * 1024**2)
    )
    assert runner.temp_parent() == Path("/dev/shm")
    monkeypatch.setattr(
        runner.shutil, "disk_usage", lambda path: SimpleNamespace(free=1024)
    )
    assert runner.temp_parent() is None
    monkeypatch.setattr(runner.os, "access", lambda path, flags: False)
    assert runner.temp_parent() is None


def test_falls_back_when_tmpfs_is_unavailable(runner, monkeypatch):
    monkeypatch.setattr(runner.sys, "platform", "win32")
    assert runner.temp_parent() is None
    monkeypatch.setattr(runner.sys, "platform", "linux")
    monkeypatch.setattr(runner.Path, "is_dir", lambda path: False)
    assert runner.temp_parent() is None
    monkeypatch.setattr(runner.Path, "is_dir", lambda path: True)
    monkeypatch.setattr(runner.os, "access", lambda path, flags: True)

    def unavailable(path):
        raise OSError("unavailable")

    monkeypatch.setattr(runner.shutil, "disk_usage", unavailable)
    assert runner.temp_parent() is None


@pytest.mark.parametrize("exit_code", [0, 1, 2, 5])
def test_preserves_checks_storage_settings_and_exit_code(
    runner, monkeypatch, tmp_path, exit_code
):
    monkeypatch.setattr(runner, "temp_parent", lambda: tmp_path)
    monkeypatch.setenv("TMPDIR", str(tmp_path / "upload-spooling"))
    monkeypatch.setenv("CRYPTOCAMPUS_DATABASE_URL", "sqlite:///original.db")
    original_environment = os.environ.copy()
    seen_roots = []
    args = ["-v", "--cov=app", "--cov-fail-under=80", "--junitxml=reports/junit.xml"]

    def run(command, *, env, check):
        assert command == [
            runner.sys.executable, "-m", "pytest",
            "-o", "tmp_path_retention_policy=failed", "--durations=20", *args,
        ]
        assert check is False
        root = Path(env["PYTEST_DEBUG_TEMPROOT"])
        assert root.is_dir() and root.parent == tmp_path
        assert env["TMPDIR"] == original_environment["TMPDIR"]
        assert env["CRYPTOCAMPUS_DATABASE_URL"] == "sqlite:///original.db"
        assert {k: v for k, v in env.items() if k != "PYTEST_DEBUG_TEMPROOT"} == {
            k: v for k, v in original_environment.items() if k != "PYTEST_DEBUG_TEMPROOT"
        }
        seen_roots.append(root)
        return SimpleNamespace(returncode=exit_code)

    monkeypatch.setattr(runner.subprocess, "run", run)
    assert runner.main(args) == exit_code
    assert seen_roots and not seen_roots[0].exists()
    assert os.environ == original_environment
