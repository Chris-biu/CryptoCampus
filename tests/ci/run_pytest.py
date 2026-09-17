"""Run unchanged pytest checks with isolated, fast temporary database files.

Only pytest's tmp_path tree moves to tmpfs. TMPDIR, upload spooling, production
database settings, SQLite pragmas, test selection and assertions stay unchanged.
Reports and coverage remain at the paths supplied by the caller, outside tmpfs.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


MIN_FREE_BYTES = 32 * 1024 * 1024


def temp_parent() -> Path | None:
    candidate = Path("/dev/shm")
    try:
        if (
            sys.platform == "linux"
            and candidate.is_dir()
            and os.access(candidate, os.W_OK | os.X_OK)
            and shutil.disk_usage(candidate).free >= MIN_FREE_BYTES
        ):
            return candidate
    except OSError:
        pass
    return None


def main(args: list[str] | None = None) -> int:
    pytest_args = sys.argv[1:] if args is None else args
    parent = temp_parent()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cryptocampus-pytest-", dir=parent) as root:
        environment = os.environ.copy()
        environment["PYTEST_DEBUG_TEMPROOT"] = root
        print(
            "[pytest workspace] "
            + ("/dev/shm" if parent is not None else "disk fallback")
            + "; successful tmp_path directories are released after each test",
            flush=True,
        )
        result = subprocess.run(
            [
                sys.executable, "-m", "pytest",
                "-o", "tmp_path_retention_policy=failed", "--durations=20",
                *pytest_args,
            ],
            env=environment,
            check=False,
        )
    print(
        f"[pytest workspace] exit={result.returncode} "
        f"elapsed={time.monotonic() - started:.2f}s",
        flush=True,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
