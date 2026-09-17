from __future__ import annotations

from contextlib import contextmanager
import threading
import time
from typing import Generator


class ProviderLockError(Exception):
    """Exception raised when Provider lock acquisition fails or times out."""
    pass


class ProviderOperationLock:
    """
    Reader-Writer lock for coordinating Benchmark operations and Provider reload.
    - Readers (Benchmarks, normal operations): shared access.
    - Writers (Provider reload): exclusive access.
    """
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._readers_count = 0
        self._writer_active = False
        self._waiting_writers = 0

    @contextmanager
    def reader_lock(self, timeout: float | None = 10.0) -> Generator[None, None, None]:
        deadline = time.monotonic() + timeout if timeout is not None else None
        with self._cond:
            while self._writer_active or self._waiting_writers > 0:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not self._cond.wait(remaining):
                        raise ProviderLockError("lock_timeout")
                else:
                    self._cond.wait()
            self._readers_count += 1

        try:
            yield
        finally:
            with self._cond:
                self._readers_count -= 1
                if self._readers_count == 0:
                    self._cond.notify_all()

    @contextmanager
    def writer_lock(self, timeout: float | None = 10.0) -> Generator[None, None, None]:
        deadline = time.monotonic() + timeout if timeout is not None else None
        with self._cond:
            self._waiting_writers += 1
            try:
                while self._writer_active or self._readers_count > 0:
                    if deadline is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not self._cond.wait(remaining):
                            raise ProviderLockError("lock_timeout")
                    else:
                        self._cond.wait()
                self._writer_active = True
            finally:
                self._waiting_writers -= 1

        try:
            yield
        finally:
            with self._cond:
                self._writer_active = False
                self._cond.notify_all()


# Process-wide singleton lock
provider_operation_lock = ProviderOperationLock()
