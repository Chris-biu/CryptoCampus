from __future__ import annotations

import threading
import time
import pytest

from app.crypto.locks import ProviderOperationLock, ProviderLockError


def test_provider_lock_read_concurrent() -> None:
    lock = ProviderOperationLock()
    results = []

    def reader(idx: int) -> None:
        with lock.reader_lock(timeout=1.0):
            results.append(f"start_{idx}")
            time.sleep(0.05)
            results.append(f"end_{idx}")

    t1 = threading.Thread(target=reader, args=(1,))
    t2 = threading.Thread(target=reader, args=(2,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Both readers should be able to run concurrently (both starts before both ends)
    assert len(results) == 4
    assert "start_1" in results and "start_2" in results


def test_provider_lock_writer_exclusive() -> None:
    lock = ProviderOperationLock()
    events = []

    def writer() -> None:
        with lock.writer_lock(timeout=1.0):
            events.append("writer_start")
            time.sleep(0.08)
            events.append("writer_end")

    def reader() -> None:
        time.sleep(0.02)
        with lock.reader_lock(timeout=1.0):
            events.append("reader_inside")

    tw = threading.Thread(target=writer)
    tr = threading.Thread(target=reader)
    tw.start()
    tr.start()
    tw.join()
    tr.join()

    # Reader cannot enter while writer is holding lock
    assert events == ["writer_start", "writer_end", "reader_inside"]


def test_provider_lock_timeout() -> None:
    lock = ProviderOperationLock()

    # Hold writer lock
    with lock.writer_lock(timeout=1.0):
        # Trying to acquire reader lock with 0.05s timeout must raise ProviderLockError
        with pytest.raises(ProviderLockError, match="lock_timeout"):
            with lock.reader_lock(timeout=0.05):
                pass
