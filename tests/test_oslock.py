"""The cross-platform exclusive file-lock primitive: it excludes a second holder, waits
when told to block, and reports UNSUPPORTED where the platform/filesystem offers no lock."""

from __future__ import annotations

import os

import pytest

from credbox import _oslock
from credbox._oslock import LockOutcome, lock_exclusive, unlock

posix_only = pytest.mark.skipif(os.name != "posix", reason="advisory file locks")


@posix_only
def test_non_blocking_second_holder_refused(tmp_path):
    path = tmp_path / "x.lock"
    first = path.open("a+")
    second = path.open("a+")
    try:
        assert lock_exclusive(first, blocking=False) is LockOutcome.ACQUIRED
        assert lock_exclusive(second, blocking=False) is LockOutcome.CONTENDED   # first still holds it
        unlock(first)
        assert lock_exclusive(second, blocking=False) is LockOutcome.ACQUIRED    # free now
        unlock(second)
    finally:
        first.close()
        second.close()


@posix_only
def test_blocking_acquires_when_free(tmp_path):
    """An uncontended blocking acquire returns held at once (does not exercise the wait)."""
    path = tmp_path / "x.lock"
    first = path.open("a+")
    second = path.open("a+")
    try:
        assert lock_exclusive(first, blocking=True) is LockOutcome.ACQUIRED
        unlock(first)
        assert lock_exclusive(second, blocking=True) is LockOutcome.ACQUIRED
        unlock(second)
    finally:
        first.close()
        second.close()


@posix_only
def test_blocking_waits_until_holder_releases(tmp_path):
    """blocking=True must genuinely WAIT for a foreign holder, not return False: while a
    child process holds the lock the parent's blocking acquire stays pending, and completes
    only once the child releases."""
    import multiprocessing as mp
    import threading

    path = tmp_path / "x.lock"
    ctx = mp.get_context("fork")
    holding = ctx.Event()   # set once the child holds the lock
    release = ctx.Event()   # parent asks the child to let go

    def child() -> None:
        handle = path.open("a+")
        lock_exclusive(handle, blocking=False)
        holding.set()
        release.wait(timeout=10)
        unlock(handle)
        handle.close()

    proc = ctx.Process(target=child)
    proc.start()
    try:
        assert holding.wait(timeout=5)   # child now holds the lock
        parent = path.open("a+")
        acquired = threading.Event()
        outcome: dict[str, bool] = {}

        def block() -> None:
            lock_exclusive(parent, blocking=True)   # must wait here while the child holds it
            # The child unlocks ONLY after `release` is set, and we can acquire only after that
            # unlock -- so if the blocking acquire genuinely waited, `release` is already set the
            # instant it returns. This is a deterministic ordering proof, not a wall-clock race.
            outcome["release_was_set_on_acquire"] = release.is_set()
            acquired.set()

        waiter = threading.Thread(target=block)
        waiter.start()
        release.set()                     # let the child release; only then can the waiter acquire
        assert acquired.wait(timeout=5)   # generous: guards against a hang, not a scheduling race
        assert outcome["release_was_set_on_acquire"] is True   # proof it did not acquire early
        waiter.join()
        unlock(parent)
        parent.close()
    finally:
        release.set()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.terminate()
            proc.join()


def test_windows_blocking_retries_on_deadlock_timeout(monkeypatch, tmp_path):
    """The Windows path: msvcrt.locking(LK_LOCK) raises EDEADLOCK after its bounded wait, so
    lock_exclusive must re-issue it until it succeeds -- that is what makes blocking=True a
    real wait rather than a one-shot that gives up at ~10s."""
    import errno

    calls = {"n": 0}

    class FakeMsvcrt:
        LK_LOCK = 0
        LK_NBLCK = 1
        LK_UNLCK = 2

        def locking(self, fileno: int, mode: int, nbytes: int) -> None:
            calls["n"] += 1
            if calls["n"] < 3:
                raise OSError(errno.EDEADLOCK, "lock timed out")   # two timeouts, then held
            return None

    monkeypatch.setattr(_oslock, "fcntl", None)
    monkeypatch.setattr(_oslock, "msvcrt", FakeMsvcrt())
    handle = (tmp_path / "x.lock").open("a+")
    try:
        assert lock_exclusive(handle, blocking=True) is LockOutcome.ACQUIRED
        assert calls["n"] == 3   # retried through both timeouts before acquiring
    finally:
        handle.close()


def test_windows_blocking_gives_up_on_non_timeout_error(monkeypatch, tmp_path):
    """A non-timeout error (e.g. EACCES) is real: do NOT retry, report CONTENDED so blocking does
    not silently spin on a permanent failure (EACCES is not an 'unsupported filesystem' errno)."""
    import errno

    class FakeMsvcrt:
        LK_LOCK = 0
        LK_NBLCK = 1
        LK_UNLCK = 2

        def locking(self, fileno: int, mode: int, nbytes: int) -> None:
            raise OSError(errno.EACCES, "permission denied")

    monkeypatch.setattr(_oslock, "fcntl", None)
    monkeypatch.setattr(_oslock, "msvcrt", FakeMsvcrt())
    handle = (tmp_path / "x.lock").open("a+")
    try:
        assert lock_exclusive(handle, blocking=True) is LockOutcome.CONTENDED
    finally:
        handle.close()


def test_no_primitive_platform_reports_unsupported(monkeypatch, tmp_path):
    """Where neither fcntl nor msvcrt exists, lock_exclusive reports UNSUPPORTED (not ACQUIRED) so
    a caller can fall open -- run without an OS guard, warning once -- rather than mistake the
    missing lock for a held one."""
    monkeypatch.setattr(_oslock, "fcntl", None)
    monkeypatch.setattr(_oslock, "msvcrt", None)
    handle = (tmp_path / "x.lock").open("a+")
    try:
        assert lock_exclusive(handle, blocking=False) is LockOutcome.UNSUPPORTED
        assert lock_exclusive(handle, blocking=True) is LockOutcome.UNSUPPORTED
        unlock(handle)   # no-op, must not raise
    finally:
        handle.close()


@pytest.mark.parametrize("code", ["ENOLCK", "EOPNOTSUPP", "ENOTSUP", "ENOSYS"])
def test_unsupported_filesystem_errnos_report_unsupported(monkeypatch, tmp_path, code):
    """The core fix: a filesystem that cannot lock (POSIX flock -> ENOLCK/EOPNOTSUPP/ENOTSUP/ENOSYS,
    as on some NFS mounts or an exotic build) must report UNSUPPORTED, distinct from CONTENDED, so a
    single-instance guard does not misread it as 'held' and refuse to run forever. Every member of
    _UNSUPPORTED_ERRNOS is exercised; on Linux ENOTSUP == EOPNOTSUPP (a harmless duplicate here),
    but off-Linux (macOS/BSD) ENOTSUP is a distinct value, so listing it gives real coverage there."""
    import errno as _errno

    errnum = getattr(_errno, code)

    class FakeFcntl:
        LOCK_EX = 2
        LOCK_NB = 4
        LOCK_UN = 8

        def flock(self, handle, flags):
            raise OSError(errnum, "cannot lock")

    monkeypatch.setattr(_oslock, "fcntl", FakeFcntl())
    handle = (tmp_path / "x.lock").open("a+")
    try:
        assert lock_exclusive(handle, blocking=False) is LockOutcome.UNSUPPORTED
        assert lock_exclusive(handle, blocking=True) is LockOutcome.UNSUPPORTED
    finally:
        handle.close()


def test_windows_non_blocking_maps_a_lock_error_to_contended(monkeypatch, tmp_path):
    """The msvcrt non-blocking branch: a lock error (EACCES, not an 'unsupported' errno) is
    CONTENDED, so a caller skips rather than falls open."""
    import errno as _errno

    class FakeMsvcrt:
        LK_LOCK = 0
        LK_NBLCK = 1
        LK_UNLCK = 2

        def locking(self, fileno, mode, nbytes):
            raise OSError(_errno.EACCES, "permission denied")

    monkeypatch.setattr(_oslock, "fcntl", None)
    monkeypatch.setattr(_oslock, "msvcrt", FakeMsvcrt())
    handle = (tmp_path / "x.lock").open("a+")
    try:
        assert lock_exclusive(handle, blocking=False) is LockOutcome.CONTENDED
    finally:
        handle.close()
