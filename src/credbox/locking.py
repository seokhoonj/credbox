"""A best-effort single-instance lock, so two runs of the same job do not overlap.

Overlapping runs -- a cron job and a manual one, or two crons -- can double-spend a paid API,
deliver duplicates, and race on shared state. A ``FileLock`` holds an exclusive advisory lock
on a file in ``runtime_dir(app)`` (where the XDG spec says locks belong) for as long as it is
held, and reports whether it was acquired, so a caller can skip a run already in progress
rather than pile on.

Built on ``fcntl.flock`` (POSIX) and ``msvcrt.locking`` (Windows) via ``_oslock`` -- both
released by the OS automatically when the process exits, even on a crash, so there is no stale
lock to clean up. On a platform with neither, it is a no-op that always acquires.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO

from credbox._oslock import LockOutcome, lock_exclusive, unlock
from credbox.errors import CredBoxError, LockHeldError
from credbox.paths import app_dir_segment
from credbox.runtime import runtime_dir

_warned_no_lock: set[str] = set()
_warn_no_lock_guard = threading.Lock()


def _warn_no_lock_once(path: Path) -> None:
    """Warn once per lock path that this filesystem cannot lock, so single-instance protection is
    unavailable and the job is running without a cross-process guard. Content-free (names the lock
    path only). Advisory locks fall open here rather than refuse to run -- see ``FileLock.acquire``."""
    key = str(path)
    if key in _warned_no_lock:
        return
    with _warn_no_lock_guard:
        if key in _warned_no_lock:
            return
        _warned_no_lock.add(key)
    print(
        f"credbox: warning: {path} is on a filesystem without locking; single-instance "
        f"protection is unavailable and this run proceeds without a cross-process guard",
        file=sys.stderr,
    )

__all__ = [
    "FileLock",
    "single_instance",
]


class FileLock:
    """An exclusive, non-blocking advisory lock named ``name`` for ``app``, held on a file in
    ``runtime_dir(app)``.

    Two ways to use it, with DIFFERENT contention semantics:
    - ``acquire()`` / ``release()`` explicitly, reading the ``acquired`` result to decide whether
      to proceed; or
    - as a context manager, which raises ``LockHeldError`` if another process holds it -- so the
      ``with`` body never runs unguarded. When the intent is to *skip* a contended run rather than
      error, use ``single_instance(app, name=...)``, which yields ``False`` instead of raising.

    Re-acquiring or releasing when not held is safe."""

    def __init__(self, app: str, *, name: str) -> None:
        """Bind to an ``app`` and a lock ``name``. Both are validated as safe path segments
        here (fail-fast), so a crafted ``name`` such as ``"../escape"`` cannot place the
        ``.lock`` file outside the runtime directory. ``name`` is keyword-only so it cannot be
        transposed with ``app`` (two same-type strings) into a lock on the wrong path.

        Raises:
            InvalidAppNameError: ``app`` or ``name`` is not a valid directory segment.
        """
        self._app = app_dir_segment(app)
        self._name = app_dir_segment(name)
        self._handle: IO[str] | None = None

    @property
    def acquired(self) -> bool:
        """Whether this lock is currently held. Derived from the open handle -- the single source
        of truth -- so it cannot be set to a value the handle contradicts."""
        return self._handle is not None

    def __repr__(self) -> str:
        return f"FileLock(app={self._app!r}, name={self._name!r}, acquired={self.acquired})"

    def acquire(self) -> bool:
        """Try to take the lock without blocking. Returns ``True`` if taken; ``False`` ONLY when
        another process genuinely holds it (so the caller should skip its run). Idempotent while held.

        On a filesystem that cannot lock (e.g. some NFS mounts, which report ``ENOLCK``), a
        single-instance lock is advisory, so this falls OPEN: it returns ``True`` and runs without a
        cross-process guard, warning once -- rather than refuse to run forever by misreading the
        missing lock as a held one. Two concurrent runs are then possible on such a mount.

        Raises:
            CredBoxError: the lock file could not be opened, or (propagated from
                ``runtime_dir``) the runtime directory could not be created.
            InsecureStorageError: the runtime directory exists but is unsafe (propagated from
                ``runtime_dir``).
        """
        if self.acquired:
            return True
        path = runtime_dir(self._app) / f"{self._name}.lock"
        try:
            handle = path.open("a+")   # a+ suits both flock and msvcrt; never truncates a holder's file
        except OSError as err:
            raise CredBoxError(f"could not open lock file {path}: {err}") from err
        outcome = lock_exclusive(handle, blocking=False)
        if outcome is LockOutcome.CONTENDED:
            handle.close()
            return False   # another process genuinely holds it -- skip this run
        if outcome is LockOutcome.UNSUPPORTED:
            _warn_no_lock_once(path)   # advisory: run anyway, without a cross-process guard
        self._handle = handle          # ACQUIRED, or UNSUPPORTED-and-running-anyway
        return True

    def release(self) -> None:
        """Release the lock and close its file. A no-op when not held. Best-effort and never
        raises: closing the handle frees the OS lock regardless, so a failing ``unlock`` (e.g.
        ENOLCK on a degraded mount) is swallowed. ``self._handle`` is cleared FIRST so ``acquired``
        (derived from it) never reports "held" over a handle that is already being released."""
        handle = self._handle
        self._handle = None
        if handle is not None:
            try:
                unlock(handle)
            except OSError:
                pass   # best-effort: the handle close below frees the OS lock anyway
            finally:
                handle.close()

    def __enter__(self) -> FileLock:
        """Take the lock for the ``with`` block, or raise ``LockHeldError`` if another process
        holds it -- so the body never runs without the lock. Use ``single_instance`` to skip
        (yield ``False``) instead of raising."""
        if not self.acquire():
            raise LockHeldError(
                f"another process holds the lock {self._name!r} for {self._app!r}"
            )
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


@contextmanager
def single_instance(app: str, *, name: str) -> Iterator[bool]:
    """Hold a ``FileLock`` for the block and yield whether it was acquired -- ``True`` to
    proceed, ``False`` when another process already holds it (the caller should skip its run).
    Convenience over ``FileLock``; unlike ``with FileLock(...)`` it does NOT raise on contention,
    so the caller decides what to do. ``name`` is keyword-only so it cannot be transposed with
    ``app``.

    Raises:
        InvalidAppNameError: ``app`` or ``name`` is not a valid directory segment.
        CredBoxError / InsecureStorageError: propagated from ``runtime_dir``.
    """
    lock = FileLock(app, name=name)
    acquired = lock.acquire()
    try:
        yield acquired
    finally:
        lock.release()
