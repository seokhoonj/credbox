"""One cross-platform exclusive file-lock primitive, shared by the two callers that need it:
``locking.FileLock`` (a non-blocking single-instance guard) and the file backends (a blocking
serializer around a store's read-modify-write).

Built on ``fcntl.flock`` (POSIX) and ``msvcrt.locking`` (Windows) -- both released by the OS
automatically when the process exits, even on a crash, so there is no stale lock to clean up.

``lock_exclusive`` reports one of three ``LockOutcome`` states so a caller can tell a held lock
apart from a filesystem that cannot lock at all: ``ACQUIRED`` (the lock is now held), ``CONTENDED``
(``blocking=False`` and another holder has it), and ``UNSUPPORTED`` -- no OS primitive exists, or
the filesystem does not support locking (e.g. some NFS mounts, which report ``ENOLCK``). The
distinction matters: ``UNSUPPORTED`` must NOT be mistaken for ``CONTENDED``, or a single-instance
guard would refuse to run forever on such a mount. A caller decides its own policy per state.

The caller owns the lock file (where it lives, how it is opened); this module only takes and
releases the lock on an already-open handle.
"""

from __future__ import annotations

import errno
from enum import Enum, auto
from typing import IO

try:
    import fcntl
except ImportError:   # non-POSIX
    fcntl = None      # type: ignore[assignment]

try:
    import msvcrt
except ImportError:   # non-Windows
    msvcrt = None     # type: ignore[assignment]

__all__ = [
    "LockOutcome",
    "lock_exclusive",
    "unlock",
]


class LockOutcome(Enum):
    """The result of a ``lock_exclusive`` attempt.

    ``ACQUIRED`` -- the exclusive lock is now held. ``CONTENDED`` -- ``blocking=False`` and another
    process already holds it (do not proceed if the point was mutual exclusion). ``UNSUPPORTED`` --
    locking is unavailable on this platform/filesystem (no primitive, or ``ENOLCK``/``ENOTSUP``); a
    caller should fall open (proceed without the OS guard) rather than treat it as contended."""

    ACQUIRED = auto()
    CONTENDED = auto()
    UNSUPPORTED = auto()


# errnos that mean "this filesystem/platform cannot lock", as opposed to "another holder has it".
# ENOSYS is included so an exotic build where flock is not implemented reports UNSUPPORTED rather
# than being misread as a held lock (which would make a single-instance guard skip forever).
# EINTR is NOT here: since PEP 475 (Python 3.5) fcntl.flock auto-retries on EINTR, so an interrupted
# blocking wait does not surface as a spurious non-ACQUIRED outcome.
_UNSUPPORTED_ERRNOS = frozenset(
    {errno.ENOLCK, errno.EOPNOTSUPP, errno.ENOTSUP, errno.ENOSYS}
)


def lock_exclusive(handle: IO[str], *, blocking: bool) -> LockOutcome:
    """Take an exclusive lock on ``handle`` and report the outcome. With ``blocking=False`` return
    ``CONTENDED`` at once when another holder has it; with ``blocking=True`` wait for it. Either mode
    returns ``UNSUPPORTED`` where locking is unavailable -- no OS primitive exists, or the filesystem
    reports ``ENOLCK``/``ENOTSUP`` (e.g. some network filesystems). A caller MUST tell ``UNSUPPORTED``
    apart from ``CONTENDED`` (a real holder) rather than assume the lock was taken or is held."""
    if fcntl is not None:
        flags = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
        try:
            fcntl.flock(handle, flags)
        except OSError as err:
            return _outcome_for(err)
        return LockOutcome.ACQUIRED
    if msvcrt is not None:
        handle.seek(0)
        if not blocking:
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as err:
                return _outcome_for(err)
            return LockOutcome.ACQUIRED
        # LK_LOCK blocks only ~10s and then raises EDEADLOCK; re-issue it on that timeout so
        # ``blocking=True`` genuinely waits. Any other error is real -- give up.
        while True:
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            except OSError as err:
                if err.errno == errno.EDEADLOCK:
                    handle.seek(0)
                    continue
                return _outcome_for(err)
            return LockOutcome.ACQUIRED
    return LockOutcome.UNSUPPORTED   # neither primitive exists: locking is unavailable here


def _outcome_for(err: OSError) -> LockOutcome:
    """Map a locking ``OSError`` to ``UNSUPPORTED`` (the filesystem cannot lock) or ``CONTENDED``
    (a real holder / operation failure)."""
    return LockOutcome.UNSUPPORTED if err.errno in _UNSUPPORTED_ERRNOS else LockOutcome.CONTENDED


def unlock(handle: IO[str]) -> None:
    """Release the lock taken by ``lock_exclusive`` on ``handle``; a no-op where no OS
    primitive exists."""
    if fcntl is not None:
        fcntl.flock(handle, fcntl.LOCK_UN)
    elif msvcrt is not None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
