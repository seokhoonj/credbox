"""Atomic file writes: write a temp file in the target directory, fsync it, rename it over
the target, then fsync the directory.

A rename on the same filesystem is atomic, so a crash or a concurrent reader never sees a
half-written file, and the fsync before the rename means a crash *after* the rename cannot
leave the target pointing at unflushed bytes. Fsyncing the *directory* after the rename makes
the rename itself durable: the file's own fsync flushes its contents, but the new directory
entry is separate metadata, so without this a crash right after ``os.replace`` could lose the
rename and leave the old file (or none) in place. The temp file is created 0600 by
``mkstemp`` and its mode is set explicitly before the rename, so a secret is never briefly
world-readable between create and ``chmod``. Two overlapping writers get distinct temp paths,
so neither corrupts the other.
"""

from __future__ import annotations

import contextlib
import errno
import os
import tempfile
import time
from pathlib import Path

from credbox.errors import CredBoxError

__all__ = [
    "write_bytes_atomic",
    "write_text_atomic",
]

# Windows os.replace fails with PermissionError while another process has the target open (the CRT
# opens without FILE_SHARE_DELETE); readers deliberately hold no lock, so a get() overlapping a
# write() would otherwise spuriously fail the write. Retry a few times with a short backoff there.
# On POSIX, rename over an open file is fine, so no retry runs (the loop body succeeds first try).
_REPLACE_RETRIES = 10
_REPLACE_BACKOFF_SECONDS = 0.02

# errnos meaning "this platform/filesystem cannot fsync a directory" -- only these are
# ignored. Real durability failures (EIO, ENOSPC) are not here, so they propagate rather
# than let a non-durable rename be reported as a completed write.
_UNSUPPORTED_DIR_FSYNC_ERRNOS = frozenset({errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP})

# Only POSIX exposes a directory fsync; Windows opening a directory as a fd fails outright,
# so the directory sync is skipped there. Read once at import (os.name does not change at
# runtime) so a test can flip it without mutating the shared os module globally.
_IS_POSIX = os.name == "posix"


def write_bytes_atomic(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` atomically, leaving it mode ``mode`` (0600 by default, the
    right mode for a secret) on POSIX. On Windows, which has no POSIX mode bits, ``mode`` is
    not applied and access follows the parent directory's ACL. Creates the parent directory
    if needed.

    Raises:
        CredBoxError: the write could not be completed durably. Either it failed at or before
            the atomic rename -- ``path`` is then untouched and its temp file is removed
            (best-effort; a debris ``.tmp`` can survive only if the cleanup unlink itself also
            fails) -- or the bytes were atomically put in place but the post-rename directory
            sync hit a real I/O error, in which case ``path`` already holds the new content
            though its durability across a crash is not guaranteed. The file is never left
            partially written.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
        temp_path = Path(temp_name)
        try:
            try:
                handle = os.fdopen(fd, "wb")
            except OSError:
                os.close(fd)   # fdopen did not adopt the descriptor -- close it ourselves
                raise
            with handle:
                if hasattr(os, "fchmod"):
                    os.fchmod(handle.fileno(), mode)   # POSIX: pin the mode before any bytes land
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())   # durable before the rename
            _replace(temp_path, path)
            _fsync_dir(path.parent)         # make the rename itself durable
        except BaseException:
            # Catch BaseException, not just OSError: a KeyboardInterrupt (Ctrl-C at the no-echo
            # `set` prompt) or MemoryError raised mid-write must still remove the temp file, which
            # for the plaintext FileBackend holds the secret store. The bare `raise` re-propagates
            # unchanged -- a genuine OSError still falls through to the wrapping handler below;
            # an interrupt/OOM propagates raw rather than being disguised as a write failure.
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass   # cleanup is best-effort; never mask the original failure being re-raised
            raise
    except OSError as err:
        raise CredBoxError(f"could not write {path}: {err}") from err


def write_text_atomic(path: Path, text: str, *, mode: int = 0o600) -> None:
    """Write ``text`` (UTF-8) to ``path`` atomically, leaving it mode ``mode``.

    Raises:
        UnicodeEncodeError: ``text`` is not encodable as UTF-8 (e.g. a lone surrogate). Raised
            before any filesystem operation -- a non-encodable ``text`` is a caller error, not
            a write failure, so it is not wrapped and ``path`` is left untouched. NOTE: this
            exception's ``.object`` is the full ``text``; do NOT route a secret value through
            this helper -- the secret store writes ciphertext/JSON bytes via ``write_bytes_atomic``
            (which cannot raise this), keeping the raw value off any traceback.
        CredBoxError: the write could not be completed durably (propagated from
            ``write_bytes_atomic`` -- see its ``Raises`` for the atomic-vs-durable
            distinction on the target's state).
    """
    write_bytes_atomic(path, text.encode("utf-8"), mode=mode)


def _replace(temp_path: Path, path: Path) -> None:
    """``os.replace`` (atomic on both POSIX and Windows), retrying on Windows only when the target
    is momentarily held open by a concurrent reader (``PermissionError``). On POSIX the first call
    succeeds -- rename over an open file is fine -- so no retry runs. The final attempt is outside
    the retry guard, so a persistent failure still raises."""
    if _IS_POSIX:
        os.replace(temp_path, path)
        return
    for _attempt in range(_REPLACE_RETRIES):
        try:
            os.replace(temp_path, path)
            return
        except PermissionError:
            time.sleep(_REPLACE_BACKOFF_SECONDS)   # a reader has the target open; let it close
    os.replace(temp_path, path)   # last try: raise if it is still held


def _fsync_dir(directory: Path) -> None:
    """Fsync ``directory`` so a rename into it survives a crash.

    Only a *structural* inability to sync is tolerated; a real error is surfaced -- and the
    same rule governs both opening the directory and the fsync, so the two cannot disagree. A
    non-POSIX platform (Windows has no directory fsync) is skipped, and a filesystem that
    reports the operation unsupported (``EINVAL`` / ``ENOTSUP`` / ``EOPNOTSUPP``) is ignored:
    there the platform offers no stronger guarantee than the already-completed rename. Every
    other error -- a real I/O failure (``EIO``, ``ENOSPC``), resource exhaustion (``EMFILE``),
    or a permission/shape problem opening the directory -- propagates, so a write is never
    reported durable when the sync genuinely failed. The rename's atomicity is unaffected
    either way: the file is fully in place before this runs."""
    if not _IS_POSIX:
        return   # only POSIX exposes a directory fsync; elsewhere durability is the filesystem's job
    try:
        dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as err:
        if err.errno in _UNSUPPORTED_DIR_FSYNC_ERRNOS:
            return   # the filesystem cannot open a directory for fsync -- no stronger guarantee
        raise        # a real open failure (EIO, EMFILE, EACCES) must not pass as a durable write
    try:
        os.fsync(dir_fd)
    except OSError as err:
        if err.errno not in _UNSUPPORTED_DIR_FSYNC_ERRNOS:
            raise
    finally:
        with contextlib.suppress(OSError):   # a close error must not mask a propagating fsync error
            os.close(dir_fd)
