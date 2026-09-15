"""Shared internals for the file-based backends: value normalization and the cross-process store
lock. Lives in its own module so ``file``, ``keyring``, and ``encrypted`` all import it from one
private home rather than reaching into each other.

A file store's set/unset is a read-modify-write: load the JSON, change one key, write it back. The
atomic write guards against a *torn* file, not a lost *update* -- two writers that both read the
old map each write back their own change, and the last one wins, dropping the other's key. So the
whole critical section is held under a lock that serializes across threads (a per-path
``threading.Lock``) and processes (a blocking OS lock on a sibling ``.lock`` file, which -- unlike
the store file -- is never replaced, so an atomic rename cannot orphan a holder's lock). Where the
OS lock cannot be taken, it degrades to the thread lock alone.
"""

from __future__ import annotations

import sys
import threading
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO

from credbox._oslock import LockOutcome, lock_exclusive, unlock
from credbox.permissions import restrict_dir_to_owner

__all__ = ["normalize_secret_value", "exclusive_store_lock", "CREDENTIALS_FILE", "ENCRYPTED_FILE"]

# The on-disk store file names, one per file-based backend. Defined here -- the crypto-free shared
# home -- so a caller that only needs to LOCATE a store (e.g. the CLI `doctor` sweep) can name the
# encrypted store without importing the [crypto]-gated `encrypted` module.
CREDENTIALS_FILE = "credentials.json"   # file backend (plaintext)
ENCRYPTED_FILE = "credentials.enc"      # encrypted backend ([crypto])


def normalize_secret_value(value: object) -> str | None:
    """A stored value normalised to a non-empty string, or ``None`` -- so a blank entry reads as
    absent and falls through to the next resolution tier."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


# One lock per distinct store path, created on first use. A WeakValueDictionary bounds the registry
# by the set of stores *currently* being touched rather than by every path ever seen: a held lock
# stays alive via the caller's strong reference (see exclusive_store_lock), and an idle one is
# collected -- so a long-lived process cycling through many app names does not leak a lock per name.
_thread_lock_by_store_path: weakref.WeakValueDictionary[str, threading.Lock] = (
    weakref.WeakValueDictionary()
)
_thread_lock_registry_guard = threading.Lock()

# Paths for which we have already warned that cross-process locking is unavailable, so the notice
# is printed at most once per store rather than on every degraded write.
_warned_no_oslock: set[str] = set()
_warn_lock = threading.Lock()


def _warn_no_oslock_once(path: Path) -> None:
    """Warn once, on stderr, that the OS lock could not be taken for ``path`` so writes are
    serialized only within this process. Content-free: a store path is not a secret value. Not
    fail-closed -- a filesystem with no working lock (some network mounts) must stay usable; the
    single-process guarantee still holds and concurrent multi-process writes are the rare case."""
    key = str(path)
    with _warn_lock:
        if key in _warned_no_oslock:
            return
        _warned_no_oslock.add(key)
    print(
        f"credbox: warning: cross-process locking is unavailable for {path}; concurrent writes "
        "from other processes may not be serialized (writes within this process still are)",
        file=sys.stderr,
    )


def _thread_lock_for(store_path: str) -> threading.Lock:
    """The process-wide lock for the store at ``store_path``, created on first use."""
    with _thread_lock_registry_guard:
        lock = _thread_lock_by_store_path.get(store_path)
        if lock is None:
            lock = threading.Lock()
            _thread_lock_by_store_path[store_path] = lock
        return lock


@contextmanager
def exclusive_store_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive lock over a read-modify-write of the store file ``path``. Degrades to
    thread-only serialization where no OS lock primitive exists, the lock file cannot be created,
    or the OS lock cannot be taken -- the in-process guarantee still holds, and the degradation is
    announced once per store on stderr rather than passing silently. Shared by the file and
    encrypted backends for code reuse; each serializes concurrent writers to its OWN store file
    (they lock distinct ``.lock`` paths, so a file write and an encrypted write do not serialize
    against each other -- each backend owns a separate store)."""
    thread_lock = _thread_lock_for(str(path))   # a strong ref for the duration of the critical section
    thread_lock.acquire()
    try:
        restrict_dir_to_owner(path.parent)
        try:
            handle: IO[str] | None = (path.parent / f"{path.name}.lock").open("a+")
        except OSError:
            handle = None   # cannot create the lock file: rely on the thread lock alone
        locked = False
        try:
            outcome = lock_exclusive(handle, blocking=True) if handle is not None else None
            if outcome is not LockOutcome.ACQUIRED:
                # No OS lock taken (unavailable filesystem, or the lock file could not be created):
                # degrade to thread-only serialization, surface it once -- never fail closed.
                _warn_no_oslock_once(path)
            yield
        finally:
            if handle is not None:
                try:
                    if locked:
                        unlock(handle)
                finally:
                    handle.close()
    finally:
        thread_lock.release()
