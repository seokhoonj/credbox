"""Tests for the zero-dep file backend: the Secret return type, idempotent unset, and the
content-free CredentialsError for a malformed store (the leak guarantee)."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from credbox.backends.file import FileBackend
from credbox.errors import CredentialsError
from credbox.secret import Secret

SECRET = "sk_live_TOPSECRET_0123456789"


def _write_keys(keys: list[str]) -> None:
    """Module-level so a forked child can run it: write each key to the shared store."""
    backend = FileBackend()
    for key in keys:
        backend.set("crossproc", key, value=f"v-{key}")


def test_concurrent_sets_from_many_threads_all_survive() -> None:
    # The store set is a read-modify-write; without serialization two threads that both read the
    # old map would each write back only their own key and the last writer would drop the other's.
    # exclusive_store_lock (a per-path thread lock + OS lock) must keep every concurrent write.
    # A barrier releases all threads at once to maximise overlap; each uses its own backend
    # instance so the per-path lock is exercised across instances, not just within one.
    count = 24
    barrier = threading.Barrier(count)

    def writer(i: int) -> None:
        barrier.wait()
        FileBackend().set("myapp", f"k{i}", value=f"v{i}")

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert FileBackend().names("myapp") == sorted(f"k{i}" for i in range(count))


def test_cross_process_writes_all_survive_under_the_os_lock() -> None:
    # The OS file lock in exclusive_store_lock exists to serialize the read-modify-write across
    # PROCESSES (the per-path thread lock only covers one process). Two forked processes each write
    # N disjoint keys to one store concurrently; with the flock all 2N survive, and disabling it
    # (blocking=False, or dropping the lock) makes their RMWs clobber each other -> keys lost.
    if os.name != "posix":
        pytest.skip("advisory file locks (fork)")
    import multiprocessing as mp

    n = 25
    child_keys = [f"c{i}" for i in range(n)]
    parent_keys = [f"p{i}" for i in range(n)]
    proc = mp.get_context("fork").Process(target=_write_keys, args=(child_keys,))
    proc.start()
    _write_keys(parent_keys)
    proc.join(timeout=30)
    assert proc.exitcode == 0
    assert set(FileBackend().names("crossproc")) == set(child_keys) | set(parent_keys)


def test_degraded_cross_process_locking_warns_once_and_still_writes(monkeypatch, capsys) -> None:
    # When the OS lock cannot be taken (a filesystem with no working flock), the write is NOT
    # failed closed -- it proceeds under the thread lock alone -- but the loss of cross-process
    # serialization is announced once per store, not silently.
    from credbox._oslock import LockOutcome
    from credbox.backends import _store
    monkeypatch.setattr(
        _store, "lock_exclusive", lambda handle, *, blocking: LockOutcome.UNSUPPORTED)
    # _warned_no_oslock is reset by the autouse conftest fixture, so no manual clear here.
    backend = FileBackend()
    backend.set("myapp", "a", value="va")
    backend.set("myapp", "b", value="vb")   # same store path -> must not warn a second time

    err = capsys.readouterr().err
    assert err.count("cross-process locking is unavailable") == 1
    got_a = backend.get("myapp", "a")
    got_b = backend.get("myapp", "b")
    assert got_a is not None and got_a.reveal() == "va"   # the write still succeeded
    assert got_b is not None and got_b.reveal() == "vb"


def test_set_then_get_returns_a_secret() -> None:
    backend = FileBackend()
    backend.set("myapp", "api_key", value=SECRET)
    got = backend.get("myapp", "api_key")
    assert isinstance(got, Secret)
    assert got.reveal() == SECRET


def test_get_absent_returns_none() -> None:
    assert FileBackend().get("myapp", "absent") is None


def test_blank_stored_value_reads_as_absent(tmp_path: Path) -> None:
    # A whitespace-only value in a hand-edited or shared store must read back as absent (None), so
    # it falls through resolution rather than resolving to a blank secret.
    backend = FileBackend()
    backend.set("myapp", "real", value="v")   # create the store dir + file
    backend.path("myapp").write_text('{"blank": "   ", "real": "v"}')
    assert backend.get("myapp", "blank") is None
    assert backend.get("myapp", "real").reveal() == "v"   # type: ignore[union-attr]


def test_set_accepts_a_secret_value() -> None:
    backend = FileBackend()
    backend.set("myapp", "api_key", value=Secret(SECRET))
    assert backend.get("myapp", "api_key").reveal() == SECRET  # type: ignore[union-attr]


def test_the_stored_file_is_mode_0600(tmp_path: Path) -> None:
    import os
    import stat

    if os.name != "posix":
        pytest.skip("POSIX mode bits only")
    backend = FileBackend()
    backend.set("myapp", "api_key", value=SECRET)
    path = backend.path("myapp")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_unset_removes_a_key() -> None:
    backend = FileBackend()
    backend.set("myapp", "api_key", value=SECRET)
    backend.unset("myapp", "api_key")
    assert backend.get("myapp", "api_key") is None


def test_unset_missing_name_is_a_noop() -> None:
    FileBackend().unset("myapp", "never_set")   # must not raise


def test_names_lists_keys_sorted_never_values() -> None:
    backend = FileBackend()
    backend.set("myapp", "b_key", value="vb")
    backend.set("myapp", "a_key", value="va")
    assert backend.names("myapp") == ["a_key", "b_key"]


def test_malformed_store_raises_content_free_error() -> None:
    backend = FileBackend()
    path = backend.path("myapp")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'{"api_key": "' + SECRET.encode() + b'" THIS IS NOT JSON')
    with pytest.raises(CredentialsError) as excinfo:
        backend.get("myapp", "api_key")
    err = excinfo.value
    assert SECRET not in str(err)
    assert err.__cause__ is None
    assert err.__context__ is None


def test_non_string_value_in_store_raises_and_does_not_reach_secret() -> None:
    backend = FileBackend()
    path = backend.path("myapp")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'{"api_key": {"nested": 1}}')
    with pytest.raises(CredentialsError):
        backend.get("myapp", "api_key")
