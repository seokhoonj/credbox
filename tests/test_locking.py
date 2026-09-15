"""Single-instance locking: one holder at a time, released on exit."""

from __future__ import annotations

import os

import pytest

from credbox.errors import InvalidAppNameError
from credbox.locking import FileLock, single_instance

posix_only = pytest.mark.skipif(os.name != "posix", reason="advisory file locks")


def test_single_instance_acquires():
    with single_instance("nw", name="poll") as acquired:
        assert acquired is True


@posix_only
def test_second_holder_is_refused_while_held():
    first = FileLock("nw", name="poll")
    assert first.acquire() is True
    try:
        second = FileLock("nw", name="poll")
        assert second.acquire() is False   # first still holds it
    finally:
        first.release()


@posix_only
def test_lock_is_reusable_after_release():
    lock = FileLock("nw", name="poll")
    assert lock.acquire() is True
    lock.release()
    again = FileLock("nw", name="poll")
    assert again.acquire() is True
    again.release()


def test_context_manager_releases():
    with FileLock("nw", name="poll") as lock:
        assert lock.acquired is True
    assert lock.acquired is False


@posix_only
def test_context_manager_raises_on_contention():
    # `with FileLock(...)` must NOT run its body when another holder has the lock -- it raises
    # LockHeldError so protected work never runs unguarded (single_instance is the skip-instead
    # API). Regression for the old __enter__ that discarded acquire()'s result and entered anyway.
    from credbox.errors import LockHeldError

    holder = FileLock("nw", name="poll")
    assert holder.acquire() is True
    try:
        with pytest.raises(LockHeldError):
            with FileLock("nw", name="poll"):
                pytest.fail("entered the block without the lock")
    finally:
        holder.release()


def test_double_release_is_a_safe_no_op():
    # release() on an already-released lock must complete quietly (not re-close a descriptor or
    # raise), leave `acquired` False, and not prevent a fresh holder from taking the lock.
    lock = FileLock("nw", name="poll")
    assert lock.acquire() is True
    lock.release()
    lock.release()   # second release: no error, no double-close
    assert lock.acquired is False
    again = FileLock("nw", name="poll")
    assert again.acquire() is True
    again.release()


def test_acquire_is_idempotent_while_held():
    lock = FileLock("nw", name="poll")
    assert lock.acquire() is True
    assert lock.acquire() is True   # still held, no error
    lock.release()


def test_lock_name_traversal_rejected():
    with pytest.raises(InvalidAppNameError):
        FileLock("nw", name="../escape")   # a crafted name must not place the .lock outside runtime_dir


def test_lock_bad_app_rejected():
    with pytest.raises(InvalidAppNameError):
        FileLock("../evil", name="poll")


def test_release_clears_state_even_when_unlock_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # If the OS unlock fails (e.g. ENOLCK on a degraded mount), release() must still mark the lock
    # not-held (closing the handle frees the OS lock regardless) and must not raise -- otherwise a
    # later acquire() would short-circuit on a stale acquired=True and report "held" without
    # re-taking the lock, silently defeating the single-instance guarantee.
    import credbox.locking as locking

    lock = FileLock("nw", name="poll")
    assert lock.acquire() is True

    def _boom(_handle: object) -> None:
        raise OSError("unlock failed on this mount")

    monkeypatch.setattr(locking, "unlock", _boom)
    lock.release()   # must not raise
    assert lock.acquired is False
    # a fresh lock can now genuinely take it (the OS lock was freed by the handle close)
    other = FileLock("nw", name="poll")
    assert other.acquire() is True
    other.release()

def test_acquire_falls_open_and_warns_when_locking_unsupported(monkeypatch, capsys):
    # On a filesystem that cannot lock (ENOLCK), the advisory single-instance lock must RUN
    # (fail open) rather than refuse forever -- return True and warn once, not False.
    from credbox import locking
    from credbox._oslock import LockOutcome

    monkeypatch.setattr(locking, "_warned_no_lock", set())   # fresh warn-once state
    monkeypatch.setattr(
        locking, "lock_exclusive", lambda handle, *, blocking: LockOutcome.UNSUPPORTED)
    lock = FileLock("nw", name="poll")
    assert lock.acquire() is True          # fell open, did not refuse
    assert lock.acquired is True
    lock.release()
    err = capsys.readouterr().err
    assert "without locking" in err and "single-instance protection is unavailable" in err


def test_single_instance_runs_when_locking_unsupported(monkeypatch, capsys):
    # The documented cron pattern (`if not acquired: return`) must not silently stop on an
    # unlockable filesystem: single_instance yields True so the job runs.
    from credbox import locking
    from credbox._oslock import LockOutcome

    monkeypatch.setattr(locking, "_warned_no_lock", set())
    monkeypatch.setattr(
        locking, "lock_exclusive", lambda handle, *, blocking: LockOutcome.UNSUPPORTED)
    with single_instance("nw", name="poll") as acquired:
        assert acquired is True   # runs, not silently skipped
    assert "single-instance protection is unavailable" in capsys.readouterr().err
