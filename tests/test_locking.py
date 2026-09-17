"""Single-instance locking: one holder at a time, released on exit."""

from __future__ import annotations

import os
import warnings

import pytest

from credbox.errors import InvalidAppNameError
from credbox.locking import FileLock, single_instance

posix_only = pytest.mark.skipif(os.name != "posix", reason="advisory file locks")


def test_single_instance_acquires():
    with single_instance("myapp", name="poll") as acquired:
        assert acquired is True


@posix_only
def test_second_holder_is_refused_while_held():
    first = FileLock("myapp", name="poll")
    assert first.acquire() is True
    try:
        second = FileLock("myapp", name="poll")
        assert second.acquire() is False   # first still holds it
    finally:
        first.release()


@posix_only
def test_lock_is_reusable_after_release():
    lock = FileLock("myapp", name="poll")
    assert lock.acquire() is True
    lock.release()
    again = FileLock("myapp", name="poll")
    assert again.acquire() is True
    again.release()


def test_context_manager_releases():
    with FileLock("myapp", name="poll") as lock:
        assert lock.acquired is True
    assert lock.acquired is False


@posix_only
def test_context_manager_raises_on_contention():
    # `with FileLock(...)` must NOT run its body when another holder has the lock -- it raises
    # LockHeldError so protected work never runs unguarded (single_instance is the skip-instead
    # API). Regression for the old __enter__ that discarded acquire()'s result and entered anyway.
    from credbox.errors import LockHeldError

    holder = FileLock("myapp", name="poll")
    assert holder.acquire() is True
    try:
        with pytest.raises(LockHeldError):
            with FileLock("myapp", name="poll"):
                pytest.fail("entered the block without the lock")
    finally:
        holder.release()


def test_double_release_is_a_safe_no_op():
    # release() on an already-released lock must complete quietly (not re-close a descriptor or
    # raise), leave `acquired` False, and not prevent a fresh holder from taking the lock.
    lock = FileLock("myapp", name="poll")
    assert lock.acquire() is True
    lock.release()
    lock.release()   # second release: no error, no double-close
    assert lock.acquired is False
    again = FileLock("myapp", name="poll")
    assert again.acquire() is True
    again.release()


def test_acquire_is_idempotent_while_held():
    lock = FileLock("myapp", name="poll")
    assert lock.acquire() is True
    assert lock.acquire() is True   # still held, no error
    lock.release()


def test_lock_name_traversal_rejected():
    with pytest.raises(InvalidAppNameError):
        FileLock("myapp", name="../escape")   # a crafted name must not place the .lock outside runtime_dir


def test_lock_bad_app_rejected():
    with pytest.raises(InvalidAppNameError):
        FileLock("../evil", name="poll")


def test_release_clears_state_even_when_unlock_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # If the OS unlock fails (e.g. ENOLCK on a degraded mount), release() must still mark the lock
    # not-held (closing the handle frees the OS lock regardless) and must not raise -- otherwise a
    # later acquire() would short-circuit on a stale acquired=True and report "held" without
    # re-taking the lock, silently defeating the single-instance guarantee.
    import credbox.locking as locking

    lock = FileLock("myapp", name="poll")
    assert lock.acquire() is True

    def _boom(_handle: object) -> None:
        raise OSError("unlock failed on this mount")

    monkeypatch.setattr(locking, "unlock", _boom)
    lock.release()   # must not raise
    assert lock.acquired is False
    # a fresh lock can now genuinely take it (the OS lock was freed by the handle close)
    other = FileLock("myapp", name="poll")
    assert other.acquire() is True
    other.release()

def _force_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make lock_exclusive report UNSUPPORTED, as an unlockable filesystem (ENOLCK) would."""
    import credbox.locking as locking
    from credbox._oslock import LockOutcome

    monkeypatch.setattr(
        locking, "lock_exclusive", lambda handle, *, blocking: LockOutcome.UNSUPPORTED)


def test_acquire_falls_open_and_warns_when_locking_unsupported(monkeypatch):
    # On a filesystem that cannot lock (ENOLCK), the advisory lock must RUN (fail open) rather than
    # refuse forever: return True, set lock_unavailable, and issue a UserWarning -- not return False.
    _force_unsupported(monkeypatch)
    lock = FileLock("myapp", name="poll")
    with pytest.warns(UserWarning, match="without locking"):
        assert lock.acquire() is True          # fell open, did not refuse
    assert lock.acquired is True
    assert lock.lock_unavailable is True       # observable: ran without a real OS lock
    lock.release()


def test_single_instance_runs_when_locking_unsupported(monkeypatch):
    # The documented cron pattern (`if not acquired: return`) must not silently stop on an
    # unlockable filesystem: single_instance yields True so the job runs.
    _force_unsupported(monkeypatch)
    with pytest.warns(UserWarning, match="single-instance protection"):
        with single_instance("myapp", name="poll") as acquired:
            assert acquired is True   # runs, not silently skipped


def test_require_lock_fails_closed_on_unlockable_filesystem(monkeypatch):
    # A strict caller opts into no-run-over-double-run: require_lock=True raises a DISTINCT
    # LockUnavailableError (never LockHeldError) instead of falling open.
    from credbox.errors import LockHeldError, LockUnavailableError

    _force_unsupported(monkeypatch)
    strict = FileLock("myapp", name="poll", require_lock=True)
    with pytest.raises(LockUnavailableError) as excinfo:
        strict.acquire()
    assert not isinstance(excinfo.value, LockHeldError)   # distinct from contention
    assert strict.acquired is False            # failed closed: nothing held
    assert strict.lock_unavailable is False    # and nothing ran unguarded

    with pytest.raises(LockUnavailableError):
        with single_instance("myapp", name="poll", require_lock=True):
            pass


def test_lock_unavailable_is_false_for_a_real_lock():
    # A genuinely-acquired lock did NOT fall open.
    lock = FileLock("myapp", name="poll")
    assert lock.acquire() is True
    assert lock.lock_unavailable is False
    lock.release()


def test_lock_unavailable_resets_on_a_later_real_acquire(monkeypatch):
    # The property tracks THIS hold: after a fall-open, releasing and genuinely re-acquiring must
    # report lock_unavailable=False, not carry the stale True forward.
    _force_unsupported(monkeypatch)
    lock = FileLock("myapp", name="poll")
    with pytest.warns(UserWarning):
        lock.acquire()
    assert lock.lock_unavailable is True
    lock.release()
    monkeypatch.undo()                 # restore the real lock_exclusive
    assert lock.acquire() is True      # a genuine OS lock this time
    assert lock.lock_unavailable is False
    lock.release()


def test_lock_unavailable_is_cleared_by_release(monkeypatch):
    # release() ends the hold, so the flag must return to False -- never the nonsensical "not held,
    # yet reported unavailable" state. Pins the release()-side reset that keeps the "iff held"
    # contract honest between a fall-open release and the next acquire.
    _force_unsupported(monkeypatch)
    lock = FileLock("myapp", name="poll")
    with pytest.warns(UserWarning):
        lock.acquire()
    assert lock.lock_unavailable is True
    lock.release()
    assert lock.acquired is False
    assert lock.lock_unavailable is False


def test_reacquire_while_fell_open_preserves_lock_unavailable(monkeypatch):
    # The reset sits AFTER the idempotent early-return, so re-acquiring a still-held fell-open lock
    # must NOT wipe the "ran unguarded" signal. Pins that ordering against a refactor that hoists the
    # reset above the guard.
    _force_unsupported(monkeypatch)
    lock = FileLock("myapp", name="poll")
    with pytest.warns(UserWarning):
        lock.acquire()
    assert lock.acquire() is True          # idempotent early-return, no re-warn
    assert lock.lock_unavailable is True   # signal preserved across the re-acquire
    lock.release()


def test_acquire_reraises_and_stays_clean_when_the_warning_is_escalated(monkeypatch):
    # A strict caller (`-W error`) turns the fall-open UserWarning into an exception: acquire() must
    # fail closed -- re-raise, hold nothing (the handle was closed), and NOT report lock_unavailable,
    # because nothing ran unguarded.
    _force_unsupported(monkeypatch)
    lock = FileLock("myapp", name="poll")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(UserWarning):
            lock.acquire()
    assert lock.acquired is False
    assert lock.lock_unavailable is False


def test_context_manager_require_lock_raises_on_unlockable_filesystem(monkeypatch):
    from credbox.errors import LockUnavailableError

    _force_unsupported(monkeypatch)
    with pytest.raises(LockUnavailableError):
        with FileLock("myapp", name="poll", require_lock=True):
            pytest.fail("entered the block without a lock")
