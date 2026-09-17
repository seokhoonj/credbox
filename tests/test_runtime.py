"""The runtime directory: XDG_RUNTIME_DIR when set, a secured temp fallback when not."""

from __future__ import annotations

import os
import tempfile

import pytest

from credbox.errors import InsecureStorageError
from credbox.runtime import runtime_dir

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")


def test_uses_xdg_runtime_dir_when_set(tmp_path):
    assert runtime_dir("myapp", create=False) == tmp_path / "runtime" / "myapp"


def test_create_makes_the_directory(tmp_path):
    path = runtime_dir("myapp")
    assert path.is_dir()


@posix_only
def test_created_dir_is_0700(tmp_path):
    path = runtime_dir("myapp")
    assert (path.stat().st_mode & 0o777) == 0o700


def test_create_false_has_no_side_effect(tmp_path):
    path = runtime_dir("ghost", create=False)
    assert not path.exists()


@posix_only
def test_falls_back_to_temp_when_runtime_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    fake_tmp = tmp_path / "tmp"
    fake_tmp.mkdir()
    # gettempdir() caches its result, so patch it directly rather than TMPDIR
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(fake_tmp))
    path = runtime_dir("myapp")
    assert path.is_dir()
    assert path == fake_tmp / f"credbox-{os.getuid()}" / "myapp"
    assert (path.stat().st_mode & 0o777) == 0o700
    assert (path.parent.stat().st_mode & 0o777) == 0o700   # per-uid root is private too


@posix_only
def test_rejects_foreign_owned_precreated_runtime_dir(tmp_path, monkeypatch):
    # an attacker who pre-creates the app's runtime dir under a uid that is not ours must be
    # refused (not trusted with our sockets/locks). We can't chown without privilege, so we
    # instead make ownership *appear* foreign by shifting our own reported uid.
    victim = tmp_path / "runtime" / "myapp"
    victim.mkdir(parents=True)
    real_uid = os.stat(victim).st_uid
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)
    with pytest.raises(InsecureStorageError):
        runtime_dir("myapp")
