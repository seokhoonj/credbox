"""Permission checks: the 0600 warning and the private-directory guarantee."""

from __future__ import annotations

import os

import pytest

from credbox import permissions
from credbox.errors import InsecureStorageError
from credbox.permissions import (
    ensure_private_dir,
    restrict_dir_to_owner,
    warn_if_group_or_world_accessible,
    warn_if_group_or_world_readable,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")


@posix_only
def test_warns_once_when_world_readable(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(permissions, "_warned_permissive_paths", set())
    secret = tmp_path / "credentials.json"
    secret.write_text("{}")
    os.chmod(secret, 0o644)
    warn_if_group_or_world_readable(secret, app="host")
    warn_if_group_or_world_readable(secret, app="host")   # second call stays quiet
    err = capsys.readouterr().err
    assert err.count("chmod 600") == 1
    assert "host: warning" in err


@posix_only
def test_no_warning_when_private(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(permissions, "_warned_permissive_paths", set())
    secret = tmp_path / "credentials.json"
    secret.write_text("{}")
    os.chmod(secret, 0o600)
    warn_if_group_or_world_readable(secret, app="myapp")
    assert capsys.readouterr().err == ""


@posix_only
def test_warn_if_dir_accessible_warns_once_and_recommends_chmod_700(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(permissions, "_warned_permissive_paths", set())
    loose = tmp_path / "holder"
    loose.mkdir()
    os.chmod(loose, 0o755)   # group/other can traverse -- should be 0700
    assert warn_if_group_or_world_accessible(loose, app="myapp") is True
    assert warn_if_group_or_world_accessible(loose, app="myapp") is True   # second call stays quiet
    err = capsys.readouterr().err
    assert err.count("chmod 700") == 1   # the dir guard recommends 700, not the file's 600
    assert "myapp: warning" in err


@posix_only
def test_warn_if_dir_accessible_silent_on_private_dir_or_non_dir(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(permissions, "_warned_permissive_paths", set())
    private = tmp_path / "holder"
    private.mkdir()
    os.chmod(private, 0o700)
    assert warn_if_group_or_world_accessible(private, app="myapp") is False
    a_file = tmp_path / "credentials.json"
    a_file.write_text("{}")
    os.chmod(a_file, 0o777)
    assert warn_if_group_or_world_accessible(a_file, app="myapp") is False   # not a directory -> skip
    assert capsys.readouterr().err == ""


@posix_only
def test_ensure_private_dir_creates_0700(tmp_path):
    target = tmp_path / "rt"
    ensure_private_dir(target)
    assert target.is_dir()
    assert (target.stat().st_mode & 0o777) == 0o700


@posix_only
def test_ensure_private_dir_tightens_loose_existing(tmp_path):
    target = tmp_path / "rt"
    target.mkdir(mode=0o755)
    os.chmod(target, 0o755)
    ensure_private_dir(target)
    assert (target.stat().st_mode & 0o777) == 0o700


@posix_only
def test_ensure_private_dir_rejects_symlink(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(InsecureStorageError):
        ensure_private_dir(link)


@posix_only
def test_ensure_private_dir_rejects_non_directory(tmp_path):
    f = tmp_path / "afile"
    f.write_text("x")
    with pytest.raises(InsecureStorageError):
        ensure_private_dir(f)


@posix_only
def test_ensure_private_dir_rejects_foreign_owner(tmp_path, monkeypatch):
    target = tmp_path / "rt"
    target.mkdir(mode=0o700)
    # the dir is really owned by us; make getuid() report a different uid (a captured
    # constant, so the patched function does not call itself) so the owner check treats
    # the dir as foreign
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 99999)
    with pytest.raises(InsecureStorageError):
        ensure_private_dir(target)


@posix_only
def test_restrict_dir_to_owner_tightens_loose_dir(tmp_path):
    d = tmp_path / "cfg"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)
    restrict_dir_to_owner(d)
    assert (d.stat().st_mode & 0o777) == 0o700


@posix_only
def test_restrict_dir_to_owner_allows_symlinked_dir(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    restrict_dir_to_owner(link)   # a synced-folder symlink must be honoured, not rejected
    assert link.is_dir()


def test_guards_are_no_ops_on_non_posix(tmp_path, monkeypatch, capsys):
    """On a non-POSIX OS the mode bits do not apply: ensure_private_dir just creates the
    directory, and the readability warning stays silent."""
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(permissions, "_warned_permissive_paths", set())
    target = tmp_path / "rt"
    assert ensure_private_dir(target) == target
    assert target.is_dir()
    secret = tmp_path / "credentials.json"
    secret.write_text("{}")
    warn_if_group_or_world_readable(secret, app="myapp")   # no permission bits to check
    assert capsys.readouterr().err == ""
