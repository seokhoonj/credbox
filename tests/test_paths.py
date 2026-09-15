"""Tests for the XDG and native path resolvers and app-name validation."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from credbox.errors import CredBoxError, InvalidAppNameError
from credbox.paths import app_dir_segment, cache_dir, config_dir, data_dir, state_dir

_XDG_VARS = [
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "MYAPP_DATA_DIR",
    "MYAPP_STATE_DIR",
    "LOCALAPPDATA",
    "CREDBOX_LAYOUT",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """A clean environment: no XDG/override vars, HOME under a temp dir."""
    for var in _XDG_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    yield


# --- app_dir_segment validation ------------------------------------------------

def test_app_dir_segment_accepts_valid_names() -> None:
    for name in ("myapp", "my-app", "a.b_c", "App1"):
        assert app_dir_segment(name) == name


@pytest.mark.parametrize("bad", ["", "a/b", "..", ".", "-lead", "trail-", "a b", "a/../b"])
def test_app_dir_segment_rejects_unsafe_names(bad: str) -> None:
    with pytest.raises(InvalidAppNameError):
        app_dir_segment(bad)


def test_invalid_app_name_is_also_a_value_error() -> None:
    with pytest.raises(ValueError):
        app_dir_segment("a/b")


@pytest.mark.parametrize("reserved", ["con", "CON", "nul", "Nul", "com1", "lpt9", "aux", "prn", "con.txt"])
def test_app_dir_segment_rejects_windows_reserved_names(reserved: str) -> None:
    # Rejected on every platform so a store stays portable -- these are unusable on Windows.
    with pytest.raises(InvalidAppNameError):
        app_dir_segment(reserved)


def test_app_dir_segment_allows_names_that_merely_contain_a_reserved_word() -> None:
    for ok in ("console", "connection", "com10", "aux-service", "prnt"):
        assert app_dir_segment(ok) == ok


# --- xdg layout ----------------------------------------------------------------

def test_config_dir_uses_xdg_config_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    assert config_dir("myapp") == tmp_path / "cfg" / "myapp"


@pytest.mark.parametrize(
    ("dir_fn", "xdg_var"),
    [
        (config_dir, "XDG_CONFIG_HOME"),
        (data_dir, "XDG_DATA_HOME"),
        (state_dir, "XDG_STATE_HOME"),
        (cache_dir, "XDG_CACHE_HOME"),
    ],
)
def test_each_dir_honours_its_own_xdg_base_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, dir_fn, xdg_var: str
) -> None:
    # Each base function must read ITS OWN XDG_* variable, not a neighbour's -- a cross-wired
    # table (config reading DATA_HOME, etc.) would pass a single-variable test but leak here.
    base = tmp_path / xdg_var.lower()
    monkeypatch.setenv(xdg_var, str(base))
    assert dir_fn("myapp") == base / "myapp"


def test_config_dir_falls_back_to_home_config(tmp_path: Path) -> None:
    assert config_dir("myapp") == tmp_path / ".config" / "myapp"


def test_data_and_state_and_cache_home_fallbacks(tmp_path: Path) -> None:
    assert data_dir("myapp") == tmp_path / ".local" / "share" / "myapp"
    assert state_dir("myapp") == tmp_path / ".local" / "state" / "myapp"
    assert cache_dir("myapp") == tmp_path / ".cache" / "myapp"


def test_per_app_override_wins_for_data_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("MYAPP_DATA_DIR", str(tmp_path / "elsewhere"))
    assert data_dir("myapp") == tmp_path / "elsewhere"


def test_relative_xdg_var_is_ignored(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative/cfg")
    assert config_dir("myapp") == tmp_path / ".config" / "myapp"


# --- native layout -------------------------------------------------------------

def test_native_macos_collapses_config_data_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    support = tmp_path / "Library" / "Application Support" / "myapp"
    assert config_dir("myapp", layout="native") == support
    assert data_dir("myapp", layout="native") == support
    assert state_dir("myapp", layout="native") == support


def test_native_macos_cache_uses_library_caches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    assert cache_dir("myapp", layout="native") == tmp_path / "Library" / "Caches" / "myapp"


def test_native_windows_uses_localappdata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))
    base = tmp_path / "AppData" / "Local"
    assert config_dir("myapp", layout="native") == base / "myapp"
    assert cache_dir("myapp", layout="native") == base / "myapp" / "Cache"


def test_native_on_linux_equals_xdg(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert config_dir("myapp", layout="native") == config_dir("myapp", layout="xdg")


def test_no_home_raises_credbox_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOME", raising=False)

    def _no_home() -> Path:
        raise RuntimeError("no home")

    monkeypatch.setattr("credbox.paths.Path.home", staticmethod(_no_home))
    with pytest.raises(CredBoxError):
        config_dir("myapp")


def test_config_dir_rejects_a_non_absolute_home(monkeypatch: pytest.MonkeyPatch) -> None:
    # A whitespace/relative HOME would resolve the store against the current directory, silently
    # splitting a cron run from an interactive one; credbox must reject it, not use a relative path.
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)   # force the HOME-based resolution
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("  ")))
    with pytest.raises(CredBoxError, match="absolute"):
        config_dir("myapp")
