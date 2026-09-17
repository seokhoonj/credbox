"""Every test runs against a throwaway HOME and XDG base directories under ``tmp_path``, so
nothing here reads or writes the developer's real ``~/.config`` / ``~/.local`` or their actual
provider keys.
"""

from __future__ import annotations

import os

import pytest

_XDG_BASES = {
    "XDG_CONFIG_HOME": "config",
    "XDG_DATA_HOME": "data",
    "XDG_STATE_HOME": "state",
    "XDG_CACHE_HOME": "cache",
    "XDG_RUNTIME_DIR": "runtime",
}

# Env names the tests rely on being ABSENT (secret resolution checks the environment before any
# store, so a real exported value would override the fixture and make the suite
# machine-dependent). Cleared in the autouse fixture below.
_LEAKY_VARS = [
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "CLAUDE_API_KEY",
    "EXAMPLE_API_KEY",
    "K",
    "A_KEY",
    "B_KEY",
    "MISSING",
    "NOPE",
    "MYAPP_DATA_DIR",
    "MYAPP_STATE_DIR",
    "MYAPP_CONFIG_DIR",
    "CREDBOX_LAYOUT",
    # for_app store-binding overrides: a developer's shell value must not redirect the tests.
    "MYAPP_STORE_APP",
    "MYAPP_NAMESPACE",
    "MY_APP_STORE_APP",
    "MY_APP_NAMESPACE",
]


@pytest.fixture(autouse=True)
def isolated_xdg(tmp_path, monkeypatch):
    """Point HOME and every XDG base at a fresh temp tree; clear vars that could leak from the
    developer's real environment; reset the process-wide warn-once registries."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for var, sub in _XDG_BASES.items():
        base = tmp_path / sub
        base.mkdir()
        if var == "XDG_RUNTIME_DIR" and os.name == "posix":
            os.chmod(base, 0o700)   # runtime base must be private for ensure_private_dir
        monkeypatch.setenv(var, str(base))
    for var in _LEAKY_VARS:
        monkeypatch.delenv(var, raising=False)
    _reset_warned_registries(monkeypatch)
    return tmp_path


def _reset_warned_registries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset the module-level warn-once state so a warning emitted by one test cannot suppress
    (or leak into) another -- otherwise assertions on a one-time warning would depend on test
    order. Tolerant of which package/module is importable during the credbox transition."""
    import credbox.backends._store as store
    import credbox.backends.encrypted as encrypted
    import credbox.backends.keyring as keyring_backend
    import credbox.permissions as permissions

    monkeypatch.setattr(permissions, "_warned_permissive_paths", set())
    monkeypatch.setattr(keyring_backend, "_warned_keyring_fallback", False)
    monkeypatch.setattr(store, "_warned_no_oslock", set())
    # The Argon2id availability probe caches into a module global; reset it so a test that forces
    # the probe (by monkeypatching it False) cannot leak that state into another test's ordering.
    monkeypatch.setattr(encrypted, "_kdf_available", False)
