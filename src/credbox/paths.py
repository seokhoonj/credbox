"""Application base directories, resolved the same way on every OS by default (XDG), with an
opt-in ``native`` layout.

By default (``layout="xdg"``) each kind of file gets its own XDG base -- taken from the
matching ``XDG_*_HOME`` variable when it holds an absolute path, else the spec's home-relative
default -- on every OS, the convention git / ssh / aws already follow, so a path is identical
across machines and no platform library is needed.

- ``config_dir(app)`` -- hand-editable configuration and ``credentials.json``
  (``$XDG_CONFIG_HOME``, else ``~/.config``)
- ``data_dir(app)``   -- durable, hard-to-regenerate data
  (``$XDG_DATA_HOME``, else ``~/.local/share``)
- ``state_dir(app)``  -- persistent but replaceable run state and logs
  (``$XDG_STATE_HOME``, else ``~/.local/state``)
- ``cache_dir(app)``  -- discardable cache
  (``$XDG_CACHE_HOME``, else ``~/.cache``)

``data_dir`` and ``state_dir`` also honour a per-app ``<PREFIX>_DATA_DIR`` /
``<PREFIX>_STATE_DIR`` override (an explicit absolute path used as-is), where ``<PREFIX>`` is
``env_var_prefix(app)``; the override wins under either layout.

With ``layout="native"`` the four bases map to the OS's own locations: macOS
``~/Library/Application Support`` (config == data == state collapse) and ``~/Library/Caches``;
Windows ``%LOCALAPPDATA%`` (pinned, never roaming); Linux native == xdg.

An ``app`` is a single directory-name segment (``"myapp"``, ``"my-app"``), validated by
``app_dir_segment`` so it can never escape its base with a separator or ``..``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from credbox.environment import env_var_prefix, read_absolute_path_override
from credbox.errors import CredBoxError, InvalidAppNameError
from credbox.layout import Layout, default_layout

__all__ = [
    "config_dir",
    "data_dir",
    "state_dir",
    "cache_dir",
    "app_dir_segment",
]

_APP_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")

# Windows reserved DOS device names: unusable as a directory/file even with an extension (con.txt
# still resolves to the device). They pass the charset rule above, so reject them on EVERY platform
# -- a store must be portable, and a name that breaks only on Windows is a latent, hard-to-diagnose
# footgun. Matched case-insensitively, with or without an extension.
_WINDOWS_RESERVED = re.compile(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?")

# Each kind's XDG variable and home-relative default.
_XDG = {
    "config": ("XDG_CONFIG_HOME", ".config"),
    "data": ("XDG_DATA_HOME", ".local/share"),
    "state": ("XDG_STATE_HOME", ".local/state"),
    "cache": ("XDG_CACHE_HOME", ".cache"),
}
# Only data and state take a per-app absolute-path override; config cannot name its own
# location and cache is not worth relocating.
_OVERRIDE_SUFFIX = {"data": "DATA_DIR", "state": "STATE_DIR"}


def app_dir_segment(app: str) -> str:
    """Return ``app`` unchanged once validated as a safe single path segment, or raise.

    A valid name starts and ends with a letter or digit and contains only letters, digits,
    ``.``, ``_``, and ``-`` between (``"my-app"``, ``"a.b_c"``). This rejects an empty name, a
    path separator, ``.``/``..``, and leading/trailing punctuation, so a directory resolver
    can never be steered out of its base by a crafted name. A Windows reserved device name
    (``con``, ``nul``, ``com1`` ...) is also rejected on every platform, so a store stays portable.

    Raises:
        InvalidAppNameError: ``app`` is not a valid directory segment (a caller mistake; also
            a ``ValueError``).
    """
    return _valid_segment(app, label="app name")


def _valid_segment(value: str, *, label: str) -> str:
    """The shared segment rule behind ``app_dir_segment`` and the ``Credentials`` namespace check:
    return ``value`` unchanged once validated as a safe single path segment, or raise. ``label``
    names the value in the error message -- ``"app name"`` for an app directory, ``"namespace"`` for
    a namespace whose value composes into a keyring service name -- so the message fits whichever the
    caller validates. The rule itself (charset, no separator/``..``, Windows reserved) is identical.

    Raises:
        InvalidAppNameError: ``value`` is not a valid segment (a caller mistake; also a
            ``ValueError``).
    """
    if not _APP_NAME.fullmatch(value):
        raise InvalidAppNameError(
            f"invalid {label} {value!r}: expected a single path segment of letters, digits, "
            f"'.', '_', '-' (e.g. 'my-app')"
        )
    if _WINDOWS_RESERVED.fullmatch(value):
        raise InvalidAppNameError(
            f"invalid {label} {value!r}: it is a Windows reserved device name (con, nul, com1, ...)"
        )
    return value


def config_dir(app: str, *, layout: Layout | None = None) -> Path:
    """Hand-editable configuration and ``credentials.json`` for ``app`` (see module docstring
    for the per-layout locations).

    Raises:
        InvalidAppNameError: ``app`` is not a valid directory segment.
        CredBoxError: no home directory can be determined and no absolute env base is set.
    """
    return _app_dir("config", app, layout)


def data_dir(app: str, *, layout: Layout | None = None) -> Path:
    """Durable, hard-to-regenerate data for ``app`` (a database, an archive). A
    ``<PREFIX>_DATA_DIR`` absolute-path override wins under either layout.

    Raises:
        InvalidAppNameError: ``app`` is not a valid directory segment.
        CredBoxError: no home directory can be determined and no absolute env base is set.
    """
    return _app_dir("data", app, layout)


def state_dir(app: str, *, layout: Layout | None = None) -> Path:
    """Persistent but replaceable run state and logs for ``app``. A ``<PREFIX>_STATE_DIR``
    absolute-path override wins under either layout.

    Raises:
        InvalidAppNameError: ``app`` is not a valid directory segment.
        CredBoxError: no home directory can be determined and no absolute env base is set.
    """
    return _app_dir("state", app, layout)


def cache_dir(app: str, *, layout: Layout | None = None) -> Path:
    """Discardable cache for ``app`` -- safe to delete between runs.

    Raises:
        InvalidAppNameError: ``app`` is not a valid directory segment.
        CredBoxError: no home directory can be determined and no absolute env base is set.
    """
    return _app_dir("cache", app, layout)


# --- private resolvers ---------------------------------------------------------

def _app_dir(kind: str, app: str, layout: Layout | None) -> Path:
    """Resolve ``kind`` for ``app`` under the given (or default) layout. A per-app
    absolute-path override, when set, wins before either layout is consulted."""
    segment = app_dir_segment(app)
    suffix = _OVERRIDE_SUFFIX.get(kind)
    if suffix is not None:
        override = read_absolute_path_override(f"{env_var_prefix(app)}_{suffix}")
        if override is not None:
            return override
    active = layout if layout is not None else default_layout()
    if active == "native":
        native = _native_app_dir(kind, segment)
        if native is not None:
            return native
        # Linux (and any non-macOS/Windows) native == xdg: fall through.
    return _xdg_app_dir(kind, segment)


def _native_app_dir(kind: str, segment: str) -> Path | None:
    """The macOS/Windows native location for ``kind``, or ``None`` where native == xdg
    (Linux/other), or when ``%LOCALAPPDATA%`` is unset on Windows (fall back to xdg)."""
    if sys.platform == "darwin":
        home = _home_dir(kind, segment)
        if kind == "cache":
            return home / "Library" / "Caches" / segment
        return home / "Library" / "Application Support" / segment  # config == data == state
    if sys.platform == "win32":
        base = read_absolute_path_override("LOCALAPPDATA")  # pinned local, never roaming
        if base is None:
            return None
        if kind == "cache":
            return base / segment / "Cache"
        return base / segment
    return None


def _xdg_app_dir(kind: str, segment: str) -> Path:
    """``$<XDG var>/<segment>`` when the variable is an absolute path, else
    ``~/<home-relative default>/<segment>`` (the XDG spec's own fallback)."""
    env_name, home_subpath = _XDG[kind]
    root = read_absolute_path_override(env_name)
    if root is not None:
        return root / segment
    return _home_dir(kind, segment) / home_subpath / segment


def _home_dir(kind: str, segment: str) -> Path:
    """``Path.home()`` as a ``CredBoxError`` rather than the ``RuntimeError`` it raises when no
    home can be determined -- so the failure stays inside credbox's error surface. A non-absolute
    ``HOME`` (whitespace or a relative path) is rejected too: it would resolve the store against the
    current directory, silently splitting a cron run (cwd ``/``) from an interactive one -- the same
    hazard the XDG absolute-path override already guards against."""
    try:
        home = Path.home()
    except RuntimeError as err:
        raise CredBoxError(
            f"cannot locate the {kind} directory for {segment!r}: no home directory "
            f"(set HOME, or set an absolute base env var)"
        ) from err
    if not home.is_absolute():
        raise CredBoxError(
            f"cannot locate the {kind} directory for {segment!r}: HOME is not an absolute path "
            f"(set HOME to an absolute path, or set an absolute base env var)"
        )
    return home
