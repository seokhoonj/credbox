"""Reading values from the environment with one consistent rule -- a blank or whitespace-only
value counts as *absent* -- and folding an app name to its canonical env-var prefix.

credbox resolves both directories (an ``$XDG_CONFIG_HOME`` or a per-app override) and the
active layout (``CREDBOX_LAYOUT``) from the environment. In every case an empty string must
read as "not set" rather than as an explicit empty value, so an exported-but-blank variable
falls through to the default instead of overriding it with nothing.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from pathlib import Path

from credbox.errors import CollidingPrefixError

__all__ = [
    "env_value",
    "read_absolute_path_override",
    "env_var_prefix",
    "colliding_env_var_prefixes",
    "check_env_var_prefix_collisions",
]


def env_value(name: str) -> str | None:
    """Return ``os.environ[name]`` stripped of surrounding whitespace, or ``None`` when the
    variable is unset, empty, or whitespace-only."""
    value = os.environ.get(name, "").strip()
    return value or None


def read_absolute_path_override(env_var_name: str) -> Path | None:
    """Return the named environment variable as an absolute path (``~`` expanded), or ``None``
    when it is unset, blank, relative, or a ``~user`` whose home cannot be resolved.

    A relative value is rejected on purpose: the XDG spec says a relative base "must be
    ignored", and a relative override would resolve against the current working directory,
    silently splitting a cron run (cwd ``/``) from an interactive run. Never raises -- an
    advisory override must not crash the resolver."""
    raw = env_value(env_var_name)
    if raw is None:
        return None
    try:
        path = Path(raw).expanduser()
    except RuntimeError:
        return None
    return path if path.is_absolute() else None


def env_var_prefix(app: str) -> str:
    """Fold an app name to its canonical environment-variable prefix: every non-alphanumeric
    character to ``_``, upper-cased (``my-app`` -> ``MY_APP``). This is the one fold used for
    per-app path overrides (``MY_APP_DATA_DIR``) and by any consumer naming its own variables.

    The fold is lossy: ``a.b``, ``a-b``, and ``a_b`` all map to ``A_B`` -- see
    ``colliding_env_var_prefixes`` to detect that before it bites."""
    return re.sub(r"[^A-Za-z0-9]", "_", app).upper()


def colliding_env_var_prefixes(apps: Iterable[str]) -> dict[str, list[str]]:
    """Return the env-var prefixes that more than one of ``apps`` folds to, each mapped to the
    sorted colliding app names -- so a caller can catch that ``a-b`` and ``a.b`` would share
    ``A_B`` before choosing those names."""
    apps_by_prefix: dict[str, list[str]] = {}
    for app in apps:
        apps_by_prefix.setdefault(env_var_prefix(app), []).append(app)
    return {prefix: sorted(names) for prefix, names in apps_by_prefix.items() if len(names) > 1}


def check_env_var_prefix_collisions(apps: Iterable[str]) -> None:
    """Raise if any two of ``apps`` fold to the same environment-variable prefix.

    The guard a host embedding several components should call ONCE at startup, before any secret is
    stored: the prefix fold is lossy (``my-app``, ``my.app``, ``my_app`` all become ``MY_APP``), so
    two components whose names differ only by a separator would read the same ``<PREFIX>_STORE_APP`` /
    ``<PREFIX>_NAMESPACE`` and their stores would cross. Catching that up front turns a silent
    wrong-store write into a loud startup error. A no-op when every prefix is distinct.

    Raises:
        CollidingPrefixError: two or more apps share a prefix -- carries the ``{prefix: [app, ...]}``
            map so the host can name the clashing components.
    """
    collisions = colliding_env_var_prefixes(apps)
    if collisions:
        raise CollidingPrefixError(collisions)
