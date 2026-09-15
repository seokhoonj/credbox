"""credbox -- a secure, XDG-located secret store for apps and CLIs.

Honest plaintext mode-0600 default, with opt-in keyring and encrypted upgrades. This module
is NAME DEFINITION ONLY: it re-exports the common public surface and does no import-time work
and never imports an optional extra (``keyring``/``cryptography``).
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

from credbox.atomic import write_bytes_atomic, write_text_atomic
from credbox.backends import (
    FileBackend,
    SecretBackend,
    default_backend,
    encrypted_backend,
    file_backend,
    keyring_backend,
)
from credbox.credentials import Credentials
from credbox.environment import (
    colliding_env_var_prefixes,
    env_var_prefix,
    read_absolute_path_override,
)
from credbox.errors import (
    BlankSecretError,
    CredBoxError,
    CredentialsError,
    DecryptionError,
    InsecureStorageError,
    InvalidAppNameError,
    InvalidLayoutError,
    LockHeldError,
    LockUnavailableError,
    MissingExtraError,
    NoKeyringError,
)
from credbox.jsonfile import read_json
from credbox.layout import Layout, default_layout, set_default_layout
from credbox.locking import FileLock, single_instance
from credbox.paths import app_dir_segment, cache_dir, config_dir, data_dir, state_dir
from credbox.permissions import (
    ensure_dir,
    ensure_private_dir,
    restrict_dir_to_owner,
    warn_if_group_or_world_accessible,
    warn_if_group_or_world_readable,
)
from credbox.relocation import relocate_once
from credbox.runtime import runtime_dir
from credbox.scrub import scrub_exception, scrub_secrets
from credbox.secret import Secret, mask_secret

try:
    __version__ = _version("credbox")
except PackageNotFoundError:
    # Running from a source tree not installed as "credbox". The real version lives in the
    # distribution metadata (read above); this fallback must NOT duplicate a release number, or a
    # source-tree run would report a plausible-but-stale version once the released one moves on. A
    # PEP 440 local-version label makes it unmistakably "not a release".
    __version__ = "0+unknown"

__all__ = [
    "__version__",
    # errors
    "CredBoxError",
    "CredentialsError",
    "NoKeyringError",
    "InsecureStorageError",
    "InvalidAppNameError",
    "InvalidLayoutError",
    "BlankSecretError",
    "LockHeldError",
    "LockUnavailableError",
    "DecryptionError",
    "MissingExtraError",
    # resolver facade
    "Credentials",
    # value type
    "Secret",
    "mask_secret",
    # paths & layout
    "config_dir",
    "data_dir",
    "state_dir",
    "cache_dir",
    "app_dir_segment",
    "Layout",
    "default_layout",
    "set_default_layout",
    # environment
    "env_var_prefix",
    "colliding_env_var_prefixes",
    "read_absolute_path_override",
    # storage primitives
    "write_bytes_atomic",
    "write_text_atomic",
    "read_json",
    "relocate_once",
    "ensure_dir",
    "ensure_private_dir",
    "restrict_dir_to_owner",
    "warn_if_group_or_world_readable",
    "warn_if_group_or_world_accessible",
    "runtime_dir",
    "FileLock",
    "single_instance",
    "scrub_secrets",
    "scrub_exception",
    # backends (core + factories only; extra classes are reached via the factories)
    "SecretBackend",
    "FileBackend",
    "file_backend",
    "keyring_backend",
    "encrypted_backend",
    "default_backend",
]
