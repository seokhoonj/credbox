"""Domain exception hierarchy for credbox.

Every error credbox raises on purpose derives from ``CredBoxError``, so a caller can handle
this package's failures with a single ``except`` without catching unrelated bugs. Each leaf
states its bases explicitly: ``InvalidAppNameError`` is also a ``ValueError`` (a bad literal
name is a caller mistake) and ``MissingExtraError`` is also an ``ImportError`` (a missing
optional dependency), so an ``except ValueError`` / ``except ImportError`` still catches them.
"""

from __future__ import annotations

__all__ = [
    "CredBoxError",
    "CredentialsError",
    "NoKeyringError",
    "InsecureStorageError",
    "InvalidAppNameError",
    "InvalidLayoutError",
    "BlankSecretError",
    "InvalidSecretTypeError",
    "CollidingPrefixError",
    "InvalidMigrationError",
    "LockHeldError",
    "LockUnavailableError",
    "DecryptionError",
    "MissingExtraError",
]


class CredBoxError(Exception):
    """Base for every error credbox raises deliberately."""


class CredentialsError(CredBoxError):
    """The credential store is unusable: present but malformed (unreadable, not JSON, not a
    JSON object, a non-string value), or the backend it needs is absent. Built from safe
    fields only (a path, an errno, a content-free kind) -- never from a secret value, and
    never chained to an exception whose text could embed one."""


class NoKeyringError(CredentialsError):
    """No OS keyring backend is available at all -- an environment fact, not a store fault.
    A ``CredentialsError`` subtype so a broad ``except CredentialsError`` still catches it."""


class InsecureStorageError(CredBoxError):
    """A path that must be private is not: it is owned by another user, is a symlink, or is
    readable by group/others. Raised rather than trusting it, because a secret written there
    would leak."""


class InvalidAppNameError(CredBoxError, ValueError):
    """An app name fails the charset rule (non-empty, a leading alphanumeric, then only
    ``[A-Za-z0-9._-]``). Also a ``ValueError`` -- a bad literal name is a caller mistake --
    so an ``except ValueError`` still catches it and the CLI can single it out as a usage
    error (exit 2)."""


class InvalidLayoutError(CredBoxError, ValueError):
    """A layout other than ``"xdg"`` or ``"native"`` was passed to ``set_default_layout``. Also a
    ``ValueError`` -- an off-vocabulary literal is a caller mistake -- so an ``except ValueError``
    still catches it, mirroring ``InvalidAppNameError``. (The ``layout`` parameter is typed
    ``Literal["xdg", "native"]``, so a type-checked caller cannot reach this; it is the runtime
    backstop for a dynamically-built value.)"""


class BlankSecretError(CredBoxError, ValueError):
    """A blank or whitespace-only secret name or value was passed to ``Credentials.set``. A blank
    value would list under ``names`` yet resolve to ``None`` (blanks read as absent); a blank name
    is unresolvable -- both are refused to keep ``set`` and ``get`` consistent. Also a
    ``ValueError`` -- a blank is a caller mistake -- so an ``except ValueError`` catches it too,
    mirroring ``InvalidAppNameError``."""


class InvalidSecretTypeError(CredBoxError, TypeError):
    """A value passed to ``Credentials.set``, or an ``override`` passed to ``secret``/``require``,
    is neither a ``str`` nor a ``Secret``. Also a ``TypeError`` -- the wrong type is a caller
    mistake, so an ``except TypeError`` still catches it -- while being a ``CredBoxError`` too, so a
    caller guarding the store with ``except CredBoxError`` catches it without a separate ``except
    TypeError``. The message names the offending type only, never the value (which could be a
    secret), mirroring ``BlankSecretError``'s content-free contract."""


class CollidingPrefixError(CredBoxError, ValueError):
    """Two or more app names passed to ``check_env_var_prefix_collisions`` fold to the SAME
    environment-variable prefix (e.g. ``my-app`` and ``my.app`` both fold to ``MY_APP``), so a host
    embedding them would drive them with the same ``<PREFIX>_STORE_APP`` / ``<PREFIX>_NAMESPACE`` and
    their secrets would land in one place, colliding. Also a ``ValueError`` -- colliding component
    names are a caller mistake. Carries ``.collisions`` (``{prefix: [app, ...]}``) so a host can
    print exactly which names clash."""

    def __init__(self, collisions: dict[str, list[str]]) -> None:
        self.collisions = collisions
        detail = "; ".join(
            f"{prefix} <- {', '.join(apps)}" for prefix, apps in sorted(collisions.items())
        )
        super().__init__(
            f"app names collide on their environment-variable prefix (embedding them into one host "
            f"would cross their store bindings): {detail}"
        )


class InvalidMigrationError(CredBoxError, ValueError):
    """``Credentials.migrate_to`` was asked for an illegal migration: the destination is the SAME
    store (same app and namespace), or a same-app namespaced->flat conversion (which cannot be done
    safely, since a surviving sibling namespace would fault the flat write after the source is
    cleared). Also a ``ValueError`` -- an illegal request is a caller mistake -- so an
    ``except ValueError`` still catches it, while ``except CredBoxError`` covers it too, mirroring
    ``InvalidLayoutError`` and ``CollidingPrefixError``."""


class LockHeldError(CredBoxError):
    """Another process already holds the ``FileLock`` a ``with FileLock(...)`` block tried to take.
    The context-manager form treats "not acquired" as an error so protected work never runs
    unguarded; use ``single_instance(app, name=...)`` instead when the intent is to skip -- it
    yields ``False`` rather than raising. Distinct from the ``CredBoxError`` that ``acquire`` raises
    when the lock file cannot be opened, so a caller can tell contention (normal, skip) from a
    broken environment."""


class LockUnavailableError(CredBoxError):
    """A ``FileLock`` / ``single_instance`` created with ``require_lock=True`` could not take a real
    OS lock because the filesystem does not support locking (e.g. some NFS mounts, which report
    ``ENOLCK``). Distinct from ``LockHeldError`` (another process holds it -- normal contention): a
    strict caller that would rather NOT run than run without a cross-process guard opts into this by
    passing ``require_lock=True``; the default falls open (runs, warns) instead of raising."""


class DecryptionError(CredBoxError):
    """[crypto] The encrypted store could not be decrypted: a wrong passphrase or tampering
    (an AES-GCM tag failure). Content-free by construction -- raised from a returning frame
    so that both ``__cause__`` and ``__context__`` are ``None`` and the underlying
    ``InvalidTag`` never rides along."""


class MissingExtraError(CredBoxError, ImportError):
    """An optional feature was requested but its extra is not installed. Also an
    ``ImportError`` for dual-catch. Carries ``.extra`` (e.g. ``"keyring"``) and ``.dist``
    (e.g. ``"credbox[keyring]"``) so the CLI can print an actionable ``pip install`` hint."""

    def __init__(self, *, extra: str, dist: str) -> None:
        self.extra = extra
        self.dist = dist
        super().__init__(f"optional feature {extra!r} is not installed; run 'pip install {dist}'")
