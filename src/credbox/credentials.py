"""Resolving a secret for an application across four tiers, in a fixed order.

A ``Credentials`` is bound to an app and, optionally, to one or more *shared* stores it also
consults. ``secret(name)`` resolves in this order, first hit wins:

1. an explicit ``override`` the caller passed (e.g. an ``api_key=`` argument in code),
2. the environment variable ``name`` (``EXAMPLE_API_KEY``),
3. each shared store, in order (another app's ``credentials.json``, consulted by name),
4. this app's own store.

The shared-store tier is what lets a key common to several apps live in one place: store it once
under a shared app (say ``"auth"``) and a consumer resolves it with
``Credentials("myapp", shared=["auth"])`` -- env still wins, then the ``auth`` store, then
``myapp``'s own.

``Credentials`` is a configured FACADE: it binds ``(app, namespace, shared)`` and a single chosen
``SecretBackend`` and *orders the resolution tiers*, delegating every store touch to the backend.
It does not compose a fallback chain itself -- keyring-over-file composition lives in the backend
(see ``backends``). Every resolved value is returned as a ``Secret``, never a raw ``str``.
"""

from __future__ import annotations

import contextlib
import threading
import warnings
from collections.abc import Sequence
from typing import NamedTuple, Self

from credbox.backends import SecretBackend, SupportsLocationDescription, default_backend
from credbox.environment import env_value, env_var_prefix
from credbox.errors import (
    BlankSecretError,
    CredentialsError,
    InvalidMigrationError,
    InvalidSecretTypeError,
)
from credbox.paths import _valid_segment, app_dir_segment
from credbox.secret import Secret

__all__ = ["Credentials", "MigrationResult"]

# One-time-per-app guard for the redirect-orphans-a-legacy-store warning (fired on the first real
# store access under a redirect, not at construction). A set of app names already probed, behind a
# lock, so the legacy store is read at most once per app even across threads (mirrors the keyring
# backend's one-time-warning pattern).
_warned_legacy_orphan: set[str] = set()
_warn_lock = threading.Lock()


class MigrationResult(NamedTuple):
    """What ``Credentials.migrate_to`` did: how many secrets landed in the destination, how many of
    those replaced an existing destination key, and whether the source was emptied (a move) or left
    intact (a copy). (``migrated`` rather than ``count`` -- ``count`` is a ``tuple`` method.)"""

    migrated: int
    overwritten: int
    moved: bool


class _StoreBinding(NamedTuple):
    """The store binding validated as safe path segments -- computed once on first store access,
    never at construction (see ``Credentials._binding``)."""

    app: str
    namespace: str | None
    shared: tuple[str, ...]

    @property
    def namespace_kwargs(self) -> dict[str, str]:
        """What every backend call forwards: empty for a flat store, ``{"namespace": ...}`` for a
        namespaced one, so a backend written against the pre-0.2.0 four-argument protocol still sees
        the exact flat call. Derived from ``namespace``, so the stored binding is purely the
        validated segments (no redundant, mutable state)."""
        return {} if self.namespace is None else {"namespace": self.namespace}


class Credentials:
    """An app's secret resolver: bound to one app, optionally consulting shared stores, backed by
    one ``SecretBackend`` (a ``FileBackend`` by default)."""

    def __init__(
        self,
        app: str,
        *,
        namespace: str | None = None,
        shared: Sequence[str] = (),
        backend: SecretBackend | None = None,
    ) -> None:
        """Bind to ``app``.

        ``namespace`` (default ``None``) scopes every store touch to a component's sub-store within
        ``app``'s store, so several components can share one app's store without their keys colliding
        -- ``None`` is the flat store (the original layout, unchanged); a non-``None`` namespace
        reads and writes only its own section. A namespace is a single scoping key (one level); to
        scope by several axes, encode them into one name with a non-``/`` separator (``"prod-web"``)
        -- ``/`` is reserved for the keyring service fold.

        An app's store is wholly flat OR wholly namespaced: once any namespace is written, reading or
        writing that same app's store with ``namespace=None`` raises ``CredentialsError`` (and a flat
        store read with a ``namespace`` does too) rather than mixing layouts -- so on migrating a
        0.1-era flat store to namespaces, move its keys under a namespace, do not read the old flat
        keys with ``namespace=None`` alongside. (A ``secret`` resolved from the override or
        environment tier never touches the store, so it is unaffected.)

        ``shared`` names other apps whose stores are consulted before ``app``'s own (e.g.
        ``["auth"]`` for a key common to several apps). A shared store is read at its own FLAT
        layout, never scoped by this ``namespace`` -- a cross-app common store belongs to no one
        component's section, so an embedded component still finds its keys. ``backend`` selects the
        store; the default is a ``FileBackend`` (call ``default_backend(use_keyring=True)`` or a
        factory for the keyring/encrypted backends).

        The ``(app, namespace, shared)`` binding is validated as safe path segments lazily, on the
        first store access (see ``_binding``) -- not here. So constructing a ``Credentials`` with a
        malformed binding never raises; the ``InvalidAppNameError`` surfaces only when a store tier
        is actually consulted. This is deliberate: a secret satisfied by the override or environment
        tier never touches -- or validates -- the binding, and building a ``Credentials`` at import
        (e.g. from a ``for_app`` override) cannot crash the import.

        Raises:
            TypeError: ``shared`` is a bare ``str`` -- almost always a mistake (``shared="auth"``
                would iterate into the characters ``"a","u","t","h"`` and consult four bogus
                stores); pass a sequence like ``["auth"]``. Validated eagerly (it is a type
                confusion, not a binding value), unlike the segment validation above.
        """
        if isinstance(shared, str):
            raise TypeError(
                f"shared must be a sequence of app names, not a bare str {shared!r}; "
                f"pass [{shared!r}] for a single shared store"
            )
        self._raw_app = app
        self._raw_namespace = namespace
        self._raw_shared = tuple(shared)
        self._backend = backend if backend is not None else default_backend()
        self._binding_cache: _StoreBinding | None = None
        # Set by `for_app` to this component's own app name when a redirect is active, so the FIRST
        # store access can warn (once) about a still-populated legacy store -- deferred here so an
        # override/env-satisfied caller, which never reaches the store, pays no such check.
        self._legacy_own_app: str | None = None

    def _binding(self) -> _StoreBinding:
        """The binding validated as safe path segments, computed once and cached.

        Every store-touching path (``secret``'s store tiers, ``set``, ``unset``, ``names``) calls
        this before reaching the backend, so a backend only ever receives pre-validated segments
        (the keyring folds ``namespace`` into the service name ``app/namespace``, so an unvalidated
        one could escape its service -- ``backends/protocol.py``). The override and environment
        tiers of ``secret`` skip it, so they resolve without validating -- or needing -- the binding.

        Raises:
            InvalidAppNameError: the app, the namespace, or a shared name is not a valid segment
                (deferred here from construction).
        """
        if self._binding_cache is None:
            # Validate the app identity FIRST, so a malformed component name surfaces as an "app"
            # error even when `for_app`'s auto-namespace copied that same name into the namespace.
            app = app_dir_segment(self._raw_app)
            namespace = (
                _valid_segment(self._raw_namespace, label="namespace")
                if self._raw_namespace is not None
                else None
            )
            self._binding_cache = _StoreBinding(
                app=app,
                namespace=namespace,
                shared=tuple(app_dir_segment(name) for name in self._raw_shared),
            )
        return self._binding_cache

    def _warn_orphaned_once(self) -> None:
        """On an ACTUAL store operation under a ``for_app`` redirect, warn (once per app) if the
        component's own store still holds secrets the redirect cannot reach. Kept out of
        ``_binding`` -- which validation-only accessors (``app``/``namespace``/``store_location``)
        also call -- so only a real store touch (``secret``'s store tiers, ``set``, ``unset``,
        ``names``), never a mere accessor, can trigger the legacy-store read or the warning."""
        if self._legacy_own_app is None:
            return
        binding = self._binding()
        _warn_if_own_store_orphaned(
            self._legacy_own_app, binding.app, binding.namespace, self._backend
        )

    @classmethod
    def for_app(
        cls,
        app: str,
        *,
        shared: Sequence[str] = (),
        backend: SecretBackend | None = None,
    ) -> Self:
        """Build the credentials for ``app``, letting a host process redirect the store binding.

        Use this instead of ``Credentials(app)`` in a component that may be embedded in another
        application. By default it is exactly ``Credentials(app)`` -- the flat ``app`` store, so a
        standalone run is unchanged. But a host that wants to consolidate several components into
        ONE store can redirect this component with two environment variables, keyed by the app's
        own prefix (``env_var_prefix(app)``, e.g. ``MYAPP`` for ``"myapp"``):

        - ``<PREFIX>_STORE_APP`` -- the app whose store to use instead (the host's own, e.g.
          ``host``); defaults to ``app``.
        - ``<PREFIX>_NAMESPACE`` -- the section to scope to within that store (e.g. ``myapp``).
          When ``<PREFIX>_STORE_APP`` redirects into a DIFFERENT app's store and this is unset, it
          DEFAULTS to ``app`` (this component's own name), so several components consolidated into
          one host store each land in their own section and never collide in its flat top level. A
          standalone run (no ``STORE_APP`` redirect) stays flat (``None``); an explicit value wins.

        So a host need only set ``MYAPP_STORE_APP=host`` and this returns
        ``Credentials("host", namespace="myapp")`` -- the component's secrets land in the host's
        ``credentials.json`` under a ``myapp`` section, beside its siblings; setting
        ``MYAPP_NAMESPACE`` explicitly only overrides that section name. A blank or whitespace-only
        value reads as unset. ``namespace`` is not a parameter here -- it is resolved (or defaulted)
        from ``<PREFIX>_NAMESPACE``; ``shared`` and ``backend`` are forwarded to the constructor
        unchanged.

        A consolidated host store is therefore wholly namespaced: every embedded component lives in
        its own section, and the host's OWN keys must live under a namespace too (e.g.
        ``Credentials("host", namespace="host")``), never flat at the top level -- mixing a flat key
        with namespaced sections in one store is refused (``CredentialsError``).

        The prefix is ``env_var_prefix(app)``, so distinctly-named components read distinct override
        variables -- but that fold is lossy (``my-app``, ``my.app``, ``my_app`` all become
        ``MY_APP``), so two components whose names differ only by a separator would read the SAME
        override; a host embedding several components should call ``check_env_var_prefix_collisions``
        once at startup to rule that out before it bites.

        Embedding is single-level: a host may consolidate leaf consumers into its own store, but a
        host that is itself embeddable cannot transitively re-home its sub-consumers -- each
        component always reads its own ``<PREFIX>_STORE_APP`` / ``<PREFIX>_NAMESPACE`` (never a
        super-host's), and the namespace is one level deep, so ``super -> host -> component`` cannot
        be expressed. Consolidate leaves, not a chain of hosts.

        Raises:
            InvalidAppNameError: ``app`` -- or a ``<PREFIX>_STORE_APP`` / ``<PREFIX>_NAMESPACE``
                override -- is not a valid segment. Deferred to the first store access (the binding
                is validated lazily), so a blank or malformed value does not raise here; a secret
                satisfied by the override or environment tier never reaches that validation at all.
            TypeError: ``shared`` is a bare ``str`` -- pass a sequence like ``["auth"]`` (forwarded
                to the constructor, which rejects it eagerly).
        """
        prefix = env_var_prefix(app)   # a pure fold, so the raw app is safe here; the segment is validated lazily
        store_app = env_value(f"{prefix}_STORE_APP") or app
        namespace = env_value(f"{prefix}_NAMESPACE")
        if namespace is None and store_app != app:
            # Redirecting into a different app's store without an explicit namespace defaults it to
            # this component's own name, so consolidated components never collide in the host store's
            # flat top level (each writes its own section). Standalone (store_app == app) stays flat.
            namespace = app
        creds = cls(store_app, namespace=namespace, shared=shared, backend=backend)
        if store_app != app:
            # Arm the orphan check without doing I/O here: it fires on the FIRST store access (see
            # `_binding`), so an override/env-satisfied caller never triggers the legacy-store read.
            creds._legacy_own_app = app
        return creds

    def __repr__(self) -> str:
        # Secret-safe: the app, the namespace, the shared-store order, and the backend type only --
        # no value. Shows the RAW binding (never validates), so repr never raises even on an
        # as-yet-unvalidated malformed binding -- and a valid binding reads identically, since
        # validation returns each segment unchanged.
        return (
            f"Credentials(app={self._raw_app!r}, namespace={self._raw_namespace!r}, "
            f"shared={list(self._raw_shared)!r}, backend={type(self._backend).__name__})"
        )

    def secret(self, name: str, *, override: str | Secret | None = None) -> Secret | None:
        """Resolve ``name`` across the four tiers (override > env > shared > app) as a ``Secret``,
        or ``None`` when unset everywhere. A blank value at any tier is treated as absent.

        ``namespace`` scopes only this app's OWN store tier: the override and the environment
        variable are resolved by ``name`` alone, and a ``shared`` store is read at its own flat
        layout -- so the same ``name`` reads the same env var and the same shared key whatever the
        namespace. The namespace isolates where this app's own value is stored, not which env var
        names it nor how a shared store is read.

        Raises:
            InvalidSecretTypeError: ``override`` is neither a ``str`` nor a ``Secret`` (also a
                ``TypeError``). Checked before the store is touched.
            InvalidAppNameError: the store binding is malformed and a store tier had to be consulted
                (the override/env tiers never reach this -- the binding is validated lazily).
            CredentialsError: a consulted store is present but unreadable or malformed.
            DecryptionError: with an encrypted backend, a store could not be decrypted (a wrong
                passphrase or tampering) -- a sibling of ``CredentialsError`` under ``CredBoxError``,
                so catch ``CredBoxError`` to cover both, or ``DecryptionError`` to single it out.
        """
        if override is not None:
            if not isinstance(override, (str, Secret)):
                raise InvalidSecretTypeError(
                    f"override must be a str or Secret, not {type(override).__name__}")
            raw = override.reveal() if isinstance(override, Secret) else override
            cleaned = raw.strip()
            if cleaned:
                return Secret(cleaned)
        from_env = env_value(name)
        if from_env is not None:
            return Secret(from_env)
        # Only now is the binding needed, so only now is it validated -- an override/env hit above
        # returned without ever touching, or validating, the store.
        binding = self._binding()
        self._warn_orphaned_once()
        for shared_app_name in binding.shared:
            # A shared store is a cross-app common store (many apps read it), flat by nature -- so
            # read it at its own flat layout, NOT scoped by this component's namespace. Scoping it
            # would force the shared key into the component's section, where an embedded component
            # would miss it (or fault on the flat store's layout). The namespace scopes the OWN
            # store only.
            value = self._backend.get(shared_app_name, name)
            if value is not None:
                return value
        return self._backend.get(binding.app, name, **binding.namespace_kwargs)

    def require(self, name: str, *, override: str | Secret | None = None) -> Secret:
        """Like ``secret`` but raise when the secret is unset everywhere -- for a key the caller
        cannot proceed without. The error is content-free (it names ``name`` and the app, never a
        value).

        Raises:
            CredentialsError: ``name`` resolves to nothing across all tiers, or a consulted store
                is malformed.
            InvalidSecretTypeError: ``override`` is neither a ``str`` nor a ``Secret`` (forwarded
                from ``secret``).
            InvalidAppNameError: the store binding is malformed -- when no override or environment
                value satisfies the request, ``require`` reaches the store tier that validates it.
            DecryptionError: with an encrypted backend, a store could not be decrypted (catch
                ``CredBoxError`` to cover both, or ``DecryptionError`` to single it out).
        """
        value = self.secret(name, override=override)
        if value is None:
            # Backend-neutral hint: the env var works for every backend, but do not name a
            # specific store command -- `credbox set` writes the plaintext file store, which the
            # encrypted backend never reads, so hard-coding it would misdirect that consumer.
            # A None return means every tier was consulted, so `secret` already validated and
            # cached the binding via `_binding()` -- this is a cache hit, not a re-validation.
            raise CredentialsError(
                f"required secret {name!r} is not set for {self._binding().app}: set the {name} "
                f"environment variable, or store it for this app"
            )
        return value

    def set(self, name: str, *, value: str | Secret) -> None:
        """Store ``value`` (a ``str`` or ``Secret``) under ``name`` in this app's own store
        (never a shared one). ``value`` is keyword-only so it cannot be swapped with ``name``.

        Surrounding whitespace is stripped before storing, so the stored file holds exactly what
        ``secret`` returns (resolution strips every tier, so a pasted key's trailing newline never
        survives a read). Do NOT store a secret whose leading or trailing whitespace is significant:
        it is stripped on both write and read and cannot be preserved.

        Raises:
            BlankSecretError: ``name`` or ``value`` is empty or whitespace-only. A blank value
                would list under ``names`` yet resolve to ``None``; a blank name is unresolvable --
                both are refused to keep set and get consistent. A subclass of both ``CredBoxError``
                and ``ValueError``.
            InvalidSecretTypeError: ``value`` is neither ``str`` nor ``Secret`` -- a contract
                violation reachable only from a dynamically-typed caller. Also a ``TypeError`` (so
                ``except TypeError`` still catches it) and a ``CredBoxError`` (so a store guard
                catches it too); the message names the type only, never the value.
            InvalidAppNameError: the store binding is malformed (validated lazily, on this write).
            CredentialsError: the store could not be written.
            DecryptionError: with an encrypted backend, the existing store had to be read to
                merge the new value and could not be decrypted (a wrong passphrase or tampering).
        """
        if not name or not name.strip():
            raise BlankSecretError("refusing to store under a blank name")
        raw = value.reveal() if isinstance(value, Secret) else value
        if not isinstance(raw, str):
            # A non-str, non-Secret value (a contract violation) must not reach json.dumps, whose
            # TypeError would carry the value in its traceback frame -- name only the type.
            raise InvalidSecretTypeError(f"value must be a str or Secret, not {type(raw).__name__}")
        raw = raw.strip()
        if not raw:
            raise BlankSecretError(f"refusing to store a blank value for {name!r}")
        binding = self._binding()
        self._warn_orphaned_once()
        self._backend.set(binding.app, name, value=raw, **binding.namespace_kwargs)

    def unset(self, name: str) -> None:
        """Remove ``name`` from this app's own store; a no-op when absent.

        Raises:
            InvalidAppNameError: the store binding is malformed (validated lazily, on this call).
            CredentialsError: the store could not be written.
            DecryptionError: with an encrypted backend, the existing store had to be read to
                remove the name and could not be decrypted (a wrong passphrase or tampering).
        """
        binding = self._binding()
        self._warn_orphaned_once()
        self._backend.unset(binding.app, name, **binding.namespace_kwargs)

    def names(self) -> list[str]:
        """The secret names stored in this app's own store, sorted -- never the values. With a
        keyring backend this lists only the file-fallback names (the OS keyring cannot enumerate
        its keys).

        Raises:
            InvalidAppNameError: the store binding is malformed (validated lazily, on this call).
            CredentialsError: the store is present but malformed.
            DecryptionError: with an encrypted backend, the store could not be decrypted (catch
                ``CredBoxError`` to cover both, or ``DecryptionError`` to single it out).
        """
        binding = self._binding()
        self._warn_orphaned_once()
        return self._backend.names(binding.app, **binding.namespace_kwargs)

    def migrate_to(self, dest: Credentials, *, remove_source: bool = False) -> MigrationResult:
        """Copy this store's secrets into ``dest`` (or move them with ``remove_source=True``),
        returning a ``MigrationResult``. Reads each STORED value (never the environment or an
        override) and writes it under ``dest``'s binding.

        Durability: for the ordinary case (a different app, or the same app namespace->namespace) the
        destination is written FIRST and the source removed only after, so a failed write leaves the
        source intact -- nothing is ever lost. A same-app flat->namespace conversion is the one
        exception: the two layouts cannot share a file, so the flat source is cleared before the
        namespaced destination is written (an inherent move; with a per-key store it holds the values
        in memory across the swap). The layout rules assume the single-file (file/encrypted) store;
        for the keyring backend, whose flat and namespaced entries coexist, they are conservative
        but safe.

        Raises:
            InvalidMigrationError: the request is not a legal migration -- ``dest`` is the SAME store
                (same app and namespace), or it is a same-app namespaced->flat conversion (which
                cannot be done safely, because a surviving sibling namespace would fault the flat
                write after the source is cleared; migrate to a different app instead). Also a
                ``ValueError``, so ``except ValueError`` and ``except CredBoxError`` both catch it.
            InvalidAppNameError: either binding is malformed (validated on access).
            CredentialsError / DecryptionError: a store could not be read or written.
        """
        # The physical store is identified by (backend kind, app, namespace): a different backend on
        # the same app+namespace is a DIFFERENT store (e.g. a plaintext->encrypted upgrade,
        # credentials.json vs credentials.enc), so the same-store and same-file tests fold the backend
        # in too -- otherwise a legitimate cross-backend migration would be misjudged.
        is_same_backend = type(self._backend) is type(dest._backend)
        if is_same_backend and (self.app, self.namespace) == (dest.app, dest.namespace):
            raise InvalidMigrationError("source and destination are the same store")
        is_same_file = is_same_backend and self.app == dest.app
        has_layout_conflict = is_same_file and (self.namespace is None) != (dest.namespace is None)
        if has_layout_conflict and self.namespace is not None:
            raise InvalidMigrationError(
                "cannot migrate a namespaced store to the flat layout of the same app; "
                "migrate to a different app instead"
            )
        binding = self._binding()
        source_names = self._backend.names(binding.app, **binding.namespace_kwargs)
        stored_secrets: list[tuple[str, Secret]] = []
        for name in source_names:
            value = self._backend.get(binding.app, name, **binding.namespace_kwargs)
            if value is not None:
                stored_secrets.append((name, value))

        if has_layout_conflict:
            # Same file, flat -> namespaced: the layouts cannot coexist, so the flat source must be
            # cleared before the namespaced destination is written. Inherently a move; the values are
            # held in memory across the swap, and the emptied file ({}) is valid in either layout. The
            # destination namespace is necessarily new (the file was flat), so nothing is overwritten.
            # Clear by the FULL key list, not stored_secrets -- a blank-valued key (get() reads it as
            # absent, so it is not in stored_secrets) must still be removed, or it would leave the file
            # flat and fault the namespaced write after the good keys were already cleared.
            n_overwritten = 0
            for name in source_names:
                self.unset(name)
            for name, value in stored_secrets:
                dest.set(name, value=value)
            moved = True
        else:
            # Cross-file, or same-file namespace->namespace: write the destination FIRST, then remove
            # the source only if asked -- so a failed write leaves the source intact, losing nothing.
            existing = set(dest.names())   # safe to read: no layout conflict blocks it
            n_overwritten = sum(1 for name, _ in stored_secrets if name in existing)
            for name, value in stored_secrets:
                dest.set(name, value=value)
            if remove_source:
                # Empty the source FULLY (by the whole key list, not just the migrated ones), so a
                # blank-valued key does not survive the move -- symmetric with the flat->ns branch.
                for name in source_names:
                    self.unset(name)
            moved = remove_source
        return MigrationResult(migrated=len(stored_secrets), overwritten=n_overwritten, moved=moved)

    @property
    def app(self) -> str:
        """The resolved store app -- the app whose store this reads and writes, after any
        ``for_app`` redirect. Validated on access (a malformed binding raises
        ``InvalidAppNameError``)."""
        return self._binding().app

    @property
    def namespace(self) -> str | None:
        """The resolved namespace scoping this app's own store, or ``None`` for a flat store.
        Validated on access (a malformed binding raises ``InvalidAppNameError``)."""
        return self._binding().namespace

    def store_location(self) -> str:
        """A secret-free, human-readable description of WHERE this app's secrets are stored -- the
        backend-resolved file path or keyring service, honoring any ``for_app`` redirect and
        namespace. For a setup wizard to show the user, instead of recomputing (and drifting from)
        the store path: it reflects the actual backend and resolved binding, so it stays correct
        under embedding and across backends. A backend that predates the ``SupportsLocationDescription``
        capability (0.4.0) yields a generic ``<BackendType> store for app '...'`` description instead
        of a concrete path.

        Raises:
            InvalidAppNameError: the store binding is malformed (validated on access).
        """
        binding = self._binding()
        if isinstance(self._backend, SupportsLocationDescription):
            return self._backend.describe_location(binding.app, namespace=binding.namespace)
        # A custom backend written against the four-operation SecretBackend interface only: fall
        # back to a generic but still-useful description rather than failing.
        scope = "" if binding.namespace is None else f", namespace {binding.namespace!r}"
        return f"{type(self._backend).__name__} store for app {binding.app!r}{scope}"


def _warn_if_own_store_orphaned(
    legacy_app: str, store_app: str, store_namespace: str | None, backend: SecretBackend | None
) -> None:
    """Warn, once per app, when a ``for_app`` redirect leaves the component's OWN (pre-embed) store
    holding secrets the redirect can no longer reach -- so a user upgrading into a host discovers
    their standalone keys did not move, and the exact command (the resolved binding) to move them.

    Best-effort discoverability only, on three counts, so it can never break the store access it
    rides on: (1) the once-per-app guard is claimed under the lock BEFORE the read, so the legacy
    store is probed at most once per app per process (no re-read on every fresh instance, and no
    concurrent duplicate probe); (2) it swallows any backend/filesystem error from that read (a
    broken or absent legacy store must not raise); (3) it suppresses even ``warnings.warn`` itself,
    so a strict ``-W error`` / ``filterwarnings=error`` filter cannot turn a nudge into a fatal
    error. The printed command carries the resolved binding AND ``--remove-source``, so running it
    actually empties the legacy store and stops the warning from recurring next process."""
    with _warn_lock:
        if legacy_app in _warned_legacy_orphan:
            return
        _warned_legacy_orphan.add(legacy_app)   # claim before the read: probe at most once per app
    try:
        legacy = Credentials(legacy_app, backend=backend)   # the component's own, flat, pre-redirect store
        if not legacy.names():
            return
        where = legacy.store_location()
    except Exception:
        # A pure discoverability nudge must never be load-bearing: swallow ANY failure of the legacy
        # read (a malformed store, a custom backend raising something other than CredBoxError/OSError),
        # so it can never break the store access it rides on.
        return
    to_namespace = "" if store_namespace is None else f" --to-namespace {store_namespace}"
    with contextlib.suppress(Exception):
        warnings.warn(
            f"{legacy_app!r} is redirected to store {store_app!r}, but its own store ({where}) still "
            f"holds secrets the redirect cannot reach; move them with "
            f"'credbox migrate --from-app {legacy_app} --to-app {store_app}{to_namespace} --remove-source'",
            stacklevel=4,
        )
