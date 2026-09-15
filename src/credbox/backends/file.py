"""The zero-dep file backend: a ``name -> secret`` JSON map in ``credentials.json`` under
``config_dir(app)`` -- flat, or namespaced (``namespace -> {name -> secret}``) when a caller
scopes its operations to a namespace -- written atomically at mode 0600 in a directory tightened
to 0700.

It is the reliable base everywhere -- no OS session, no network, portable across machines, the
same headless as on a desktop -- and it is TERMINAL: it has no fallback. Reads route through a
leak-safe decoder (a malformed file yields a content-free fault, never an exception carrying the
file's bytes); writes serialize the whole read-modify-write under a cross-process lock so
concurrent writers do not lose each other's keys.
"""

from __future__ import annotations

from pathlib import Path

from credbox._store_codec import (
    StoreFault,
    StoreFaultKind,
    layout_mismatch_hint,
    parse_store,
    serialize_store,
)
from credbox.atomic import write_bytes_atomic
from credbox.backends._store import CREDENTIALS_FILE, exclusive_store_lock, normalize_secret_value
from credbox.errors import CredBoxError, CredentialsError
from credbox.paths import config_dir
from credbox.permissions import (
    PRIVATE_FILE_MODE,
    warn_if_group_or_world_readable,
)
from credbox.secret import Secret

__all__ = ["FileBackend"]


class FileBackend:
    """Secrets in ``credentials.json`` (a JSON object -- flat ``name -> secret``, or namespaced
    ``namespace -> {name -> secret}``) under ``config_dir(app)``, written atomically at mode 0600
    in a directory tightened to 0700. Terminal -- no fallback."""

    def path(self, app: str) -> Path:
        """The credentials file for ``app``: ``credentials.json`` in ``config_dir(app)``."""
        return config_dir(app) / CREDENTIALS_FILE

    def get(self, app: str, name: str, *, namespace: str | None = None) -> Secret | None:
        """Return the value stored under ``name`` (within ``namespace`` when given) as a ``Secret``,
        or ``None`` when the file, namespace, or key is absent (or the value is blank). Warns once
        if the file is readable beyond its owner.

        Raises:
            CredentialsError: the file exists but is unreadable, not UTF-8, not JSON, not a JSON
                object, or holds the wrong shape for the requested mode (a flat value read as a
                namespace object, or the reverse) -- built from the fault kind and JSON position
                only, never the file's content.
        """
        if namespace is None:
            by_name = self._load_flat(app)
        else:
            by_name = self._load_nested(app).get(namespace, {})
        cleaned = normalize_secret_value(by_name.get(name))
        return Secret(cleaned) if cleaned is not None else None

    def set(self, app: str, name: str, *, value: str | Secret,
            namespace: str | None = None) -> None:
        """Store ``value`` (a ``str`` or ``Secret``) under ``name`` (within ``namespace`` when
        given) at mode 0600 in a 0700 directory. The whole read-modify-write is serialized -- across
        threads and, wherever the OS file lock can be taken, across processes -- so concurrent
        writers, including writers to OTHER namespaces of the same store, do not lose keys.

        Raises:
            CredentialsError: the existing file is unreadable or malformed, or the write failed.
        """
        raw = value.reveal() if isinstance(value, Secret) else value
        with exclusive_store_lock(self.path(app)):
            if namespace is None:
                flat = self._load_flat(app)
                flat[name] = raw
                self._save(app, flat)
            else:
                nested = self._load_nested(app)
                nested.setdefault(namespace, {})[name] = raw
                self._save(app, nested)

    def unset(self, app: str, name: str, *, namespace: str | None = None) -> None:
        """Remove ``name`` (within ``namespace`` when given) if present; an idempotent no-op when
        the file, namespace, or key is absent. The read-modify-write is serialized (see ``set``),
        and other namespaces are preserved.

        Raises:
            CredentialsError: the existing file is unreadable or malformed, or the write failed.
        """
        with exclusive_store_lock(self.path(app)):
            if namespace is None:
                flat = self._load_flat(app)
                if name in flat:
                    del flat[name]
                    self._save(app, flat)
            else:
                nested = self._load_nested(app)
                submap = nested.get(namespace)
                if submap is not None and name in submap:
                    del submap[name]
                    if not submap:
                        del nested[namespace]   # drop the now-empty namespace, not an empty {}
                    self._save(app, nested)

    def names(self, app: str, *, namespace: str | None = None) -> list[str]:
        """The stored key names (within ``namespace`` when given), sorted -- never the values.

        Raises:
            CredentialsError: the file exists but is unreadable or malformed.
        """
        if namespace is None:
            return sorted(self._load_flat(app))
        return sorted(self._load_nested(app).get(namespace, {}))

    def _read(self, app: str) -> bytes | None:
        """The raw store bytes, or ``None`` when the file is absent. Warns once when the file is
        readable beyond its owner. Shared by the flat and nested loaders so the read/warn path lives
        in one place."""
        path = self.path(app)
        try:
            store_bytes = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as err:
            # An I/O error carries no file content; keep the errno detail.
            raise CredentialsError(f"could not read {path}: {err}") from err
        warn_if_group_or_world_readable(path, app=app)
        return store_bytes

    def _load_flat(self, app: str) -> dict[str, str]:
        """Parse ``credentials.json`` as a flat ``name -> secret`` map, or ``{}`` when absent. A
        malformed file becomes a content-free ``CredentialsError`` via ``_store_codec`` -- the raw
        bytes die in ``parse_store``'s returning frame and are not bound at this raise site."""
        store_bytes = self._read(app)
        if store_bytes is None:
            return {}
        result = parse_store(store_bytes)
        del store_bytes   # drop this frame's copy of the raw bytes before any raise
        if isinstance(result, StoreFault):
            raise _fault_error(self.path(app), result, nested=False)
        return result

    def _load_nested(self, app: str) -> dict[str, dict[str, str]]:
        """Parse ``credentials.json`` as a two-level ``namespace -> {name -> secret}`` map, or
        ``{}`` when absent. Same leak-safe returning-frame contract as ``_load_flat``."""
        store_bytes = self._read(app)
        if store_bytes is None:
            return {}
        result = parse_store(store_bytes, nested=True)
        del store_bytes
        if isinstance(result, StoreFault):
            raise _fault_error(self.path(app), result, nested=True)
        return result

    def _save(self, app: str, store: dict[str, str] | dict[str, dict[str, str]]) -> None:
        """Serialize the store (flat or nested) and write it back to ``credentials.json`` atomically
        at mode 0600. The config directory was already hardened to 0700 by ``exclusive_store_lock``,
        which wraps every ``set``/``unset`` -- so this method does not repeat that.

        The plaintext map is a live frame-local here (the caller handed it to us to store); the
        *raised* ``CredentialsError`` carries only the path/errno, never a value -- the object-
        level guarantee, not a claim that no plaintext exists in the frame (see _store_codec)."""
        path = self.path(app)
        encoded = serialize_store(store)
        if isinstance(encoded, StoreFault):
            raise CredentialsError(f"{path} could not be serialized: a value is not encodable")
        try:
            write_bytes_atomic(path, encoded, mode=PRIVATE_FILE_MODE)
        except CredBoxError as err:
            raise CredentialsError(str(err)) from err


def _fault_error(path: Path, fault: StoreFault, *, nested: bool) -> CredentialsError:
    """A content-free ``CredentialsError`` describing a ``StoreFault`` -- built from the enum
    and the integer JSON position only, in a frame where no secret local is bound. ``nested`` is
    the layout the read expected, used only to append a diagnostic hint when the fault looks like a
    flat-vs-namespaced mismatch (never any store content)."""
    kind = fault.kind
    if kind is StoreFaultKind.NOT_UTF8:
        detail = "not valid UTF-8"
    elif kind is StoreFaultKind.NOT_JSON:
        detail = f"not valid JSON (line {fault.lineno}, column {fault.colno})"
    elif kind is StoreFaultKind.NOT_OBJECT:
        detail = "not a JSON object of name to value"
    elif kind is StoreFaultKind.NOT_STRING_VALUE:
        detail = "a JSON object with a non-string value"
    else:
        detail = "malformed"
    return CredentialsError(f"{path} is {detail}{layout_mismatch_hint(nested=nested, kind=kind)}")
