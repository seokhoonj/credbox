"""The OS keyring backend ([keyring] extra), with a file ``fallback`` for headless machines.

When the OS keyring has no backend (cron, containers, servers) the operation is delegated to
``fallback`` in full and a one-time, content-free warning is printed so the user knows their
secrets are in the file, not the keyring. When the keyring works it is authoritative, and a
successful write/delete also clears any stale plaintext copy from the fallback.

**Leak contract.** A keyring call can raise a third-party exception whose ``str()``
embeds a secret. Every such exception is caught *inside* a returning-frame helper
(``_try_keyring_*``) and never escapes; the ``CredentialsError`` a caller sees is built from safe
fields only (``app``, ``name``, a fixed phrase) and raised where no exception is in flight, so
both ``__cause__`` AND ``__context__`` are ``None`` (a bare ``raise ... from None`` would leave
the secret-bearing exception on ``__context__``). The warn-once message is content-free too.

One direction cannot be fully closed: a value written to the file fallback *while the keyring is
down* is not migrated into the keyring on recovery. If on recovery the keyring holds no entry for
that name, ``get`` consults the file and returns it; but if the keyring still holds an older value,
that older value shadows the newer file value (the keyring is authoritative on a conflict).
Re-set the key while the keyring is reachable.
"""

from __future__ import annotations

import contextlib
import sys
import threading
from typing import Literal

from credbox.backends._store import normalize_secret_value
from credbox.backends.protocol import SecretBackend
from credbox.errors import CredentialsError, NoKeyringError
from credbox.secret import Secret

__all__ = ["KeyringBackend"]

# The closed vocabulary the returning-frame helpers report. Typed so mypy --strict rejects an
# off-vocabulary literal at either the producer or a call site -- the branch that chooses between a
# content-free raise and a file fallback must not mis-branch on a typo.
KeyringStatus = Literal["ok", "no_backend", "failed"]

_warned_keyring_fallback = False
_warn_lock = threading.Lock()


class KeyringBackend:
    """Secrets in the OS keyring (username = ``name``; service = ``app`` for the flat store, or the
    namespace-folded ``app/namespace`` when a namespace is given), with a file ``fallback`` for
    machines where no keyring backend exists.

    Keyring entries are independent items, so an app's flat and namespaced keyring entries can
    coexist -- the "an app's store is wholly flat or wholly namespaced" rule is a property of the
    single-file (file/encrypted) stores, not of the keyring."""

    def __init__(self, *, fallback: SecretBackend | None = None) -> None:
        self._fallback = fallback

    def __repr__(self) -> str:
        fallback = type(self._fallback).__name__ if self._fallback is not None else None
        return f"KeyringBackend(fallback={fallback})"

    def get(self, app: str, name: str, *, namespace: str | None = None) -> Secret | None:
        """Return the keyring value for ``name`` (within ``namespace`` when given) as a ``Secret``,
        or ``None`` when set nowhere. Falls back to the file ONLY when no keyring backend exists at
        all (`no_backend`, warning once), and when the keyring is reachable but empty (so a value
        written to the file while the keyring was structurally absent stays readable after
        recovery). **Fails closed on a keyring error** -- it does NOT serve a stale file value in
        place of the authoritative keyring value.

        Raises:
            NoKeyringError: no keyring backend exists and no fallback is configured.
            CredentialsError: the keyring is present but the read failed (fail-closed -- the file
                fallback is NOT consulted on a keyring error), or a consulted fallback file is
                malformed.
        """
        service = _keyring_service(app, namespace)
        status, raw = _try_keyring_get(service, name)
        if status == "no_backend":
            return self._fallback_get(app, name, namespace)
        if status == "failed":
            # Fail closed: a present-but-erroring keyring must NOT silently serve a stale (or
            # attacker-planted) file value in place of the authoritative keyring value. Raised
            # where no exception is in flight (it died in _try_keyring_get), so content-free.
            raise _keyring_operation_error(service, name)
        cleaned = normalize_secret_value(raw)
        if cleaned is not None:
            return Secret(cleaned)
        if self._fallback is not None:
            return self._fallback.get(app, name, **_fallback_namespace_kwargs(namespace))
        return None

    def set(self, app: str, name: str, *, value: str | Secret,
            namespace: str | None = None) -> None:
        """Store ``value`` in the keyring (within ``namespace`` when given); a successful write also
        clears any stale plaintext copy from the fallback file. Falls back to the file ONLY when no
        keyring backend exists at all (`no_backend`, warning once). **Fails closed on a keyring
        error** -- it does NOT silently write plaintext to the fallback, which would report success
        while the keyring's old value keeps shadowing this write on recovery.

        Raises:
            NoKeyringError: no keyring backend exists and no fallback is configured.
            CredentialsError: the keyring is present but the write failed (fail-closed -- no
                plaintext is written to the fallback); or the write succeeded but a stale file copy
                could not be cleared.
        """
        raw = value.reveal() if isinstance(value, Secret) else value
        service = _keyring_service(app, namespace)
        status = _try_keyring_set(service, name, raw)
        if status == "no_backend":
            self._fallback_set(app, name, raw, namespace)
            return
        if status == "failed":
            # Fail closed: do NOT silently write plaintext to the fallback on a keyring error --
            # that would report success while the keyring's OLD value still shadows this write on
            # recovery (a rotation that silently does not take effect). Content-free, no in-flight exc.
            raise _keyring_operation_error(service, name)
        if self._fallback is not None:
            try:
                self._fallback.unset(app, name, **_fallback_namespace_kwargs(namespace))
            except CredentialsError as err:
                raise CredentialsError(
                    f"stored {service}/{name} in the keyring, but a stale plaintext copy may remain "
                    f"in the file store and could not be cleared"
                ) from err

    def unset(self, app: str, name: str, *, namespace: str | None = None) -> None:
        """Remove ``name`` (within ``namespace`` when given) from the keyring and from any fallback
        file copy; an idempotent no-op when absent. Fails closed: a keyring present but erroring on
        delete raises rather than silently reporting a delete that may not have happened.

        Raises:
            NoKeyringError: no keyring backend exists and no fallback is configured.
            CredentialsError: the keyring is present but the delete failed; or the delete
                succeeded but a stale file copy could not be cleared.
        """
        service = _keyring_service(app, namespace)
        status = _try_keyring_delete(service, name)
        if status == "no_backend":
            if self._fallback is not None:
                _warn_keyring_fallback_once()
                self._fallback.unset(app, name, **_fallback_namespace_kwargs(namespace))
                return
            raise _no_backend_error(service, name)
        if status == "failed":
            # Keyring present but the delete genuinely failed: do NOT report success while the
            # secret may still be retrievable. Content-free -- no in-flight exception here.
            raise _keyring_operation_error(service, name)
        if self._fallback is not None:
            try:
                self._fallback.unset(app, name, **_fallback_namespace_kwargs(namespace))
            except CredentialsError as err:
                raise CredentialsError(
                    f"deleted {service}/{name} from the keyring, but a stale plaintext copy may "
                    f"remain in the file store and could not be cleared"
                ) from err

    def names(self, app: str, *, namespace: str | None = None) -> list[str]:
        """The fallback file's stored key names (within ``namespace`` when given), sorted. The OS
        keyring cannot enumerate its own keys, so a key stored solely in the keyring is not listed.

        Raises:
            CredentialsError: the fallback file is present but malformed.
        """
        return self._fallback.names(app, **_fallback_namespace_kwargs(namespace)) if self._fallback is not None else []

    def _fallback_get(self, app: str, name: str, namespace: str | None) -> Secret | None:
        """Delegate to the file fallback (the legitimate headless `no_backend` case), warning
        once; raise `NoKeyringError` when no fallback is configured."""
        if self._fallback is not None:
            _warn_keyring_fallback_once()
            return self._fallback.get(app, name, **_fallback_namespace_kwargs(namespace))
        raise _no_backend_error(_keyring_service(app, namespace), name)

    def _fallback_set(self, app: str, name: str, raw: str, namespace: str | None) -> None:
        if self._fallback is not None:
            _warn_keyring_fallback_once()
            self._fallback.set(app, name, value=raw, **_fallback_namespace_kwargs(namespace))
            return
        raise _no_backend_error(_keyring_service(app, namespace), name)


def _fallback_namespace_kwargs(namespace: str | None) -> dict[str, str]:
    """The ``namespace`` keyword to forward to the fallback backend -- empty when ``None``, so a
    fallback written against the original four-method protocol (no ``namespace`` parameter) is
    called exactly as before; only a namespaced operation passes it."""
    return {} if namespace is None else {"namespace": namespace}


def _keyring_service(app: str, namespace: str | None) -> str:
    """The OS-keyring service name for ``app``'s store, folded with ``namespace`` when given
    (``app/namespace``), so a namespaced component's keyring entries do not collide with the app's
    flat entries or with another namespace's -- the keyring analogue of a namespace object in the
    file store."""
    return app if namespace is None else f"{app}/{namespace}"


def _no_backend_error(service: str, name: str) -> NoKeyringError:
    """A content-free error for "no OS keyring backend, and no fallback", raised where no
    third-party exception is in flight so ``__cause__`` and ``__context__`` are both ``None``."""
    return NoKeyringError(
        f"no OS keyring backend available for {service}/{name} and no fallback is configured"
    )


def _keyring_operation_error(service: str, name: str) -> CredentialsError:
    """A content-free error for a present-but-erroring keyring (fail-closed), raised where no
    third-party exception is in flight so ``__cause__`` and ``__context__`` are both ``None``."""
    return CredentialsError(
        f"keyring operation failed for {service}/{name}: the OS keyring is present but returned an "
        f"error (check that the keyring/keychain service is running and unlocked)"
    )


# --- returning-frame keyring calls (the third-party exception dies here) --------
#
# Each helper catches every keyring exception INSIDE its own frame and returns a status string,
# so the exception never reaches a caller frame. That is what lets KeyringBackend raise a
# content-free CredentialsError with __context__ == None: at the raise site there is no exception
# in flight to become the implicit context. The `import keyring` guard is `except Exception` (not
# just ImportError) because executing keyring's __init__ (backend/D-Bus discovery) can raise a
# non-ImportError, which must be folded into a status here rather than escape as a raw traceback
# whose frame retains `raw`.
#
# The catch is deliberately total -- it does NOT re-raise MemoryError the way _store_codec/scrub do.
# All three run with a secret in frame (_try_keyring_set holds `raw`), so the difference is not
# "who has a secret" but what swallowing PRODUCES. _store_codec/scrub let MemoryError propagate only
# because their swallow-alternative is worse than the frame-locals exposure -- a misclassified
# fault, or a returned still-unscrubbed string. Here swallowing yields a safe status instead ("failed"
# -> fail-closed raise; "no_backend" -> file fallback), so there is nothing to trade: folding a
# swallowed OOM to a status keeps `raw` off the propagating traceback at no cost. BaseException
# (KeyboardInterrupt/SystemExit) is not an Exception, so it still propagates -- carrying no secret
# text of its own, though `raw` would sit in this frame; that is the interpreter tearing down.


def _try_keyring_get(service: str, name: str) -> tuple[KeyringStatus, str | None]:
    """Return ``("ok", value)``, ``("no_backend", None)``, or ``("failed", None)``. ``service`` is
    the namespace-folded app name (see ``_keyring_service``)."""
    try:
        import keyring
        import keyring.errors
    except Exception:
        return "no_backend", None
    try:
        return "ok", keyring.get_password(service, name)
    except keyring.errors.NoKeyringError:
        return "no_backend", None
    except Exception:
        return "failed", None


def _try_keyring_set(service: str, name: str, raw: str) -> KeyringStatus:
    """Return ``"ok"``, ``"no_backend"``, or ``"failed"``. ``service`` is the namespace-folded app
    name (see ``_keyring_service``)."""
    try:
        import keyring
        import keyring.errors
    except Exception:
        return "no_backend"
    try:
        keyring.set_password(service, name, raw)
        return "ok"
    except keyring.errors.NoKeyringError:
        return "no_backend"
    except Exception:
        return "failed"


def _try_keyring_delete(service: str, name: str) -> KeyringStatus:
    """Return ``"ok"`` (deleted, including an already-absent key), ``"no_backend"``, or
    ``"failed"``. ``service`` is the namespace-folded app name (see ``_keyring_service``)."""
    try:
        import keyring
        import keyring.errors
    except Exception:
        return "no_backend"
    try:
        keyring.delete_password(service, name)
        return "ok"
    except keyring.errors.PasswordDeleteError:
        return "ok"   # already absent -- unset is idempotent
    except keyring.errors.NoKeyringError:
        return "no_backend"
    except Exception:
        return "failed"


def _warn_keyring_fallback_once() -> None:
    """Warn once, on stderr, that the OS keyring is unavailable and secrets are going to the file
    backend instead. Content-free: it never interpolates the third-party error, whose text could
    embed a secret."""
    global _warned_keyring_fallback
    if _warned_keyring_fallback:
        return   # fast path: once warned, every later fallback op skips the lock entirely
    with _warn_lock:
        if _warned_keyring_fallback:   # re-check under the lock (double-checked locking)
            return
        _warned_keyring_fallback = True
    # Suppress a failing stderr write (e.g. a closed fd): the warning is best-effort and must not
    # abort the fallback operation it precedes.
    with contextlib.suppress(OSError):
        print(
            "credbox: warning: OS keyring unavailable; using the file backend "
            "(credentials.json, mode 0600) instead",
            file=sys.stderr,
        )
