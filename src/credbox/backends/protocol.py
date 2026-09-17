"""The ``SecretBackend`` protocol: the seam every store implementation satisfies.

A backend answers, for an ``(app, name)`` pair: read (``get``), write (``set``), remove
(``unset``), or list the names (``names``). ``get`` returns a ``Secret`` (never a raw ``str``),
so a resolved value cannot land in a log by accident; ``set`` accepts a ``str`` or a ``Secret``.
``value`` is keyword-only so it can never be swapped with ``name`` positionally -- a swap would
store the secret *as a key name*.

``namespace`` (keyword-only, default ``None``) selects a component's sub-store WITHIN one app's
store, so several components can share one app's store without their keys colliding.
``namespace=None`` is the flat store (the original layout, unchanged); a non-``None`` namespace
scopes every operation to that namespace alone and leaves the others untouched.

A backend TRUSTS its ``(app, name, namespace)`` inputs -- it does not validate them, exactly as it
does not validate ``name`` (an arbitrary key). The validating boundary is the ``Credentials`` facade,
which validates ``app``, every ``shared`` name, and a non-``None`` ``namespace`` (as a single path
segment with no ``/``) before any of them reaches a backend. A backend then composes ``namespace``
into a storage key (the keyring folds it into the service name ``app/namespace``); a caller driving a
backend DIRECTLY, bypassing the facade, is responsible for passing a segment with no ``/`` so a
namespace cannot collide with the flat ``app`` service or another namespace.

``namespace`` is new in 0.2.0. ``Credentials`` omits it entirely from the call for a flat
(``namespace=None``) resolution -- it makes the exact pre-0.2.0 four-argument call -- so a backend
written against the original protocol (without a ``namespace`` parameter) keeps working unchanged
for flat use; a backend that means to support namespaces must accept this keyword.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from credbox.secret import Secret

__all__ = ["SecretBackend", "SupportsLocationDescription"]


class SecretBackend(Protocol):
    """The store interface every backend implements.

    ``get`` returns the stored value as a ``Secret``, or ``None`` when the store or key is
    absent. The value is normalized on read -- surrounding whitespace is stripped and a
    whitespace-only value reads back as absent (``None``), so a blank falls through to the next
    resolution tier and never wins as an empty ``Secret``. ``set``/``unset`` mutate the
    store; ``names`` lists the stored keys, never their values. When the store is present but
    unusable a method raises a ``CredBoxError`` -- a ``CredentialsError`` for an unreadable or
    malformed store (or an absent required backend), or a ``DecryptionError`` from the encrypted
    backend when the store cannot be decrypted; a caller that wants to cover every backend
    catches the ``CredBoxError`` base, since ``DecryptionError`` is a sibling of
    ``CredentialsError``, not a subtype. ``unset`` on a missing name is an idempotent no-op, not
    an error.
    """

    def get(self, app: str, name: str, *, namespace: str | None = None) -> Secret | None: ...
    def set(self, app: str, name: str, *, value: str | Secret,
            namespace: str | None = None) -> None: ...
    def unset(self, app: str, name: str, *, namespace: str | None = None) -> None: ...
    def names(self, app: str, *, namespace: str | None = None) -> list[str]: ...


@runtime_checkable
class SupportsLocationDescription(Protocol):
    """An OPTIONAL capability a backend may add on top of ``SecretBackend`` (new in 0.4.0): a
    secret-free, human-readable description of WHERE it keeps an app's secrets -- a file path, or an
    OS-keyring service name -- for a setup wizard to show the user. Kept off ``SecretBackend`` so a
    backend written against the four-operation interface still satisfies it; ``Credentials.store_location``
    narrows with ``isinstance`` and falls back to a generic description when a backend lacks it. All
    of credbox's own backends (file, encrypted, keyring) implement it."""

    def describe_location(self, app: str, *, namespace: str | None = None) -> str: ...
