"""The encrypted file backend ([crypto] extra): a single AES-GCM blob keyed by an Argon2id hash
of a passphrase.

TERMINAL -- there is no fallback: a decrypt failure (wrong passphrase or tampering) FAILS CLOSED
with a content-free ``DecryptionError``, never a plaintext downgrade. The store is ONE atomically
written file so a header and ciphertext cannot desync:

    header_len(4, big-endian) || header(JSON) || nonce(12) || ciphertext_and_tag

The header carries all KDF params and is bound as the AES-GCM associated data (AAD), so params or
version cannot be downgraded unauthenticated. The key is re-derived from the header's own params
on read (after clamping them, so a tampered header cannot force a huge Argon2id allocation before
the tag check can reject it). A fresh nonce is drawn per encryption and never reused with a key.

Threat model: the store is tamper-EVIDENT against in-place header/ciphertext edits and against a
blob relocated from another store (the ``app`` is AAD-bound and re-checked). It is NOT protected
against ROLLBACK -- an actor with write access can replace the file with an earlier valid snapshot
encrypted under the same passphrase (e.g. reverting a rotated credential); detecting that needs
external monotonic state and is out of scope here. Key and passphrase bytes cannot be zeroized in
CPython (immutable ``str``, non-wiped ``bytes``); their lifetime is minimized, not erased.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from enum import Enum, auto
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InternalError, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from credbox._store_codec import StoreFault, layout_mismatch_hint, parse_store, serialize_store
from credbox.atomic import write_bytes_atomic
from credbox.backends._store import ENCRYPTED_FILE, exclusive_store_lock, normalize_secret_value
from credbox.errors import CredBoxError, CredentialsError, DecryptionError
from credbox.paths import config_dir
from credbox.permissions import PRIVATE_FILE_MODE, warn_if_group_or_world_readable
from credbox.secret import Secret

__all__ = ["EncryptedFileBackend"]

_KEY_LEN = 32
_NONCE_LEN = 12
_SALT_LEN = 16
# Write-time Argon2id cost (deliberately expensive -- ~100ms-scale per store open, a feature).
_WRITE_TIME_COST = 3
_WRITE_MEMORY_COST_KIB = 64 * 1024   # 64 MiB
_WRITE_LANES = 4
# Read-time clamps: a tampered header cannot force a huge Argon2id allocation before the AAD/tag
# check can reject it. A legitimate header's params sit inside these bounds, so clamping is a
# no-op for it; only a tampered header is reshaped (and then fails the tag check anyway).
_MAX_TIME_COST = 16
_MAX_MEMORY_COST_KIB = 4 * _WRITE_MEMORY_COST_KIB   # 256 MiB -- bounds a tampered-header alloc close
_MAX_LANES = 16                                     #   to the legitimate write cost, still a no-op for it


class EncryptedFileBackend:
    """Secrets in a single AES-GCM-encrypted blob under ``config_dir(app)``, keyed by an Argon2id
    hash of ``passphrase``. Terminal -- no fallback; a decrypt failure fails closed."""

    def __init__(self, *, passphrase: Secret) -> None:
        self._passphrase = passphrase

    def __repr__(self) -> str:
        return "EncryptedFileBackend()"   # never render the passphrase

    def path(self, app: str) -> Path:
        """The encrypted store file for ``app``: ``credentials.enc`` in ``config_dir(app)``."""
        return config_dir(app) / ENCRYPTED_FILE

    def describe_location(self, app: str, *, namespace: str | None = None) -> str:
        """Where ``app``'s secrets are stored: the encrypted file path, and the namespace section
        within it when scoped. Secret-free -- a path and a section name only."""
        section = "" if namespace is None else f", section {namespace!r}"
        return f"{self.path(app)}{section}"

    def get(self, app: str, name: str, *, namespace: str | None = None) -> Secret | None:
        """Return the value stored under ``name`` (within ``namespace`` when given) as a ``Secret``,
        or ``None`` when absent.

        Raises:
            DecryptionError: the store exists but could not be decrypted (wrong passphrase or
                tampering) -- content-free, ``__cause__`` and ``__context__`` both ``None``.
            CredentialsError: the store is unreadable, or decrypts to a malformed map.
        """
        if namespace is None:
            by_name = self._load_flat(app)
        else:
            by_name = self._load_nested(app).get(namespace, {})
        cleaned = normalize_secret_value(by_name.get(name))
        return Secret(cleaned) if cleaned is not None else None

    def set(self, app: str, name: str, *, value: str | Secret,
            namespace: str | None = None) -> None:
        """Store ``value`` under ``name`` (within ``namespace`` when given), re-encrypting the whole
        store with a fresh nonce under the same cross-process lock as the file backend. Other
        namespaces are preserved.

        Raises:
            DecryptionError: the existing store could not be decrypted.
            CredentialsError: the store is unreadable, or the write failed.
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
        absent. Re-encrypts under the same lock as ``set``, preserving other namespaces.

        Raises:
            DecryptionError: the existing store could not be decrypted.
            CredentialsError: the store is unreadable, or the write failed.
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
            DecryptionError / CredentialsError: as for ``get``.
        """
        if namespace is None:
            return sorted(self._load_flat(app))
        return sorted(self._load_nested(app).get(namespace, {}))

    def _decrypt(self, app: str) -> bytes | None:
        """Decrypt the store to its plaintext JSON bytes, or ``None`` when the store file is absent.
        The returned bytes are the ONLY reference to the decrypted plaintext -- the caller (``_load_*``)
        must ``parse_store`` and ``del`` them before any raise, so a malformed-store error's frame
        cannot retain them. Every decrypt/KDF failure is raised HERE, from a frame where the
        passphrase and blob are already gone.

        Raises:
            DecryptionError: wrong passphrase or tampering -- content-free.
            CredentialsError: unreadable file, an unsupported/too-new build, or a KDF-unavailable build.
        """
        _ensure_kdf_available()   # before any passphrase.reveal(), so an unsupported build is content-free
        path = self.path(app)
        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as err:
            raise CredentialsError(f"could not read {path}: {err}") from err
        # The file is ciphertext, but a group/world-readable .enc still invites an offline
        # passphrase attack, so nudge the owner to tighten it -- as the file backend does for its
        # plaintext store. Names the path only (not a secret), so it is safe before any reveal.
        warn_if_group_or_world_readable(path, app=app)
        outcome = _try_decrypt(blob, self._passphrase.reveal(), app)
        del blob
        # Every raise below fires from THIS frame -- where no passphrase/plaintext is bound (the
        # passphrase was a temporary argument, blob is already deleted) and no exception is in
        # flight (_try_decrypt RETURNED its outcome) -- so each error's __cause__ and __context__
        # are None and no secret-bearing crypto frame is on the traceback.
        if outcome is _CryptoOutcome.KDF_UNAVAILABLE:
            # The build could not derive at the header's (clamped) params, though the tiny
            # availability probe passed (e.g. no thread support for lanes>1). Content-free, and
            # distinct from wrong-passphrase so the user is told to upgrade, not to doubt the pass.
            raise CredentialsError(
                f"could not read {path}: Argon2id key derivation failed in this cryptography/OpenSSL build"
            )
        if outcome is _CryptoOutcome.NEWER_VERSION:
            # A well-formed argon2id header carrying an unrecognized newer version -- written by a
            # newer credbox. Report that distinctly (content-free) instead of misdiagnosing it as a
            # wrong passphrase or tampering, so the user is told to upgrade rather than doubting
            # their passphrase. (The header is pre-tag-check, so someone with write access could
            # choose this message, but both outcomes are content-free -- no secret either way.)
            raise CredentialsError(
                f"the store {path} was written by a newer credbox; upgrade credbox to read it"
            )
        if not isinstance(outcome, bytes):
            # FAILED today -- and the deliberate fail-closed sink for any future non-bytes outcome:
            # an unrecognized member is rejected here as a decrypt failure, never reaching
            # parse_store as plaintext. (Wrong passphrase, tampering, or a relocated blob whose
            # AAD-bound app did not match.) Keeping this positive `isinstance(bytes)` gate -- rather
            # than an `is FAILED` check -- is what makes the fall-through safe.
            raise DecryptionError(
                f"could not decrypt {path}: wrong passphrase or tampering"
            )
        return outcome

    def _load_flat(self, app: str) -> dict[str, str]:
        """Decrypt and parse the store as a flat ``name -> secret`` map, or ``{}`` when absent."""
        plaintext = self._decrypt(app)
        if plaintext is None:
            return {}
        # `plaintext` is the ONLY reference to the decrypted bytes; drop it before any raise, so a
        # malformed-store CredentialsError's traceback frame cannot retain the decrypted store.
        result = parse_store(plaintext)
        del plaintext
        if isinstance(result, StoreFault):
            raise CredentialsError(
                f"the decrypted store {self.path(app)} is malformed"
                f"{layout_mismatch_hint(nested=False, kind=result.kind)}")
        return result

    def _load_nested(self, app: str) -> dict[str, dict[str, str]]:
        """Decrypt and parse the store as a two-level ``namespace -> {name -> secret}`` map, or
        ``{}`` when absent. Same drop-before-raise contract as ``_load_flat``."""
        plaintext = self._decrypt(app)
        if plaintext is None:
            return {}
        result = parse_store(plaintext, nested=True)
        del plaintext
        if isinstance(result, StoreFault):
            raise CredentialsError(
                f"the decrypted store {self.path(app)} is malformed"
                f"{layout_mismatch_hint(nested=True, kind=result.kind)}")
        return result

    def _save(self, app: str, store: dict[str, str] | dict[str, dict[str, str]]) -> None:
        _ensure_kdf_available()   # before any passphrase.reveal(), so an unsupported build is content-free
        path = self.path(app)
        encoded = serialize_store(store)
        if isinstance(encoded, StoreFault):
            raise CredentialsError(f"{path} could not be serialized: a value is not encodable")
        blob = _encrypt(encoded, self._passphrase.reveal(), app)
        del encoded   # drop the serialized-plaintext alias, which lives only in this frame
        if not isinstance(blob, bytes):   # KDF_UNAVAILABLE
            # The build could not derive at the write params. `_encrypt`/`_derive_key` RETURNED the
            # signal (never raised), so the passphrase and the serialized-plaintext frame are off the
            # traceback and `__cause__`/`__context__` are None -- as on the read path. This is NOT,
            # however, frame-clean: unlike a read, a write inherently holds the plaintext map --
            # `store` stays bound here and in the `set`/`unset` callers -- the accepted
            # object-level residual of a write (see FileBackend._save). Content-free message.
            raise CredentialsError(
                f"could not write {path}: Argon2id key derivation failed in this cryptography/OpenSSL build"
            )
        try:
            write_bytes_atomic(path, blob, mode=PRIVATE_FILE_MODE)
        except CredBoxError as err:
            raise CredentialsError(str(err)) from err


# --- crypto primitives ---------------------------------------------------------

class _CryptoOutcome(Enum):
    """A non-plaintext result of a decrypt-or-encrypt attempt (both re-derive the key), RETURNED
    (never raised) so the frames that hold the passphrase (``_derive_key``) or the serialized
    plaintext (``_encrypt``) are never attached to an escaping exception's traceback. The store
    loaders (``_load_flat``/``_load_nested``) and ``_save`` map each member to a content-free error
    raised from their own frame, where no exception is in flight (so ``__cause__``/``__context__``
    are ``None``)."""

    FAILED = auto()           # wrong passphrase, tampering, or a malformed/relocated blob
    NEWER_VERSION = auto()    # a well-formed header whose version this build does not understand
    KDF_UNAVAILABLE = auto()  # Argon2id rejected the real params in this cryptography/OpenSSL build

_kdf_available = False
_kdf_probe_lock = threading.Lock()


def _ensure_kdf_available() -> None:
    """Confirm this cryptography/OpenSSL build actually provides Argon2id, raising a content-free
    ``CredentialsError`` if not. Probed with a throwaway secret-free input and cached, and called
    BEFORE any passphrase is revealed -- so an unsupported build fails closed here instead of
    letting an ``UnsupportedAlgorithm``/``InternalError`` escape a later ``derive()`` whose frame
    holds the passphrase. Not folded into ``DecryptionError`` (that would misreport a missing
    build capability as a wrong passphrase or tampering)."""
    global _kdf_available
    if _kdf_available:
        return
    with _kdf_probe_lock:
        if _kdf_available:
            return
        try:
            Argon2id(
                salt=b"\x00" * _SALT_LEN, length=_KEY_LEN,
                iterations=1, lanes=1, memory_cost=8,
            ).derive(b"")   # b"": no secret in this frame, so a raise here leaks nothing
        except (UnsupportedAlgorithm, InternalError):
            raise CredentialsError(
                "this cryptography/OpenSSL build does not support Argon2id; "
                "upgrade cryptography (>=44) or its bundled OpenSSL"
            ) from None
        _kdf_available = True


def _derive_key(
    passphrase: str, salt: bytes, *, time_cost: int, memory_cost: int, lanes: int
) -> bytes | Literal[_CryptoOutcome.KDF_UNAVAILABLE]:
    kdf = Argon2id(
        salt=salt,
        length=_KEY_LEN,
        iterations=time_cost,
        lanes=lanes,
        memory_cost=memory_cost,
    )
    # surrogatepass: a passphrase holding a lone surrogate (e.g. sourced from an env var via
    # surrogateescape) encodes to deterministic bytes instead of raising UnicodeEncodeError, whose
    # .object/.args and this frame's locals (passphrase, plaintext) would otherwise leak the secret.
    try:
        return kdf.derive(passphrase.encode("utf-8", "surrogatepass"))
    except (UnsupportedAlgorithm, InternalError):
        # The availability probe validates Argon2id at tiny params; the REAL derive runs at 64 MiB
        # (write) or up to the clamped 256 MiB / 16 lanes (read), which an OpenSSL build can still
        # reject param-specifically (e.g. no thread support for lanes>1) even though the probe
        # passed. RETURN the failure -- never raise -- so this frame, which holds `passphrase`, is
        # not attached to any escaping exception's traceback; the store loaders/_save turn the signal
        # into a content-free CredentialsError from their own clean frame. (Distinct from wrong-passphrase:
        # this is a build-capability failure, so the caller says "upgrade", not "wrong passphrase".)
        return _CryptoOutcome.KDF_UNAVAILABLE


def _encrypt(
    plaintext: bytes, passphrase: str, app: str
) -> bytes | Literal[_CryptoOutcome.KDF_UNAVAILABLE]:
    """Encrypt ``plaintext`` into the single-blob layout with a fresh salt and nonce. ``app`` is
    written into the header (and thus bound as AAD) so a reader can confirm the blob belongs to
    the store it was found in -- see ``_try_decrypt``. On a build that cannot derive at the write
    params it RETURNS ``KDF_UNAVAILABLE`` rather than raising, so the passphrase and this frame's
    ``plaintext`` are kept off any escaping traceback for that case; ``_save`` turns the signal into
    a content-free error. This is NOT a blanket "never raises": ``AESGCM.encrypt``/``json.dumps`` can
    still fault with ``plaintext`` in frame -- the accepted object-level residual of a write."""
    salt = os.urandom(_SALT_LEN)
    key = _derive_key(
        passphrase, salt,
        time_cost=_WRITE_TIME_COST, memory_cost=_WRITE_MEMORY_COST_KIB, lanes=_WRITE_LANES,
    )
    if not isinstance(key, bytes):
        return key   # KDF_UNAVAILABLE -- propagate the signal; do not build a header round a missing key
    del passphrase   # unused past key derivation: keep it off the json.dumps / AESGCM.encrypt frame,
                     # so a fault there leaves only plaintext in frame (the documented residual)
    header = {
        "v": 1,
        "kdf": "argon2id",
        "t": _WRITE_TIME_COST,
        "m": _WRITE_MEMORY_COST_KIB,
        "p": _WRITE_LANES,
        "app": app,
        "salt": base64.b64encode(salt).decode("ascii"),
    }
    header_json = json.dumps(header, sort_keys=True).encode("utf-8")
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header_json)   # AAD = the whole header
    return len(header_json).to_bytes(4, "big") + header_json + nonce + ciphertext


def _try_decrypt(blob: bytes, passphrase: str, app: str) -> bytes | _CryptoOutcome:
    """Parse the blob, re-derive the key from the header's own (clamped) params, and AES-GCM
    decrypt with the header bound as AAD. Return the plaintext bytes, or a ``_CryptoOutcome``:
    ``FAILED`` on any decrypt failure (a malformed blob, wrong passphrase, tampering, or a blob
    bound to a different app), ``NEWER_VERSION`` for a well-formed header whose version is newer
    than this build understands, or ``KDF_UNAVAILABLE`` when the build cannot derive at the (clamped)
    header params. Every fault -- crypto, decode, OR a build-capability failure from ``_derive_key``
    -- is turned into a RETURNED outcome here and never raised, so the passphrase- and blob-bearing
    frames are never attached to the caller's error and its ``__context__`` is ``None``."""
    try:
        header_len = int.from_bytes(blob[:4], "big")
        header_json = blob[4:4 + header_len]
        rest = blob[4 + header_len:]
        nonce = rest[:_NONCE_LEN]
        ciphertext = rest[_NONCE_LEN:]
        if len(header_json) != header_len or len(nonce) != _NONCE_LEN:
            return _CryptoOutcome.FAILED
        header = json.loads(header_json)
        if not isinstance(header, dict) or header.get("kdf") != "argon2id":
            return _CryptoOutcome.FAILED
        version = header.get("v")
        if version != 1:
            # A well-formed argon2id header with a recognizably-newer integer version was written
            # by a newer credbox; signal that distinctly. Anything else (v absent, non-int, <1) is
            # malformed and falls through to a normal decrypt failure.
            return _CryptoOutcome.NEWER_VERSION if isinstance(version, int) and version > 1 else _CryptoOutcome.FAILED
        salt = base64.b64decode(header["salt"])
        if len(salt) < _SALT_LEN:
            return _CryptoOutcome.FAILED   # a too-short/empty salt is malformed or tampered

        time_cost = _clamp(int(header["t"]), 1, _MAX_TIME_COST)
        memory_cost = _clamp(int(header["m"]), 8 * _MAX_LANES, _MAX_MEMORY_COST_KIB)
        lanes = _clamp(int(header["p"]), 1, _MAX_LANES)
        key = _derive_key(passphrase, salt, time_cost=time_cost, memory_cost=memory_cost, lanes=lanes)
        if not isinstance(key, bytes):
            return key   # KDF_UNAVAILABLE -- the build rejected these (clamped) params; propagate the signal
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header_json)
        # App binding: a v1 blob carries its app in the (AAD-authenticated) header. A blob moved
        # from another same-passphrase store decrypts (its own header is the AAD) but its app will
        # not match -- reject it as tampering. A blob without the field (a hypothetical older one)
        # skips the check, so the binding is additive and back-compatible.
        stored_app = header.get("app")
        if stored_app is not None and stored_app != app:
            return _CryptoOutcome.FAILED
        return plaintext
    except (InvalidTag, ValueError, KeyError, TypeError, RecursionError, OverflowError,
            json.JSONDecodeError, UnicodeDecodeError):
        # Every way a tampered/garbage header can fault maps to FAILED here, so nothing escapes with
        # `passphrase`/`blob` retained in this frame's traceback. Two non-obvious members:
        # RecursionError -- a header whose JSON nests thousands of levels; OverflowError -- a header
        # param like {"t": 1e999} parses to float('inf'), and int(inf) raises OverflowError (not a
        # ValueError). Only MemoryError/KeyboardInterrupt propagate: an OOM is not a malformed
        # header, so folding it to "wrong passphrase or tampering" would misclassify it, exactly as
        # _store_codec keeps its own catches narrow.
        return _CryptoOutcome.FAILED


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(value, high))
