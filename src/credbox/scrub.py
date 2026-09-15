"""Removing secret values from text before it is logged or surfaced.

A provider often echoes the API key back inside an error message or a request URL, so an
unscrubbed exception can leak the very secret it failed to use into a log or a terminal.
``scrub_secrets`` replaces each known secret value -- and its URL-encoded forms -- in a string
with ``***``; ``scrub_exception`` walks an exception and its ``__cause__`` / ``__context__``
chain and scrubs each node's ``args``, its transport URLs (``url``, ``request.url``,
``response.url``), and its ``__notes__`` in place. Both are best-effort: they run on the error
path, where a second failure would mask the first, so any *ordinary* exception while inspecting a
node is swallowed. The one carve-out is ``MemoryError`` (and ``KeyboardInterrupt`` / ``SystemExit``,
which are not ``Exception`` and propagate anyway): it is re-raised rather than swallowed. This is
the lesser of two leaks, not a leak-free path -- swallowing returns the still-unscrubbed,
secret-bearing text as the function's result (a certain leak into the log sink), whereas the
propagating ``MemoryError`` exposes this frame's ``secret_values`` only to a handler that dumps
frame-locals (its own ``str`` carries no secret). The caller supplies the secret *values* to
redact; this module never reads a store.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeAlias
from urllib.parse import quote, quote_plus

from credbox.secret import Secret

__all__ = [
    "scrub_secrets",
    "scrub_exception",
]

REDACTION = "***"

# A single secret OR an iterable of them; a bare str/Secret is one secret, never iterated.
SecretsArg: TypeAlias = "str | Secret | Iterable[str | Secret]"


def _reject_bytes_secrets(secrets: SecretsArg) -> None:
    """Refuse a binary ``secrets`` arg (``bytes``/``bytearray``/``memoryview``), eagerly and loudly.
    Each is ``Iterable[int]``, so it slips through the best-effort bodies below, matches no ``str``
    item, and redacts NOTHING -- a silent no-op that returns the secret-bearing text unchanged, the
    worst failure for a leak guard. (``array('B')`` is the same but exotic; a fully general
    ``Iterable[int]`` guard is impossible, so we name the concrete buffer types.) These are outside
    ``SecretsArg`` (mypy already rejects them for typed callers); this is the runtime backstop for
    dynamically-typed ones, raised before the never-raises body so the misuse surfaces.

    ``from None`` because this runs inside callers' ``except`` blocks (``scrub_exception``): it sets
    ``__suppress_context__`` so the in-flight, possibly secret-bearing exception is not RENDERED in
    this TypeError's traceback. (It does not detach ``__context__`` -- Python keeps the object link;
    the point is only to keep it out of the printed output, and the in-flight error is the caller's
    own object anyway.)"""
    if isinstance(secrets, (bytes, bytearray, memoryview)):
        raise TypeError(
            "scrub secrets must be str/Secret (or an iterable of them), not bytes/bytearray/memoryview"
        ) from None


def scrub_secrets(text: str, secrets: SecretsArg) -> str:
    """Return ``text`` with every non-empty value in ``secrets`` -- and each value's
    URL-encoded (``quote`` / ``quote_plus``) forms -- replaced by ``***``.

    ``secrets`` may be raw ``str`` values or ``Secret``s (the natural thing to pass -- a
    ``Secret`` is revealed here, at the point of use, purely to redact it; passing one is NOT a
    silent no-op). Longer targets are replaced first, so a secret that is a prefix of another (or
    of its own encoded form) does not leave a tail exposed. Best-effort and never raises on the error
    path: a non-iterable ``secrets`` leaves ``text`` unchanged. The one eager rejection is a
    ``bytes`` ``secrets`` (a caller type error -- see ``_reject_bytes_secrets``)."""
    _reject_bytes_secrets(secrets)
    try:
        secret_values = _redactable_values(secrets)
    except MemoryError:
        raise   # never swallow OOM into a return of the still-unscrubbed text (see module docstring)
    except Exception:
        # a non-iterable or mid-iteration-raising `secrets` must not raise on the error path
        return text
    return _replace_targets(text, _redaction_targets(secret_values))


def scrub_exception(err: BaseException, secrets: SecretsArg) -> BaseException:
    """Scrub every secret in ``secrets`` from ``err`` and its ``__cause__`` / ``__context__``
    chain, in place, and return ``err``. Best-effort: any failure while inspecting a node is
    swallowed, so this never raises on the error path.

    Per node it rewrites ``args`` (recursing into ``str`` values nested in ``list``/``tuple``/
    ``dict``/``set`` args, since ``str(err)`` renders those verbatim), the transport URLs
    (``url``, ``request.url``, ``response.url`` -- each ``getattr``-guarded, since httpx spells
    them as properties that raise when unset), and ``__notes__`` (PEP 678). It does **not**
    guarantee ``str(err)`` is clean for an exception with a custom ``__str__`` that renders
    something other than these, so also pass the rendered log line through ``scrub_secrets``
    before emitting it. The redaction targets are computed once here and threaded through the
    walk rather than rebuilt per field. Like ``scrub_secrets`` it never raises on the error path,
    save the one eager rejection of a ``bytes`` ``secrets`` arg (see ``_reject_bytes_secrets``)."""
    _reject_bytes_secrets(secrets)
    try:
        secret_values = _redactable_values(secrets)
    except MemoryError:
        raise   # never swallow OOM into a return of the still-unscrubbed error (see module docstring)
    except Exception:
        return err   # a non-iterable or raising `secrets` must not mask the original error
    if not secret_values:
        return err
    targets = _redaction_targets(secret_values)
    seen: set[int] = set()
    stack: list[BaseException | None] = [err]
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))
        _scrub_node(node, targets)
        for attr in ("__cause__", "__context__"):
            try:
                stack.append(getattr(node, attr, None))
            except MemoryError:
                raise   # never swallow OOM into skipping a chained node that still holds a secret
            except Exception:
                pass   # a custom exception's attribute access may raise; never on the error path
        if isinstance(node, BaseExceptionGroup):
            # PEP 654: a group's members live in `.exceptions`, not on the cause/context chain.
            # httpx/anyio raise these routinely, and each member's args/URLs are exactly what this
            # module exists to scrub -- so walk them too (the `seen` set guards against cycles).
            stack.extend(node.exceptions)
    return err


def _redactable_values(secrets: SecretsArg) -> list[str]:
    """The non-empty raw strings to redact, drawn from a single ``str``/``Secret`` OR an iterable
    of them. A bare ``str``/``Secret`` is treated as one secret, NOT iterated -- otherwise
    ``scrub_secrets(log, "apikey")`` (the natural single-secret call) would walk the string into
    characters and redact every letter, shredding the log while missing the secret. A ``Secret`` is
    revealed here, the point of use for redaction. Any other item type is skipped."""
    if isinstance(secrets, (str, Secret)):
        secrets = [secrets]
    values: list[str] = []
    for item in secrets:
        raw = item.reveal() if isinstance(item, Secret) else item
        if isinstance(raw, str) and raw.strip():   # skip empty AND whitespace-only (would over-scrub)
            values.append(raw)
    return values


def _percent_hex_lowercased(encoded: str) -> str:
    """A copy of a percent-encoded string with each ``%XX`` hex pair lowercased. ``quote``/
    ``quote_plus`` emit UPPERCASE hex (``%2F``), but RFC 3986 allows either case and a server may
    echo the value with lowercase hex (``%2f``); redacting both forms closes that residual leak.
    Only the two hex digits after each ``%`` change -- never the secret's own characters."""
    out: list[str] = []
    i, n = 0, len(encoded)
    while i < n:
        if encoded[i] == "%" and i + 2 < n:
            out.append("%" + encoded[i + 1 : i + 3].lower())
            i += 3
        else:
            out.append(encoded[i])
            i += 1
    return "".join(out)


def _redaction_targets(secret_values: list[str]) -> list[str]:
    """Every string that must be redacted -- each secret plus its ``quote``/``quote_plus`` forms
    (and their lowercase-hex variants) -- deduplicated and ordered longest-first so no target's
    replacement uncovers another's tail."""
    targets: set[str] = set()
    for value in secret_values:
        targets.add(value)
        try:
            for encoded in (quote(value), quote_plus(value)):
                targets.add(encoded)
                targets.add(_percent_hex_lowercased(encoded))
        except Exception:
            pass   # an exotic value that will not URL-encode: the raw form is still redacted
    return sorted(targets, key=len, reverse=True)


def _replace_targets(text: str, targets: list[str]) -> str:
    """Replace each prepared target in ``text`` with ``***`` (targets already deduped/ordered)."""
    result = text
    for target in targets:
        result = result.replace(target, REDACTION)
    return result


def _scrub_value(value: object, targets: list[str]) -> object:
    """Scrub ``str`` values anywhere inside ``value``, recursing through ``list``/``tuple``/
    ``dict``/``set`` containers so a secret nested in a non-string exception arg (e.g.
    ``ValueError([msg])``, whose ``str()`` renders the list verbatim) is redacted too. Any
    other type is returned unchanged."""
    if isinstance(value, str):
        return _replace_targets(value, targets)
    if isinstance(value, tuple):
        return tuple(_scrub_value(v, targets) for v in value)
    if isinstance(value, list):
        return [_scrub_value(v, targets) for v in value]
    if isinstance(value, dict):
        return {_scrub_value(k, targets): _scrub_value(v, targets) for k, v in value.items()}
    if isinstance(value, frozenset):
        return frozenset(_scrub_value(v, targets) for v in value)
    if isinstance(value, set):
        return {_scrub_value(v, targets) for v in value}
    return value


def _scrub_node(node: BaseException, targets: list[str]) -> None:
    """Scrub ``node.args``, its transport URLs, and its ``__notes__``, each guarded
    independently so a property that raises cannot abort the walk."""
    try:
        args = node.args
        if args:
            node.args = tuple(_scrub_value(arg, targets) for arg in args)
    except MemoryError:
        raise   # never swallow OOM into leaving `args` unscrubbed on the node
    except Exception:
        pass   # a custom .args accessor may raise; the never-raise contract wins here
    _scrub_url_attr(node, targets)
    for owner_name in ("request", "response"):
        try:
            owner = getattr(node, owner_name, None)
        except MemoryError:
            raise   # never swallow OOM into skipping an owner whose url still holds a secret
        except Exception:
            owner = None
        if owner is not None:
            _scrub_url_attr(owner, targets)
    try:
        notes = getattr(node, "__notes__", None)
        if isinstance(notes, list):
            node.__notes__ = [
                _replace_targets(note, targets) if isinstance(note, str) else note
                for note in notes
            ]
    except MemoryError:
        raise   # never swallow OOM into leaving `__notes__` unscrubbed on the node
    except Exception:
        pass   # a custom __notes__ may not be assignable; never on the error path


def _scrub_url_attr(obj: object, targets: list[str]) -> None:
    """Scrub a string ``url`` attribute on ``obj`` in place, fully guarded -- reading ``url``
    (an httpx property) can itself raise when unset, and a non-string ``url`` (an httpx URL
    object) is left alone."""
    try:
        url = getattr(obj, "url", None)
    except MemoryError:
        raise   # never swallow OOM into leaving the URL unscrubbed on the node
    except Exception:
        return   # a property that raises when unset
    if isinstance(url, str):
        try:
            obj.url = _replace_targets(url, targets)  # type: ignore[attr-defined]
        except MemoryError:
            raise   # never swallow OOM into leaving the URL unscrubbed on the node
        except Exception:
            pass   # a read-only or custom url property: cannot rewrite it, and must not raise
