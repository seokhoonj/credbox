"""The leak-safe store codec: ``parse_store`` / ``serialize_store``.

A *returning-frame* pair. Each decodes or encodes the store map INSIDE a function that
RETURNS, so a content-bearing exception (``UnicodeDecodeError.object``, ``JSONDecodeError.doc``)
is caught here and turned into a content-free ``StoreFault`` -- it never escapes to a raise
site that could keep the secret bytes alive on ``__context__`` or in traceback frame-locals.

Catches are NARROW on purpose: only the specific decode/parse errors map to a fault. A
``MemoryError``, ``KeyboardInterrupt``, ``SystemExit``, or a genuine bug propagates -- the
codec never swallows it behind a fault. The caller (``FileBackend``) turns a ``StoreFault``
into a ``CredentialsError`` built from the enum/ints only, in a frame where no secret local
is bound.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Literal, overload

__all__ = ["StoreFaultKind", "StoreFault", "parse_store", "serialize_store"]


class StoreFaultKind(Enum):
    """A content-free reason the store could not be parsed or serialized -- the enum member
    only, never ``str(err)`` or any file content."""

    NOT_UTF8 = "not_utf8"
    NOT_JSON = "not_json"
    NOT_OBJECT = "not_object"               # top-level JSON is not an object
    NOT_STRING_VALUE = "not_string_value"   # a value in the object is not a str (tampered store)
    NESTING = "nesting"                     # RecursionError while parsing
    NOT_ENCODABLE = "not_encodable"         # serialize side: lone-surrogate UnicodeEncodeError


@dataclass(frozen=True, slots=True)
class StoreFault:
    """A disjoint-sum failure of the codec: the kind, plus an optional JSON position (ints
    only, never file content)."""

    kind: StoreFaultKind
    lineno: int | None = None
    colno: int | None = None


@overload
def parse_store(
    store_bytes: bytes, *, nested: Literal[False] = ...
) -> dict[str, str] | StoreFault: ...
@overload
def parse_store(
    store_bytes: bytes, *, nested: Literal[True]
) -> dict[str, dict[str, str]] | StoreFault: ...
def parse_store(
    store_bytes: bytes, *, nested: bool = False
) -> dict[str, str] | dict[str, dict[str, str]] | StoreFault:
    """Decode UTF-8 and parse JSON inside this returning frame, returning the store map or a
    content-free ``StoreFault``. ``nested=False`` (default) parses the flat ``{name: secret}`` map;
    ``nested=True`` parses the two-level ``{namespace: {name: secret}}`` map (one store file holding
    several components' secrets, each in its own namespace object).

    Narrow catches only: ``UnicodeDecodeError`` -> ``NOT_UTF8``; ``json.JSONDecodeError`` ->
    ``NOT_JSON`` (keeping the int ``lineno``/``colno``); a bare ``ValueError`` -> ``NOT_JSON``
    (``json.loads`` raises a plain ``ValueError`` -- not ``JSONDecodeError`` -- for a number
    literal past ``sys.get_int_max_str_digits()``; catching it here keeps a tampered store's raw
    bytes off the escaping traceback frame); ``RecursionError`` -> ``NESTING``. A parsed top level
    that is not a ``dict`` -> ``NOT_OBJECT``. In flat mode, any value that is not a ``str`` ->
    ``NOT_STRING_VALUE``, so a tampered ``{"k": {...}}`` never flows into ``Secret(str)``; in nested
    mode, a namespace whose value is not an object -> ``NOT_OBJECT`` and an inner non-``str`` value
    -> ``NOT_STRING_VALUE`` (so a store written in one shape and read in the other faults rather
    than mis-parsing). An empty ``{}`` store is valid in BOTH modes (the check loop simply does not
    run), so an emptied store carries no shape and either mode may next write it. Anything else --
    ``MemoryError``, ``KeyboardInterrupt`` -- propagates.
    """
    try:
        text = store_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return StoreFault(StoreFaultKind.NOT_UTF8)
    try:
        try:
            parsed = json.loads(text)
        except RecursionError:
            return StoreFault(StoreFaultKind.NESTING)
        except json.JSONDecodeError as err:
            return StoreFault(StoreFaultKind.NOT_JSON, lineno=err.lineno, colno=err.colno)
        except ValueError:
            # json.loads raises a bare ValueError (not JSONDecodeError) for a number literal
            # exceeding the interpreter's integer-string-conversion limit; fold it here too.
            return StoreFault(StoreFaultKind.NOT_JSON)
    finally:
        del text
    if not isinstance(parsed, dict):
        return StoreFault(StoreFaultKind.NOT_OBJECT)
    if nested:
        # Each top-level value is a namespace object of {name: secret}; a non-object namespace
        # value means the file was written flat (or tampered) and is read here in nested mode.
        for namespace, submap in parsed.items():
            if not isinstance(namespace, str) or not isinstance(submap, dict):
                return StoreFault(StoreFaultKind.NOT_OBJECT)
            for name, value in submap.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    return StoreFault(StoreFaultKind.NOT_STRING_VALUE)
        return parsed
    for name, value in parsed.items():
        if not isinstance(name, str) or not isinstance(value, str):
            return StoreFault(StoreFaultKind.NOT_STRING_VALUE)
    return parsed


def layout_mismatch_hint(*, nested: bool, kind: StoreFaultKind) -> str:
    """A short, content-free clause appended to a malformed-store error when the fault looks like a
    flat-vs-namespaced LAYOUT mismatch (the most common cause) rather than genuine corruption. A
    store is wholly flat or wholly namespaced; reading it in the other mode faults here. Empty for
    any other fault kind (real corruption keeps the bare message)."""
    if nested and kind is StoreFaultKind.NOT_OBJECT:
        # nested read, but a top-level value is not an object -> the store looks flat.
        return " (or a flat store read with a namespace -- read it without one, or migrate it)"
    if not nested and kind is StoreFaultKind.NOT_STRING_VALUE:
        # flat read, but a value is an object -> the store looks namespaced. Caller-neutral phrasing:
        # correct for both the CLI (-n/--namespace) and the API (namespace=...).
        return " (or a namespaced store read without a namespace -- read it with the namespace it was written under)"
    return ""


def serialize_store(store: dict[str, str] | dict[str, dict[str, str]]) -> bytes | StoreFault:
    """Serialize the store map to UTF-8 JSON bytes inside this returning frame -- the flat
    ``{name: secret}`` map or the nested ``{namespace: {name: secret}}`` map; ``json.dumps`` encodes
    either shape.

    Narrow catch only: a lone-surrogate ``UnicodeEncodeError`` (the whole store) ->
    ``NOT_ENCODABLE``, never raised out. ``ensure_ascii=False`` is required so a lone
    surrogate surfaces as an encode error here rather than round-tripping as ``\\udXXX``.
    Inputs are already ``str`` values, so ``json.dumps`` cannot hit a non-str ``TypeError``.
    """
    try:
        text = json.dumps(store, ensure_ascii=False)
        return text.encode("utf-8")
    except UnicodeEncodeError:
        return StoreFault(StoreFaultKind.NOT_ENCODABLE)
