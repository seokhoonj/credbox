"""Tests for the leak-safe store codec.

These pin the leak-safety invariants: narrow catches (a ``KeyboardInterrupt``/``MemoryError``
must propagate, not be swallowed into a fault), the ``NOT_STRING_VALUE`` guard that keeps a
tampered non-string value out of ``Secret(str)``, and the leak guarantee that no fault ever
carries secret content.
"""

from __future__ import annotations

import json

import pytest

from credbox._store_codec import StoreFault, StoreFaultKind, parse_store, serialize_store

SECRET = "sk_live_TOPSECRET_value"


def test_roundtrip_preserves_the_store_map() -> None:
    store = {"api_key": SECRET, "db_password": "hunter2hunter2"}
    encoded = serialize_store(store)
    assert isinstance(encoded, bytes)
    assert parse_store(encoded) == store


def test_non_utf8_bytes_return_not_utf8_fault() -> None:
    result = parse_store(b"\xff\xfe not utf-8")
    assert result == StoreFault(StoreFaultKind.NOT_UTF8)


def test_not_json_returns_not_json_fault_with_position() -> None:
    result = parse_store(b"{not json")
    assert isinstance(result, StoreFault)
    assert result.kind is StoreFaultKind.NOT_JSON
    assert result.lineno is not None and result.colno is not None


def test_oversized_integer_literal_returns_not_json_fault_without_escaping() -> None:
    # json.loads raises a bare ValueError (not JSONDecodeError) for a number literal past
    # sys.get_int_max_str_digits() (4300). It must fold to a NOT_JSON fault, not escape the
    # returning frame -- otherwise a tampered plaintext store crashes the reader and leaves the
    # raw store bytes on the traceback. Reproduces the real bug, no mock.
    blob = ('{"SECRETKEY":' + "7" * 5000 + "}").encode("utf-8")
    result = parse_store(blob)   # must NOT raise
    assert result == StoreFault(StoreFaultKind.NOT_JSON)
    # Pin the top-level bare literal too (same `except ValueError` clause): a store that is just
    # the oversized number, no object wrapper, must fold identically -- not raise, not echo digits.
    top_level = parse_store(("7" * 5000).encode("utf-8"))
    assert top_level == StoreFault(StoreFaultKind.NOT_JSON)
    assert "7" * 5000 not in repr(top_level)


def test_top_level_non_object_returns_not_object_fault() -> None:
    assert parse_store(b'["a", "b"]') == StoreFault(StoreFaultKind.NOT_OBJECT)
    assert parse_store(b'"just a string"') == StoreFault(StoreFaultKind.NOT_OBJECT)


def test_non_string_value_returns_not_string_value_fault() -> None:
    # A tampered store whose value is a nested object must NOT flow into Secret(str).
    result = parse_store(b'{"k": {"nested": 1}}')
    assert result == StoreFault(StoreFaultKind.NOT_STRING_VALUE)
    result = parse_store(b'{"k": 12345}')
    assert result == StoreFault(StoreFaultKind.NOT_STRING_VALUE)


def test_deep_nesting_returns_nesting_fault_mock_forced(monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock json.loads to raise RecursionError rather than building a crashing input.
    def _raise(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("too deep")

    monkeypatch.setattr(json, "loads", _raise)
    assert parse_store(b'{"k": "v"}') == StoreFault(StoreFaultKind.NESTING)


def test_serialize_lone_surrogate_returns_not_encodable() -> None:
    result = serialize_store({"k": "\ud800"})  # a lone surrogate cannot encode to utf-8
    assert result == StoreFault(StoreFaultKind.NOT_ENCODABLE)


def test_parse_does_not_swallow_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*_args: object, **_kwargs: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(json, "loads", _raise)
    with pytest.raises(KeyboardInterrupt):
        parse_store(b'{"k": "v"}')


def test_parse_does_not_swallow_memory_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*_args: object, **_kwargs: object) -> object:
        raise MemoryError

    monkeypatch.setattr(json, "loads", _raise)
    with pytest.raises(MemoryError):
        parse_store(b'{"k": "v"}')


def test_a_fault_carries_no_secret_content() -> None:
    # A malformed store that embeds a secret substring must produce a fault whose repr and
    # fields contain none of it -- the leak guarantee at the value level.
    blob = b'{"api_key": "' + SECRET.encode() + b'" NOT JSON'
    result = parse_store(blob)
    assert isinstance(result, StoreFault)
    assert SECRET not in repr(result)
    assert all(SECRET not in str(field) for field in (result.kind, result.lineno, result.colno))
