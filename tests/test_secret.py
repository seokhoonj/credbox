"""Tests for the ``Secret`` value type and ``mask_secret``.

These pin the leak-safety invariants: the ``edge <= 0`` whole-secret disclosure (the ``-0``
slice footgun) and the ``__eq__`` crash on a non-ASCII or lone-surrogate secret.
"""

from __future__ import annotations

import pytest

from credbox.secret import Secret, mask_secret

SECRET = "sk_live_0123456789abcdef"


def test_reveal_returns_the_raw_value() -> None:
    assert Secret(SECRET).reveal() == SECRET


def test_str_renders_the_mask_not_the_secret() -> None:
    text = str(Secret(SECRET))
    assert SECRET not in text
    assert text == mask_secret(SECRET)


def test_repr_is_masked_and_hides_the_secret() -> None:
    text = repr(Secret(SECRET))
    assert text.startswith("Secret(")
    assert SECRET not in text


def test_format_and_fstring_render_the_mask_not_the_secret() -> None:
    # `f"{secret}"` and `format(secret)` route through object.__format__ (empty spec) -> __str__,
    # so they must inherit the mask; a regression that added a value-revealing __format__ would
    # leak into any log line that interpolates a Secret.
    secret = Secret(SECRET)
    assert SECRET not in f"{secret}"
    assert SECRET not in format(secret)
    assert format(secret) == mask_secret(SECRET)


def test_format_with_a_nonempty_spec_does_not_reveal_the_secret() -> None:
    # A format spec reaches str.__format__ only if __str__ already masked; object.__format__ with a
    # non-empty spec raises TypeError rather than falling back to the raw value -- either way the
    # secret must never appear.
    try:
        rendered = f"{Secret(SECRET):>40}"
    except TypeError:
        return   # object.__format__ rejects a spec it has no value to format -- no leak, acceptable
    assert SECRET not in rendered


def test_secret_in_exception_message_is_masked() -> None:
    # Embedding a Secret in an exception (a common accidental-leak path) renders its mask, because
    # str(secret) is the mask -- str(ValueError(secret)) must not carry the raw value.
    assert SECRET not in str(ValueError(Secret(SECRET)))


def test_mask_reveals_both_edges_for_a_long_value() -> None:
    assert mask_secret("abcdefghijklmnop", edge=4) == "abcd...mnop"


def test_mask_fully_redacts_a_value_shorter_than_four_edges() -> None:
    # 9 chars at edge=4 needs len >= 16 -> fully redacted, not "8 of 9 chars shown".
    assert mask_secret("123456789", edge=4) == "***"


def test_mask_edge_zero_fully_redacts_and_never_reveals_the_whole_secret() -> None:
    # The -0 slice footgun: value[-0:] == value[0:] == the whole secret if the guard is
    # only `len >= 4*edge` (always true at edge=0). The `edge > 0` guard must catch this.
    assert mask_secret(SECRET, edge=0) == "***"


def test_mask_negative_edge_fully_redacts() -> None:
    assert mask_secret(SECRET, edge=-3) == "***"


def test_equality_uses_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    # The value of `==` being correct does not prove it is constant-time -- ordinary `==` would
    # give the same booleans while leaking length/prefix timing. Assert __eq__ actually routes
    # through hmac.compare_digest (the timing-safe primitive), which a regression to `a == b`
    # would silently stop doing.
    import hmac

    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def recording(a: bytes, b: bytes) -> bool:
        calls.append((bytes(a), bytes(b)))
        return real(a, b)

    monkeypatch.setattr("credbox.secret.hmac.compare_digest", recording)
    assert Secret(SECRET) == Secret(SECRET)
    assert len(calls) == 1
    assert calls[0] == (SECRET.encode(), SECRET.encode())


def test_equal_secrets_compare_equal() -> None:
    assert Secret(SECRET) == Secret(SECRET)


def test_different_secrets_compare_unequal() -> None:
    assert Secret(SECRET) != Secret(SECRET + "x")


def test_equality_of_non_ascii_secrets_does_not_crash() -> None:
    # hmac.compare_digest raises TypeError on a non-ASCII *str*; the value type must encode
    # to bytes first so a secret with a non-ASCII char compares instead of crashing.
    assert Secret("café_péé") == Secret("café_péé")
    assert Secret("péér") != Secret("pééx")


def test_equality_of_lone_surrogate_secrets_does_not_crash() -> None:
    # A plain str .encode("utf-8") raises UnicodeEncodeError on a lone surrogate, and that
    # exception's .object/.args carry the raw secret. surrogatepass encoding must let such a
    # value compare instead of raising a secret-bearing exception out of __eq__.
    assert Secret("tok-\udc80") == Secret("tok-\udc80")
    assert Secret("tok-\udc80") != Secret("tok-\udc81")


def test_equality_against_a_non_secret_is_false_and_never_raises() -> None:
    assert (Secret(SECRET) == SECRET) is False
    assert (Secret(SECRET) == None) is False  # noqa: E711 - exercising __eq__, not identity


def test_eq_returns_notimplemented_for_an_incompatible_type() -> None:
    # The direct dunder must return NotImplemented so Python can try the reflected comparison; a
    # bare `return False` would also make `== object()` false, but for the wrong reason.
    assert Secret(SECRET).__eq__(object()) is NotImplemented


def test_secret_is_unhashable() -> None:
    with pytest.raises(TypeError):
        hash(Secret(SECRET))
    with pytest.raises(TypeError):
        {Secret(SECRET): 1}  # cannot become a dict key


def test_secret_rejects_a_non_str_value() -> None:
    with pytest.raises(TypeError):
        Secret(b"bytes-not-str")  # type: ignore[arg-type]


def test_secret_refuses_pickle_and_never_serializes_the_value() -> None:
    # Default pickling of a __slots__ object would write _value out in plaintext; refuse it so a
    # Secret in a pickled object graph (multiprocessing arg, pickle cache) cannot leak silently.
    import pickle

    with pytest.raises(TypeError):
        pickle.dumps(Secret(SECRET))


def test_secret_copy_and_deepcopy_still_work_and_stay_masked() -> None:
    # copy/deepcopy stay in memory (no serialization), so they remain supported despite the
    # pickle refusal, and the copies are real Secrets that still mask.
    import copy

    original = Secret(SECRET)
    for clone in (copy.copy(original), copy.deepcopy(original)):
        assert isinstance(clone, Secret)
        assert clone == original
        assert SECRET not in str(clone)
        assert clone.reveal() == SECRET


def test_getstate_refuses_to_expose_cleartext() -> None:
    # object.__getstate__ (3.11+) would return {'_value': ...} in cleartext to a generic dumper.
    with pytest.raises(TypeError):
        Secret("SECRETXYZ").__getstate__()
