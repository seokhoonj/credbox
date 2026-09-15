"""Secret scrubbing: redact values from text and exception chains without ever raising."""

from __future__ import annotations

import pytest

from credbox.scrub import REDACTION, scrub_exception, scrub_secrets


def test_scrub_replaces_each_secret():
    text = "auth with sk-abc and sk-def"
    out = scrub_secrets(text, ["sk-abc", "sk-def"])
    assert "sk-abc" not in out and "sk-def" not in out
    assert out.count(REDACTION) == 2


def test_scrub_ignores_empty_secrets():
    assert scrub_secrets("hello", ["", "   ", None]) == "hello"   # type: ignore[list-item]


def test_scrub_prefix_secret_does_not_leak_suffix():
    # "abc" is a prefix of "abcdef"; longest-first replacement must not leave "def" behind
    assert scrub_secrets("abcdef", ["abc", "abcdef"]) == "***"


def test_scrub_secrets_survives_non_iterable():
    assert scrub_secrets("boom", None) == "boom"   # type: ignore[arg-type]  # never raises


def test_scrub_exception_cleans_args():
    err = ValueError("key sk-secret rejected")
    scrub_exception(err, ["sk-secret"])
    assert "sk-secret" not in str(err)
    assert REDACTION in str(err)


def test_scrub_exception_walks_cause_chain():
    root = ValueError("inner sk-secret")
    try:
        try:
            raise root
        except ValueError as inner:
            raise RuntimeError("outer sk-secret") from inner
    except RuntimeError as err:
        scrub_exception(err, ["sk-secret"])
        assert "sk-secret" not in str(err)
        assert err.__cause__ is not None
        assert "sk-secret" not in str(err.__cause__)


def test_scrub_exception_cleans_url_attribute():
    err = ConnectionError("failed")
    err.url = "https://api/v1?key=sk-secret"   # type: ignore[attr-defined]
    scrub_exception(err, ["sk-secret"])
    assert "sk-secret" not in err.url   # type: ignore[attr-defined]


def test_scrub_exception_survives_raising_property():
    class Nasty(Exception):
        @property
        def url(self):
            raise RuntimeError("property blows up")

    err = Nasty("sk-secret in message")
    # must not raise, and must still scrub args
    scrub_exception(err, ["sk-secret"])
    assert "sk-secret" not in str(err)


def test_scrub_exception_handles_self_referential_cause():
    err = ValueError("sk-secret")
    err.__cause__ = err   # pathological cycle must not loop forever
    scrub_exception(err, ["sk-secret"])
    assert "sk-secret" not in str(err)


def test_scrub_exception_preserves_non_string_args():
    sentinel = object()
    err = Exception("token sk-secret", 404, sentinel)
    scrub_exception(err, ["sk-secret"])
    assert "sk-secret" not in err.args[0]
    assert err.args[1] == 404          # non-string args untouched
    assert err.args[2] is sentinel


def test_scrub_exception_survives_non_iterable_secrets():
    err = ValueError("sk-secret")
    result = scrub_exception(err, None)   # type: ignore[arg-type]  # must not raise
    assert result is err


def test_scrub_survives_secrets_iterator_that_raises_mid_iteration():
    # a secrets iterator can yield one value and then raise while an error is already being
    # handled; both entry points must swallow that and never propagate on the error path
    def secrets_then_boom():
        yield "sk-secret"
        raise RuntimeError("iterator blew up mid-iteration")

    assert scrub_secrets("has sk-secret", secrets_then_boom()) == "has sk-secret"
    err = ValueError("sk-secret here")
    assert scrub_exception(err, secrets_then_boom()) is err


def test_scrub_propagates_memory_error_instead_of_returning_unscrubbed():
    # Ordinary exceptions from `secrets` are swallowed so scrub never raises on the error path,
    # but MemoryError must propagate: swallowing it would return the still-unscrubbed, secret-
    # bearing text/err as the result -- a worse leak than a MemoryError, which carries no secret.
    def secrets_then_oom():
        yield "sk-secret"
        raise MemoryError("out of memory")

    with pytest.raises(MemoryError):
        scrub_secrets("has sk-secret", secrets_then_oom())
    with pytest.raises(MemoryError):
        scrub_exception(ValueError("sk-secret here"), secrets_then_oom())


def test_scrub_exception_scrubs_secrets_nested_in_non_string_args():
    # A secret inside a list/dict/tuple arg is rendered verbatim by str(err), so it must be
    # scrubbed too -- not left because the top-level arg is not a str.
    err = ValueError(["token sk-secret in a list", {"k": "sk-secret in a dict"}, ("sk-secret",)])
    scrub_exception(err, ["sk-secret"])
    rendered = repr(err.args)
    assert "sk-secret" not in rendered
    assert REDACTION in rendered


def test_scrub_exception_propagates_memory_error_from_arg_scrub():
    # The per-node MemoryError guard must re-raise, not swallow into leaving the node's args
    # unscrubbed. Force the OOM inside the string replace that scrubs an arg.
    class OomStr(str):
        def replace(self, *_args: object, **_kwargs: object) -> str:
            raise MemoryError("out of memory scrubbing")

    with pytest.raises(MemoryError):
        scrub_exception(ValueError(OomStr("sk-secret")), ["sk-secret"])


def test_scrub_exception_descends_into_exception_group_children():
    # PEP 654: a group's members are in .exceptions, not on __cause__/__context__. Each member's
    # args are exactly what this module redacts, so the walk must descend into the group.
    group = ExceptionGroup(
        "multiple failures",
        [ValueError("first sk-secret"), RuntimeError("second sk-secret")],
    )
    scrub_exception(group, ["sk-secret"])
    rendered = "".join(str(e) for e in group.exceptions)
    assert "sk-secret" not in rendered
    assert REDACTION in rendered


def test_scrub_exception_walks_context_chain():
    # an implicit __context__ (a raise inside an except, without `from`) is a separate edge
    # from __cause__ and must also be scrubbed
    try:
        try:
            raise ValueError("inner sk-secret")
        except ValueError:
            raise RuntimeError("outer sk-secret")   # noqa: B904 -- implicit __context__ is the point
    except RuntimeError as err:
        scrub_exception(err, ["sk-secret"])
        assert err.__context__ is not None
        assert "sk-secret" not in str(err)
        assert "sk-secret" not in str(err.__context__)


def test_scrub_accepts_a_bare_string_as_one_secret_not_a_char_iterable():
    # A single secret passed directly (scrub_secrets(log, "apikey")) must be treated as ONE secret,
    # never iterated into characters -- otherwise it would redact every letter and shred the log
    # while missing the actual secret.
    out = scrub_secrets("login apikey ok, id=7", "apikey")
    assert out == f"login {REDACTION} ok, id=7"
    err = ValueError("token apikey rejected")
    scrub_exception(err, "apikey")
    assert "apikey" not in str(err) and REDACTION in str(err)


def test_scrub_accepts_a_bare_secret_as_one_secret():
    from credbox.secret import Secret

    assert scrub_secrets("v=sk-xyz done", Secret("sk-xyz")) == f"v={REDACTION} done"


def test_scrub_accepts_secret_values_and_redacts_them():
    # Passing a Secret (the natural thing, since Credentials hands back Secrets) must redact it --
    # not silently do nothing. Both entry points.
    from credbox.secret import Secret

    assert scrub_secrets("failed with sk-abc123", [Secret("sk-abc123")]) == f"failed with {REDACTION}"
    err = ValueError("token sk-abc123 rejected")
    scrub_exception(err, [Secret("sk-abc123")])
    assert "sk-abc123" not in str(err)
    assert REDACTION in str(err)


def test_scrub_redacts_lowercase_percent_encoded_echo() -> None:
    # quote/quote_plus emit UPPERCASE hex; a server echoing the value with lowercase percent-hex
    # (%2f, %40) must still be redacted -- the residual case-variant leak.
    secret = "s3cr3t/p@ss"
    scrubbed = scrub_secrets("failed for token=s3cr3t%2fp%40ss", [secret])
    assert "s3cr3t%2fp%40ss" not in scrubbed
    assert "***" in scrubbed
