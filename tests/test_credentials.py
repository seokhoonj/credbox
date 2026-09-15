"""Tests for the Credentials facade: four-tier resolution, Secret returns, and content-free
require()."""

from __future__ import annotations

import pytest

from credbox.credentials import Credentials
from credbox.errors import CredentialsError
from credbox.secret import Secret


def test_secret_from_own_store_is_a_secret() -> None:
    creds = Credentials("myapp")
    creds.set("api_key", value="v")
    got = creds.secret("api_key")
    assert isinstance(got, Secret)
    assert got.reveal() == "v"


def test_override_wins_over_store() -> None:
    creds = Credentials("myapp")
    creds.set("api_key", value="stored")
    assert creds.secret("api_key", override="explicit").reveal() == "explicit"  # type: ignore[union-attr]


def test_env_beats_store(monkeypatch: pytest.MonkeyPatch) -> None:
    creds = Credentials("myapp")
    creds.set("API_TOKEN", value="stored")
    monkeypatch.setenv("API_TOKEN", "from_env")
    assert creds.secret("API_TOKEN").reveal() == "from_env"  # type: ignore[union-attr]


def test_override_wins_over_env_and_store_together(monkeypatch: pytest.MonkeyPatch) -> None:
    # The top of the precedence chain: with all three tiers populated at once (override > env >
    # store), the explicit override must win. Neither test_override_wins_over_store nor
    # test_env_beats_store pins the override-vs-env edge -- only this three-way case does.
    creds = Credentials("myapp")
    creds.set("API_TOKEN", value="stored")
    monkeypatch.setenv("API_TOKEN", "from_env")
    assert creds.secret("API_TOKEN", override="explicit").reveal() == "explicit"  # type: ignore[union-attr]


@pytest.mark.parametrize("blank_env", ["", "   ", "\t\n"])
def test_blank_env_value_falls_through_to_the_store(
    monkeypatch: pytest.MonkeyPatch, blank_env: str
) -> None:
    # A blank/whitespace-only env var must read as ABSENT at the env tier, not override the stored
    # value with nothing -- the documented "a blank value at any tier is treated as absent" rule,
    # exercised end-to-end through Credentials (not just env_value in isolation).
    creds = Credentials("myapp")
    creds.set("API_TOKEN", value="stored")
    monkeypatch.setenv("API_TOKEN", blank_env)
    assert creds.secret("API_TOKEN").reveal() == "stored"  # type: ignore[union-attr]


def test_shared_store_consulted_before_own() -> None:
    Credentials("auth").set("shared_key", value="from_auth")
    creds = Credentials("myapp", shared=["auth"])
    assert creds.secret("shared_key").reveal() == "from_auth"  # type: ignore[union-attr]


def test_own_store_used_when_not_in_shared() -> None:
    Credentials("myapp").set("own", value="mine")
    creds = Credentials("myapp", shared=["auth"])
    assert creds.secret("own").reveal() == "mine"  # type: ignore[union-attr]


def test_unset_everywhere_returns_none() -> None:
    assert Credentials("myapp").secret("nope") is None


def test_require_raises_when_unset() -> None:
    with pytest.raises(CredentialsError) as excinfo:
        Credentials("myapp").require("nope")
    assert "nope" in str(excinfo.value)   # the name is safe to name; there is no value to leak


def test_set_strips_surrounding_whitespace() -> None:
    creds = Credentials("myapp")
    creds.set("k", value="  spaced  ")
    assert creds.secret("k").reveal() == "spaced"  # type: ignore[union-attr]


def test_set_refuses_a_blank_value() -> None:
    from credbox.errors import BlankSecretError

    with pytest.raises(BlankSecretError):
        Credentials("myapp").set("k", value="   ")


def test_shared_as_a_bare_string_is_rejected() -> None:
    # shared="auth" would iterate into 'a','u','t','h' and consult four bogus stores; reject it.
    # (mypy does NOT flag this -- a str IS a Sequence[str] -- so the runtime guard is the defense.)
    with pytest.raises(TypeError):
        Credentials("myapp", shared="auth")


def test_set_refuses_a_blank_name() -> None:
    from credbox.errors import BlankSecretError

    with pytest.raises(BlankSecretError):
        Credentials("myapp").set("", value="v")
    with pytest.raises(BlankSecretError):
        Credentials("myapp").set("   ", value="v")


def test_blank_secret_error_is_both_credbox_and_value_error() -> None:
    # Rooted in the CredBoxError family (so `except CredBoxError` catches it) and still a
    # ValueError (a blank is a caller mistake), mirroring InvalidAppNameError.
    from credbox.errors import BlankSecretError, CredBoxError

    assert issubclass(BlankSecretError, CredBoxError)
    assert issubclass(BlankSecretError, ValueError)


def test_blank_override_falls_through_to_the_store() -> None:
    creds = Credentials("myapp")
    creds.set("k", value="stored")
    assert creds.secret("k", override="   ").reveal() == "stored"  # type: ignore[union-attr]


def test_secret_override_is_used() -> None:
    assert Credentials("myapp").secret("k", override=Secret("ov")).reveal() == "ov"  # type: ignore[union-attr]


def test_first_shared_store_wins_over_later_ones() -> None:
    Credentials("a").set("K", value="from-a")
    Credentials("b").set("K", value="from-b")
    creds = Credentials("myapp", shared=["a", "b"])   # order: a before b
    assert creds.require("K").reveal() == "from-a"


def test_set_accepts_a_secret() -> None:
    creds = Credentials("myapp")
    creds.set("k", value=Secret("v"))
    assert creds.secret("k").reveal() == "v"  # type: ignore[union-attr]


def test_repr_never_shows_a_value() -> None:
    creds = Credentials("myapp")
    creds.set("k", value="topsecret_value")
    assert "topsecret_value" not in repr(creds)


def test_names_lists_own_store_sorted() -> None:
    creds = Credentials("myapp")
    creds.set("b_key", value="1")
    creds.set("a_key", value="2")
    assert creds.names() == ["a_key", "b_key"]


def test_set_rejects_a_non_str_value_without_reaching_json_dumps() -> None:
    # A non-str, non-Secret value is a contract violation; it must raise a type-only TypeError
    # before json.dumps, whose own TypeError would carry the value on a traceback frame.
    with pytest.raises(TypeError, match="str or Secret"):
        Credentials("app").set("K", value=b"bytes-not-str")   # type: ignore[arg-type]
