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


# --- for_app: the embeddable alternative constructor ------------------------------


def _own_store_path(app: str):
    from credbox.paths import config_dir

    return config_dir(app) / "credentials.json"


def _store_json(app: str) -> dict[str, object]:
    import json

    data = json.loads(_own_store_path(app).read_text())
    assert isinstance(data, dict)   # narrows json.loads's Any and pins the store shape
    return data


def test_for_app_standalone_matches_the_bare_constructor() -> None:
    # With no override env, for_app("thinchat") is exactly Credentials("thinchat") -- own flat store.
    Credentials.for_app("thinchat").set("api_key", value="v")
    assert _store_json("thinchat") == {"api_key": "v"}   # own flat store, not namespaced
    assert Credentials("thinchat").secret("api_key").reveal() == "v"  # type: ignore[union-attr]


def test_for_app_redirects_into_a_host_store_and_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    # A host sets BOTH <PREFIX>_STORE_APP and <PREFIX>_NAMESPACE to consolidate the component into
    # its own store under a per-component namespace; the secret lands there, not in the own store.
    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    monkeypatch.setenv("THINCHAT_NAMESPACE", "thinchat")
    Credentials.for_app("thinchat").set("GEMINI_API_KEY", value="g-1")

    assert _store_json("newswatcher") == {"thinchat": {"GEMINI_API_KEY": "g-1"}}
    assert not _own_store_path("thinchat").exists()   # nothing in the component's own store
    assert Credentials.for_app("thinchat").secret("GEMINI_API_KEY").reveal() == "g-1"  # type: ignore[union-attr]


def test_for_app_store_app_only_redirects_but_stays_flat(monkeypatch: pytest.MonkeyPatch) -> None:
    # STORE_APP without NAMESPACE: write into the host's store, still flat (no namespace section).
    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    Credentials.for_app("thinchat").set("GEMINI_API_KEY", value="g-1")
    assert _store_json("newswatcher") == {"GEMINI_API_KEY": "g-1"}   # flat in the host store
    assert not _own_store_path("thinchat").exists()


def test_for_app_namespace_only_stays_in_own_store(monkeypatch: pytest.MonkeyPatch) -> None:
    # NAMESPACE without STORE_APP: the component's OWN store, but namespaced into a section.
    monkeypatch.setenv("THINCHAT_NAMESPACE", "chat")
    Credentials.for_app("thinchat").set("GEMINI_API_KEY", value="g-1")
    assert _store_json("thinchat") == {"chat": {"GEMINI_API_KEY": "g-1"}}


def test_for_app_treats_a_blank_override_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    # A blank/whitespace-only override reads as absent (credbox's blank-is-absent rule), so the
    # default (own app, flat) applies -- an exported-but-empty var does not silently break the store.
    monkeypatch.setenv("THINCHAT_STORE_APP", "   ")
    monkeypatch.setenv("THINCHAT_NAMESPACE", "")
    Credentials.for_app("thinchat").set("api_key", value="v")
    assert _store_json("thinchat") == {"api_key": "v"}   # landed in the own flat store, not elsewhere


def test_for_app_folds_the_prefix_like_env_var_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    # The override key is env_var_prefix(app): "my-app" -> "MY_APP", so a hyphenated app name is
    # redirected by MY_APP_STORE_APP, the name a shell can actually export.
    monkeypatch.setenv("MY_APP_STORE_APP", "host")
    Credentials.for_app("my-app").set("api_key", value="v")
    assert _store_json("host") == {"api_key": "v"}       # the MY_APP_ override took effect
    assert not _own_store_path("my-app").exists()


def test_for_app_validates_the_app_before_reading_any_override() -> None:
    from credbox.errors import InvalidAppNameError

    with pytest.raises(InvalidAppNameError):
        Credentials.for_app("")            # blank identity fails fast, not an odd "_STORE_APP" lookup
    with pytest.raises(InvalidAppNameError):
        Credentials.for_app("bad/app")     # a separator in the identity is rejected up front


@pytest.mark.parametrize("var,bad", [("THINCHAT_STORE_APP", "../evil"), ("THINCHAT_NAMESPACE", "bad/ns")])
def test_for_app_rejects_an_invalid_override(monkeypatch: pytest.MonkeyPatch, var: str, bad: str) -> None:
    from credbox.errors import InvalidAppNameError

    monkeypatch.setenv(var, bad)   # a malformed override is validated by the constructor it forwards to
    with pytest.raises(InvalidAppNameError):
        Credentials.for_app("thinchat")


def test_for_app_forwards_shared() -> None:
    # for_app resolves only the (app, namespace) binding; shared passes through unchanged.
    Credentials("auth").set("shared_key", value="from_auth")
    creds = Credentials.for_app("thinchat", shared=["auth"])
    assert creds.secret("shared_key").reveal() == "from_auth"  # type: ignore[union-attr]


def test_for_app_forwards_the_backend() -> None:
    # The backend argument must reach the constructed Credentials -- a regression dropping it would
    # silently fall back to the default FileBackend. Assert the passed backend actually took the write.
    class _RecordingBackend:
        def __init__(self) -> None:
            self.writes: list[tuple[str, str, str | None]] = []

        def get(self, app: str, name: str, *, namespace: str | None = None) -> Secret | None:
            return None

        def set(self, app: str, name: str, *, value: str | Secret, namespace: str | None = None) -> None:
            self.writes.append((app, name, namespace))

        def unset(self, app: str, name: str, *, namespace: str | None = None) -> None: ...

        def names(self, app: str, *, namespace: str | None = None) -> list[str]:
            return []

    backend = _RecordingBackend()
    Credentials.for_app("thinchat", backend=backend).set("api_key", value="v")
    assert backend.writes == [("thinchat", "api_key", None)]   # the write reached the passed backend


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
