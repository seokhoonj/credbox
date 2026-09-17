"""Tests for the Credentials facade: four-tier resolution, Secret returns, and content-free
require()."""

from __future__ import annotations

import pytest

from credbox.credentials import Credentials, MigrationResult
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


def test_for_app_store_app_only_auto_namespaces_by_app_name(monkeypatch: pytest.MonkeyPatch) -> None:
    # STORE_APP without NAMESPACE, redirecting into a DIFFERENT app, auto-scopes the component under
    # its own name -- so it lands in its own section, never in the host store's flat top level.
    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    Credentials.for_app("thinchat").set("GEMINI_API_KEY", value="g-1")
    assert _store_json("newswatcher") == {"thinchat": {"GEMINI_API_KEY": "g-1"}}   # own section, not flat
    assert not _own_store_path("thinchat").exists()
    got = Credentials.for_app("thinchat").secret("GEMINI_API_KEY")
    assert got is not None and got.reveal() == "g-1"


def test_for_app_two_components_into_one_host_store_do_not_collide(monkeypatch: pytest.MonkeyPatch) -> None:
    # Two components consolidated into one host store with ONLY STORE_APP set must not overwrite each
    # other in a shared flat slot: the auto-namespace isolates them by app name.
    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    monkeypatch.setenv("MAILMAIL_STORE_APP", "newswatcher")
    Credentials.for_app("thinchat").set("API_KEY", value="thin")
    Credentials.for_app("mailmail").set("API_KEY", value="mail")
    thin = Credentials.for_app("thinchat").secret("API_KEY")
    mail = Credentials.for_app("mailmail").secret("API_KEY")
    assert thin is not None and thin.reveal() == "thin"
    assert mail is not None and mail.reveal() == "mail"
    assert _store_json("newswatcher") == {
        "thinchat": {"API_KEY": "thin"},
        "mailmail": {"API_KEY": "mail"},
    }


def test_for_app_explicit_namespace_overrides_the_auto_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    monkeypatch.setenv("THINCHAT_NAMESPACE", "custom")
    Credentials.for_app("thinchat").set("K", value="v")
    assert _store_json("newswatcher") == {"custom": {"K": "v"}}   # explicit section, not the app-name default


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
    assert _store_json("host") == {"my-app": {"api_key": "v"}}   # MY_APP_ took effect; auto-namespaced by app
    assert not _own_store_path("my-app").exists()


def test_for_app_validates_the_app_lazily_on_first_store_access() -> None:
    from credbox.errors import InvalidAppNameError

    # The binding is validated on the first store access, not at construction -- so building the
    # facade never raises; a blank or malformed identity surfaces when a store tier is consulted.
    Credentials.for_app("")            # no raise here
    Credentials.for_app("bad/app")     # nor here
    with pytest.raises(InvalidAppNameError):
        Credentials.for_app("").secret("K")
    with pytest.raises(InvalidAppNameError):
        Credentials.for_app("bad/app").secret("K")


@pytest.mark.parametrize("var,bad", [("THINCHAT_STORE_APP", "../evil"), ("THINCHAT_NAMESPACE", "bad/ns")])
def test_for_app_rejects_an_invalid_override(monkeypatch: pytest.MonkeyPatch, var: str, bad: str) -> None:
    from credbox.errors import InvalidAppNameError

    monkeypatch.setenv(var, bad)   # a malformed override is validated on first store access
    creds = Credentials.for_app("thinchat")   # deferred: construction does not raise
    with pytest.raises(InvalidAppNameError):
        creds.secret("K")


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


# -- lazy binding validation: the override/env tiers never touch or validate the store --

def test_a_malformed_binding_does_not_raise_at_construction() -> None:
    # Building the facade validates nothing; a malformed segment surfaces only on a store touch,
    # so importing a module that builds a Credentials cannot crash on a bad binding.
    Credentials("bad/app")
    Credentials("app", namespace="bad/ns")
    Credentials("app", shared=["bad/shared"])


def test_an_override_resolves_under_a_malformed_binding() -> None:
    # The override tier returns before the store is touched, so a misconfigured store binding
    # never blocks a caller who supplied the secret directly.
    creds = Credentials("bad/app", namespace="../evil")
    got = creds.secret("K", override="explicit")
    assert got is not None and got.reveal() == "explicit"


def test_the_environment_resolves_under_a_malformed_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("K", "from_env")
    creds = Credentials("bad/app", namespace="../evil")
    got = creds.secret("K")
    assert got is not None and got.reveal() == "from_env"


def test_a_store_read_under_a_malformed_binding_raises_when_no_override_or_env() -> None:
    from credbox.errors import InvalidAppNameError

    creds = Credentials("app", namespace="bad/ns")
    with pytest.raises(InvalidAppNameError, match="namespace"):
        creds.secret("K")   # override and env empty -> the store tier validates the binding


def test_repr_never_raises_on_a_malformed_binding() -> None:
    # repr shows the raw binding and must never validate -- a debugger printing it cannot crash.
    assert "bad/ns" in repr(Credentials("app", namespace="bad/ns"))


def test_the_binding_is_validated_once_and_cached() -> None:
    creds = Credentials("myapp")
    creds.set("K", value="v")
    assert creds._binding() is creds._binding()   # the validated binding is memoized


# -- InvalidSecretTypeError: a non-str/Secret value or override is caught by except CredBoxError --

def test_set_rejects_a_non_str_value_as_invalid_secret_type() -> None:
    from credbox.errors import CredBoxError, InvalidSecretTypeError

    creds = Credentials("myapp")
    with pytest.raises(InvalidSecretTypeError) as exc:
        creds.set("K", value=123)  # type: ignore[arg-type]
    assert isinstance(exc.value, TypeError) and isinstance(exc.value, CredBoxError)
    assert "int" in str(exc.value) and "123" not in str(exc.value)   # names the type, never the value


def test_secret_rejects_a_non_str_override_as_invalid_secret_type() -> None:
    from credbox.errors import CredBoxError, InvalidSecretTypeError

    creds = Credentials("myapp")
    with pytest.raises(InvalidSecretTypeError) as exc:
        creds.secret("K", override=123)  # type: ignore[arg-type]
    assert isinstance(exc.value, TypeError) and isinstance(exc.value, CredBoxError)


def test_shared_store_read_flat_even_when_the_own_store_is_namespaced() -> None:
    # D: a shared store is common across apps and stored flat; an embedded component (own store
    # namespaced) must still read it at its flat layout, not force it into the component's section.
    Credentials("auth").set("shared_key", value="from_auth")   # a flat shared store
    creds = Credentials("myapp", namespace="comp", shared=["auth"])
    got = creds.secret("shared_key")
    assert got is not None and got.reveal() == "from_auth"
    # the own (namespaced) store still resolves its own keys
    creds.set("own_key", value="mine")
    own = creds.secret("own_key")
    assert own is not None and own.reveal() == "mine"


# -- resolved-binding accessors and a backend-aware store-location description --

def test_store_location_names_the_file_and_section() -> None:
    from credbox.paths import config_dir

    creds = Credentials("myapp")
    loc = creds.store_location()
    assert str(config_dir("myapp") / "credentials.json") in loc
    assert "section" not in loc   # a flat store has no section

    scoped = Credentials("myapp", namespace="comp")
    assert "section 'comp'" in scoped.store_location()


def test_app_and_namespace_report_the_resolved_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    creds = Credentials.for_app("thinchat")
    assert creds.app == "newswatcher"          # the redirected store app
    assert creds.namespace == "thinchat"       # auto-namespaced by the component's own name
    assert Credentials("myapp").app == "myapp"
    assert Credentials("myapp").namespace is None


def test_store_location_reflects_a_for_app_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    from credbox.paths import config_dir

    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    loc = Credentials.for_app("thinchat").store_location()
    assert str(config_dir("newswatcher") / "credentials.json") in loc   # the host store, not the component's
    assert "section 'thinchat'" in loc


# -- a redirect that orphans the component's own store warns once, on first store access --

def test_a_redirect_that_orphans_the_legacy_store_warns_with_the_exact_command(
    monkeypatch: pytest.MonkeyPatch, recwarn: pytest.WarningsRecorder
) -> None:
    from credbox.credentials import _warned_legacy_orphan

    _warned_legacy_orphan.clear()   # reset the once-per-app guard for a deterministic assertion
    Credentials("thinchat").set("K", value="v")   # a standalone store that already holds a secret
    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    Credentials.for_app("thinchat").names()       # the FIRST store access fires the deferred warning
    messages = [str(w.message) for w in recwarn]
    # the exact, correct remediation -- the auto-namespace target AND --remove-source, so running it
    # actually empties the legacy store (a bare copy would leave it orphaned and the warning recurring)
    assert any(
        "credbox migrate --from-app thinchat --to-app newswatcher --to-namespace thinchat --remove-source"
        in m
        for m in messages
    )


def test_reading_an_accessor_under_a_redirect_does_not_warn_or_do_store_io(
    monkeypatch: pytest.MonkeyPatch, recwarn: pytest.WarningsRecorder
) -> None:
    # The orphan check rides on a real store OPERATION, never a mere accessor: reading `.app` /
    # `.namespace` / `.store_location()` must not read the legacy store or emit the warning.
    from credbox.credentials import _warned_legacy_orphan

    _warned_legacy_orphan.clear()
    Credentials("thinchat").set("K", value="v")
    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    creds = Credentials.for_app("thinchat")
    assert creds.app == "newswatcher" and creds.namespace == "thinchat"
    assert "newswatcher" in creds.store_location()
    assert not any("migrate" in str(w.message) for w in recwarn)   # no accessor triggered the nudge


def test_the_orphan_warning_is_deferred_off_the_override_path(
    monkeypatch: pytest.MonkeyPatch, recwarn: pytest.WarningsRecorder
) -> None:
    # An override-satisfied caller never reaches the store, so it must NOT trigger the legacy-store
    # read or the warning -- the whole reason the check is deferred off for_app.
    from credbox.credentials import _warned_legacy_orphan

    _warned_legacy_orphan.clear()
    Credentials("thinchat").set("K", value="v")
    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    got = Credentials.for_app("thinchat").secret("K", override="explicit")
    assert got is not None and got.reveal() == "explicit"
    assert not any("migrate" in str(w.message) for w in recwarn)


def test_the_orphan_warning_fires_at_most_once(
    monkeypatch: pytest.MonkeyPatch, recwarn: pytest.WarningsRecorder
) -> None:
    from credbox.credentials import _warned_legacy_orphan

    _warned_legacy_orphan.clear()
    Credentials("thinchat").set("K", value="v")
    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    for _ in range(3):
        Credentials.for_app("thinchat").names()   # three fresh instances, three store accesses
    assert sum("migrate" in str(w.message) for w in recwarn) == 1


def test_the_orphan_warning_never_breaks_a_store_access_under_warnings_as_errors(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    # Best-effort: even with warnings promoted to errors, the discoverability nudge must not turn a
    # store access into a failure -- the warning is suppressed, the access succeeds.
    import warnings

    from credbox.credentials import _warned_legacy_orphan

    _warned_legacy_orphan.clear()
    Credentials("thinchat").set("K", value="v")
    monkeypatch.setenv("THINCHAT_STORE_APP", "newswatcher")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert Credentials.for_app("thinchat").names() == []   # must not raise


def test_no_orphan_warning_without_a_redirect(recwarn: pytest.WarningsRecorder) -> None:
    from credbox.credentials import _warned_legacy_orphan

    _warned_legacy_orphan.clear()
    Credentials("solo").set("K", value="v")
    Credentials.for_app("solo").names()           # standalone: no redirect, nothing orphaned
    assert not any("migrate" in str(w.message) for w in recwarn)


def test_no_orphan_warning_when_the_legacy_store_is_empty(
    monkeypatch: pytest.MonkeyPatch, recwarn: pytest.WarningsRecorder
) -> None:
    from credbox.credentials import _warned_legacy_orphan

    _warned_legacy_orphan.clear()
    monkeypatch.setenv("QUIET_STORE_APP", "newswatcher")
    Credentials.for_app("quiet").names()          # redirect active, but the own store has nothing
    assert not any("migrate" in str(w.message) for w in recwarn)


def test_store_location_falls_back_for_a_backend_without_the_capability() -> None:
    # A backend that implements only the four-operation SecretBackend interface (no describe_location)
    # gets a generic description, not a crash -- the SupportsLocationDescription fallback path.
    class BareBackend:
        def get(self, app: str, name: str, *, namespace: str | None = None) -> Secret | None:
            return None

        def set(self, app: str, name: str, *, value: str | Secret, namespace: str | None = None) -> None:
            pass

        def unset(self, app: str, name: str, *, namespace: str | None = None) -> None:
            pass

        def names(self, app: str, *, namespace: str | None = None) -> list[str]:
            return []

    loc = Credentials("myapp", namespace="comp", backend=BareBackend()).store_location()
    assert "BareBackend" in loc and "myapp" in loc and "comp" in loc


# -- migrate_to: the package-level migration API the CLI is a thin wrapper over --

def test_migrate_to_copies_and_returns_a_result() -> None:
    Credentials("src").set("K1", value="v1")
    Credentials("src").set("K2", value="v2")
    dest = Credentials("host", namespace="src")
    result = Credentials("src").migrate_to(dest)
    assert result == MigrationResult(migrated=2, overwritten=0, moved=False)
    got = dest.secret("K1")
    assert got is not None and got.reveal() == "v1"
    still = Credentials("src").secret("K1")
    assert still is not None and still.reveal() == "v1"        # copy: the source is left intact


def test_migrate_to_move_empties_the_source_and_counts_overwrites() -> None:
    Credentials("src").set("K", value="new")
    Credentials("host", namespace="src").set("K", value="old")   # dest already has K -> overwritten
    result = Credentials("src").migrate_to(Credentials("host", namespace="src"), remove_source=True)
    assert result == MigrationResult(migrated=1, overwritten=1, moved=True)
    assert Credentials("src").secret("K") is None                # moved out of the source


def test_migrate_to_rejects_the_same_store() -> None:
    from credbox.errors import CredBoxError, InvalidMigrationError

    with pytest.raises(InvalidMigrationError, match="same store") as exc:
        Credentials("app").migrate_to(Credentials("app"))
    # an illegal migration is a credbox-domain error: catchable by BOTH except idioms
    assert isinstance(exc.value, CredBoxError) and isinstance(exc.value, ValueError)


def test_migrate_to_rejects_same_app_namespaced_to_flat() -> None:
    from credbox.errors import InvalidMigrationError

    with pytest.raises(InvalidMigrationError, match="different app"):
        Credentials("app", namespace="ns").migrate_to(Credentials("app"))


def test_migrate_to_same_file_flat_to_ns_clears_a_blank_valued_key_too() -> None:
    # A blank-valued flat key (reachable only via a hand-edited store, since set() refuses blanks)
    # is read as absent by get(), so it is not among the migrated secrets -- but the same-file
    # flat->ns move must still CLEAR it, or it would leave the file flat and fault the namespaced
    # write after the good keys were already removed, losing them. Regression guard for that loss.
    import json

    Credentials("app").set("K1", value="v1")
    path = _own_store_path("app")
    data = json.loads(path.read_text())
    data["K2"] = "   "   # a blank-valued flat key, injected past set()'s blank guard
    path.write_text(json.dumps(data))

    result = Credentials("app").migrate_to(Credentials("app", namespace="ns"))
    assert result.moved is True and result.migrated == 1   # only K1 (the non-blank) migrates
    got = Credentials("app", namespace="ns").secret("K1")
    assert got is not None and got.reveal() == "v1"        # K1 survived, in the ns section
    assert _store_json("app") == {"ns": {"K1": "v1"}}      # file is wholly namespaced; the blank key is gone
