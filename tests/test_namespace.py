"""Tests for the nested-namespace feature (credbox 0.2.0): a single app store holding several
components' secrets, each in its own namespace object, without key collisions.

``namespace=None`` keeps the original flat store byte-for-byte -- that path is exercised by every
other suite (which passes no namespace); these tests cover only the new nested path, its isolation
and atomicity, and the cross-mode faults that keep one store from being read in the wrong shape.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import types

import pytest

from credbox._store_codec import StoreFault, StoreFaultKind, parse_store, serialize_store
from credbox.backends.encrypted import EncryptedFileBackend
from credbox.backends.file import FileBackend
from credbox.backends.keyring import KeyringBackend
from credbox.credentials import Credentials
from credbox.errors import CredentialsError, InvalidAppNameError
from credbox.paths import config_dir
from credbox.secret import Secret

# --- codec ---------------------------------------------------------------------

def test_codec_nested_roundtrip() -> None:
    store = {"thinchat": {"GEMINI_API_KEY": "g"}, "mailmail": {"me@naver.com": "p"}}
    encoded = serialize_store(store)
    assert not isinstance(encoded, StoreFault)
    assert parse_store(encoded, nested=True) == store


def test_codec_flat_store_read_nested_faults_not_object() -> None:
    # The str value is not a namespace object -- what a flat store looks like read in nested mode.
    encoded = serialize_store({"GEMINI_API_KEY": "g"})
    assert not isinstance(encoded, StoreFault)
    assert parse_store(encoded, nested=True) == StoreFault(StoreFaultKind.NOT_OBJECT)


def test_codec_nested_store_read_flat_faults_not_string_value() -> None:
    # The object value is not a string -- what a nested store looks like read in flat mode.
    encoded = serialize_store({"thinchat": {"GEMINI_API_KEY": "g"}})
    assert not isinstance(encoded, StoreFault)
    assert parse_store(encoded) == StoreFault(StoreFaultKind.NOT_STRING_VALUE)


def test_codec_nested_inner_non_string_faults_not_string_value() -> None:
    assert parse_store(b'{"ns": {"k": 5}}', nested=True) == StoreFault(
        StoreFaultKind.NOT_STRING_VALUE)


# --- file backend --------------------------------------------------------------

def test_file_namespace_roundtrip() -> None:
    backend = FileBackend()
    backend.set("app", "K", value="v", namespace="ns")
    stored = backend.get("app", "K", namespace="ns")
    assert stored is not None and stored.reveal() == "v"


def test_file_namespaces_are_isolated() -> None:
    backend = FileBackend()
    backend.set("app", "K", value="a-val", namespace="a")
    backend.set("app", "K", value="b-val", namespace="b")   # same name, different namespace
    secret_a = backend.get("app", "K", namespace="a")
    secret_b = backend.get("app", "K", namespace="b")
    assert secret_a is not None and secret_a.reveal() == "a-val"
    assert secret_b is not None and secret_b.reveal() == "b-val"


def test_file_on_disk_is_nested_json() -> None:
    backend = FileBackend()
    backend.set("app", "GEMINI_API_KEY", value="g", namespace="thinchat")
    on_disk = json.loads((config_dir("app") / "credentials.json").read_text(encoding="utf-8"))
    assert on_disk == {"thinchat": {"GEMINI_API_KEY": "g"}}


def test_file_set_preserves_sibling_namespace() -> None:
    backend = FileBackend()
    backend.set("app", "K1", value="v1", namespace="a")
    backend.set("app", "K2", value="v2", namespace="b")   # writing b must not drop a
    secret_a = backend.get("app", "K1", namespace="a")
    assert secret_a is not None and secret_a.reveal() == "v1"


def test_file_unset_scoped_and_preserves_sibling() -> None:
    backend = FileBackend()
    backend.set("app", "K", value="v", namespace="a")
    backend.set("app", "K", value="w", namespace="b")
    backend.unset("app", "K", namespace="a")
    assert backend.get("app", "K", namespace="a") is None
    secret_b = backend.get("app", "K", namespace="b")
    assert secret_b is not None and secret_b.reveal() == "w"


def test_file_unset_of_last_key_drops_the_empty_namespace() -> None:
    # Emptying a namespace removes it rather than leaving a residual {ns: {}} to accumulate under
    # create/delete churn; a sibling namespace is untouched.
    backend = FileBackend()
    backend.set("app", "K", value="v", namespace="a")
    backend.set("app", "K", value="w", namespace="b")
    backend.unset("app", "K", namespace="a")
    on_disk = json.loads((config_dir("app") / "credentials.json").read_text(encoding="utf-8"))
    assert on_disk == {"b": {"K": "w"}}


def test_file_names_scoped_to_namespace() -> None:
    backend = FileBackend()
    backend.set("app", "K1", value="v", namespace="a")
    backend.set("app", "K2", value="v", namespace="a")
    backend.set("app", "OTHER", value="v", namespace="b")
    assert backend.names("app", namespace="a") == ["K1", "K2"]


def test_file_absent_namespace_reads_none() -> None:
    backend = FileBackend()
    backend.set("app", "K", value="v", namespace="a")
    assert backend.get("app", "K", namespace="nope") is None


def test_file_concurrent_nested_writes_across_namespaces_all_survive() -> None:
    # A namespaced set is a read-whole-store / modify-one-namespace / write-whole-store cycle; if
    # the lock or the whole-structure preservation were wrong, a concurrent writer to another
    # namespace would drop the loser's keys. 24 writers spread over 4 namespaces, released together,
    # must all survive -- the nested analogue of the flat concurrency test.
    count = 24
    barrier = threading.Barrier(count)

    def writer(i: int) -> None:
        barrier.wait()
        FileBackend().set("myapp", f"k{i}", value=f"v{i}", namespace=f"ns{i % 4}")

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for i in range(count):
        stored = FileBackend().get("myapp", f"k{i}", namespace=f"ns{i % 4}")
        assert stored is not None and stored.reveal() == f"v{i}"


def test_file_flat_store_read_with_namespace_raises_malformed() -> None:
    backend = FileBackend()
    backend.set("app", "K", value="v")   # flat write
    with pytest.raises(CredentialsError):
        backend.get("app", "K", namespace="a")   # reading a flat store in nested mode


def test_file_nested_store_read_flat_raises_malformed() -> None:
    backend = FileBackend()
    backend.set("app", "K", value="v", namespace="a")   # nested write
    with pytest.raises(CredentialsError):
        backend.get("app", "K")   # reading a nested store in flat mode


def test_wrong_mode_error_hints_at_the_layout_mismatch() -> None:
    # A layout-mismatch fault must point the reader at the likely cause (content-free), not just
    # say "malformed" -- the two directions carry the two distinct hints.
    flat = FileBackend()
    flat.set("app", "K", value="v")
    with pytest.raises(CredentialsError, match="flat store read with a namespace"):
        flat.get("app", "K", namespace="a")
    nested = FileBackend()
    nested.set("app2", "K", value="v", namespace="a")
    with pytest.raises(CredentialsError, match="namespaced store read without a namespace"):
        nested.get("app2", "K")


def test_file_nested_malformed_error_is_content_free() -> None:
    # The wrong-mode read decrypts/parses a store whose value is a real secret; the resulting
    # CredentialsError must carry neither the secret nor a __cause__/__context__ that retains it --
    # the same leak guarantee the flat malformed test proves, now for the nested loader.
    secret = "sk-file-nested-SECRET"
    backend = FileBackend()
    backend.set("app", "K", value=secret, namespace="a")   # nested store holding a secret
    with pytest.raises(CredentialsError) as excinfo:
        backend.get("app", "K")   # read flat -> the {name: {..}} value is not a str -> fault
    err = excinfo.value
    assert secret not in str(err)
    assert err.__cause__ is None
    assert err.__context__ is None


# --- encrypted backend ---------------------------------------------------------

_PASSPHRASE = Secret("correct horse battery staple")


def test_encrypted_namespace_roundtrip_and_isolation() -> None:
    backend = EncryptedFileBackend(passphrase=_PASSPHRASE)
    backend.set("app", "K", value="a-val", namespace="a")
    backend.set("app", "K", value="b-val", namespace="b")
    secret_a = backend.get("app", "K", namespace="a")
    secret_b = backend.get("app", "K", namespace="b")
    assert secret_a is not None and secret_a.reveal() == "a-val"
    assert secret_b is not None and secret_b.reveal() == "b-val"
    # A fresh instance (same passphrase) still reads the sibling namespace.
    fresh_read = EncryptedFileBackend(passphrase=_PASSPHRASE).get("app", "K", namespace="a")
    assert fresh_read is not None and fresh_read.reveal() == "a-val"


def test_encrypted_names_and_unset_are_namespace_scoped() -> None:
    backend = EncryptedFileBackend(passphrase=_PASSPHRASE)
    backend.set("app", "K1", value="v", namespace="a")
    backend.set("app", "K2", value="v", namespace="a")
    backend.set("app", "K", value="keep", namespace="b")
    assert backend.names("app", namespace="a") == ["K1", "K2"]
    backend.unset("app", "K1", namespace="a")
    assert backend.names("app", namespace="a") == ["K2"]
    # A fresh instance proves the sibling namespace survived the unset through a real re-encrypt.
    kept = EncryptedFileBackend(passphrase=_PASSPHRASE).get("app", "K", namespace="b")
    assert kept is not None and kept.reveal() == "keep"


def test_encrypted_unset_of_last_key_drops_the_empty_namespace() -> None:
    # The residue-cleanup fix, over a real re-encrypt: emptying a namespace removes it (a fresh
    # instance reads back only the surviving sibling), not a residual {ns: {}}.
    backend = EncryptedFileBackend(passphrase=_PASSPHRASE)
    backend.set("app", "K", value="v", namespace="a")
    backend.set("app", "K", value="keep", namespace="b")
    backend.unset("app", "K", namespace="a")
    fresh = EncryptedFileBackend(passphrase=_PASSPHRASE)
    assert fresh.names("app", namespace="a") == []
    kept = fresh.get("app", "K", namespace="b")
    assert kept is not None and kept.reveal() == "keep"


def test_encrypted_nested_malformed_error_is_content_free() -> None:
    # The decrypted plaintext is a flat store holding a real secret; reading it in nested mode must
    # fault without the secret (or a retained plaintext frame) riding along -- the leak guarantee
    # for the encrypted backend's nested loader, over genuine decrypted bytes.
    secret = "sk-enc-nested-SECRET"
    backend = EncryptedFileBackend(passphrase=_PASSPHRASE)
    backend.set("app", "K", value=secret)   # flat encrypted store
    with pytest.raises(CredentialsError) as excinfo:
        backend.get("app", "K", namespace="a")   # read nested -> the str value is not an object
    err = excinfo.value
    assert secret not in str(err)
    assert err.__cause__ is None
    assert err.__context__ is None


# --- keyring backend -----------------------------------------------------------

def _install_fake_keyring(
    monkeypatch: pytest.MonkeyPatch, store: dict[tuple[str, str], str]
) -> None:
    """Install a fake ``keyring`` backed by ``store`` keyed on ``(service, username)``, so a test
    can assert the service name the backend used (the namespace folding)."""
    errors = types.ModuleType("keyring.errors")

    class KeyringError(Exception): ...
    class NoKeyringErr(KeyringError): ...
    class PasswordDeleteError(KeyringError): ...

    errors.KeyringError = KeyringError          # type: ignore[attr-defined]
    errors.NoKeyringError = NoKeyringErr        # type: ignore[attr-defined]
    errors.PasswordDeleteError = PasswordDeleteError   # type: ignore[attr-defined]

    module = types.ModuleType("keyring")
    module.errors = errors                      # type: ignore[attr-defined]
    module.get_password = lambda service, username: store.get((service, username))   # type: ignore[attr-defined]

    def set_password(service: str, username: str, password: str) -> None:
        store[(service, username)] = password

    def delete_password(service: str, username: str) -> None:
        if (service, username) in store:
            del store[(service, username)]
        else:
            raise PasswordDeleteError()

    module.set_password = set_password          # type: ignore[attr-defined]
    module.delete_password = delete_password    # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "keyring", module)
    monkeypatch.setitem(sys.modules, "keyring.errors", errors)


def test_keyring_namespace_folds_into_the_service_name(monkeypatch: pytest.MonkeyPatch) -> None:
    store: dict[tuple[str, str], str] = {}
    _install_fake_keyring(monkeypatch, store)
    backend = KeyringBackend(fallback=FileBackend())
    backend.set("app", "K", value="v", namespace="thinchat")
    # Stored under the namespace-folded service, so a namespace's keyring entries cannot collide
    # with the app's flat entries or another namespace's.
    assert ("app/thinchat", "K") in store
    assert ("app", "K") not in store
    stored = backend.get("app", "K", namespace="thinchat")
    assert stored is not None and stored.reveal() == "v"
    assert backend.get("app", "K", namespace="other") is None


def test_keyring_namespaced_unset_removes_only_its_folded_entry(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    store: dict[tuple[str, str], str] = {}
    _install_fake_keyring(monkeypatch, store)
    backend = KeyringBackend(fallback=FileBackend())
    backend.set("app", "K", value="a-val", namespace="a")
    backend.set("app", "K", value="b-val", namespace="b")
    backend.unset("app", "K", namespace="a")
    assert ("app/a", "K") not in store   # only namespace a's folded entry is deleted
    assert ("app/b", "K") in store       # the sibling namespace survives
    kept = backend.get("app", "K", namespace="b")
    assert kept is not None and kept.reveal() == "b-val"


# --- Credentials facade --------------------------------------------------------

def test_facade_namespaces_coexist_in_one_app_store() -> None:
    Credentials("newswatcher", namespace="thinchat").set("GEMINI_API_KEY", value="g")
    Credentials("newswatcher", namespace="mailmail").set("me@naver.com", value="p")
    thinchat = Credentials("newswatcher", namespace="thinchat").secret("GEMINI_API_KEY")
    mailmail = Credentials("newswatcher", namespace="mailmail").secret("me@naver.com")
    assert thinchat is not None and thinchat.reveal() == "g"
    assert mailmail is not None and mailmail.reveal() == "p"
    # One physical file holds both components' secrets, each under its own namespace.
    on_disk = json.loads((config_dir("newswatcher") / "credentials.json").read_text(encoding="utf-8"))
    assert on_disk == {"thinchat": {"GEMINI_API_KEY": "g"}, "mailmail": {"me@naver.com": "p"}}


def test_facade_env_wins_over_a_namespaced_store(monkeypatch: pytest.MonkeyPatch) -> None:
    Credentials("app", namespace="ns").set("K", value="from-store")
    monkeypatch.setenv("K", "from-env")
    resolved = Credentials("app", namespace="ns").secret("K")
    assert resolved is not None and resolved.reveal() == "from-env"


def test_facade_namespace_scopes_the_shared_store_too() -> None:
    # The same key lives in two namespaces of a shared app; a namespaced consumer must read only its
    # own namespace's value from that shared store, and the shared tier still precedes the own store.
    Credentials("auth", namespace="a").set("API_KEY", value="auth-a")
    Credentials("auth", namespace="b").set("API_KEY", value="auth-b")
    Credentials("myapp", namespace="a").set("API_KEY", value="mine-a")   # own store, same namespace
    resolved = Credentials("myapp", shared=["auth"], namespace="a").secret("API_KEY")
    assert resolved is not None and resolved.reveal() == "auth-a"   # shared/a wins, not auth-b, not own


def test_facade_names_scoped_to_namespace() -> None:
    scoped = Credentials("app", namespace="ns")
    scoped.set("K1", value="v")
    scoped.set("K2", value="v")
    Credentials("app", namespace="other").set("K3", value="v")
    assert scoped.names() == ["K1", "K2"]


def test_facade_unset_scoped_to_namespace() -> None:
    Credentials("app", namespace="a").set("K", value="v")
    Credentials("app", namespace="b").set("K", value="w")
    Credentials("app", namespace="a").unset("K")
    assert Credentials("app", namespace="a").secret("K") is None
    kept = Credentials("app", namespace="b").secret("K")
    assert kept is not None and kept.reveal() == "w"


def test_facade_invalid_namespace_names_it_as_a_namespace() -> None:
    with pytest.raises(InvalidAppNameError, match="namespace"):
        Credentials("app", namespace="bad/namespace")


def test_facade_repr_shows_the_namespace_never_a_value() -> None:
    creds = Credentials("app", namespace="ns")
    creds.set("K", value="s3cr3t")
    rendered = repr(creds)
    assert "namespace='ns'" in rendered
    assert "s3cr3t" not in rendered


class _LegacyBackend:
    """A custom backend written against the ORIGINAL four-method protocol -- no ``namespace``
    parameter anywhere. Flat (namespace=None) usage must keep working: the facade omits the kwarg."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}

    def get(self, app: str, name: str) -> Secret | None:
        raw = self.store.get((app, name))
        return Secret(raw) if raw is not None else None

    def set(self, app: str, name: str, *, value: str | Secret) -> None:
        self.store[(app, name)] = value.reveal() if isinstance(value, Secret) else value

    def unset(self, app: str, name: str) -> None:
        self.store.pop((app, name), None)

    def names(self, app: str) -> list[str]:
        return sorted(name for (a, name) in self.store if a == app)


def test_facade_flat_usage_works_with_a_pre_0_2_backend_without_namespace_param() -> None:
    # Backward-compat guarantee for the extension surface: a 0.1.0-era SecretBackend with no
    # `namespace` kwarg must not break under flat use. Before the fix the facade passed
    # `namespace=None` unconditionally and this raised TypeError; now it omits the kwarg when None.
    backend = _LegacyBackend()
    creds = Credentials("app", backend=backend)   # type: ignore[arg-type]  # deliberately pre-0.2 shape
    creds.set("K", value="v")
    got = creds.secret("K")
    assert got is not None and got.reveal() == "v"
    assert creds.names() == ["K"]
    creds.unset("K")
    assert creds.secret("K") is None


def test_facade_namespace_none_writes_the_flat_layout_byte_for_byte() -> None:
    # namespace=None must produce the exact v0.1.0 flat bytes, not merely an equal parsed object --
    # a whitespace/key-order/escaping change would still round-trip through json.loads but break a
    # user's existing file and any external reader. Assert the raw bytes.
    creds = Credentials("app")
    creds.set("K1", value="v1")
    creds.set("KEY", value="일본어")   # non-ASCII survives ensure_ascii=False, unescaped
    on_disk = (config_dir("app") / "credentials.json").read_bytes()
    assert on_disk == '{"K1": "v1", "KEY": "일본어"}'.encode()   # insertion order, spaced separators


# --- cross-mode leak: both loaders, both backends, content- AND traceback-free -------------------

def _secret_in_traceback_frames(exc: BaseException, secret: str) -> bool:
    """True if ``secret`` (as a str or within bytes) sits in any CREDBOX frame-local on ``exc``'s
    traceback -- i.e. a content-free error would still have retained the plaintext in a frame. The
    leak-safe loaders ``del`` the store bytes before raising, so this must be False. Only credbox's
    own frames are inspected: the test frame legitimately holds the ``secret`` literal, and the
    guarantee is about credbox's frames, not the caller's."""
    tb = exc.__traceback__
    while tb is not None:
        module = tb.tb_frame.f_globals.get("__name__", "")
        if module.startswith("credbox"):
            for val in list(tb.tb_frame.f_locals.values()):   # snapshot: locals can mutate
                if isinstance(val, str) and secret in val:
                    return True
                if isinstance(val, (bytes, bytearray)) and secret.encode() in bytes(val):
                    return True
        tb = tb.tb_next
    return False


def test_file_flat_store_read_nested_error_is_content_and_traceback_free() -> None:
    # The complementary direction to test_file_nested_malformed_...: a flat store holding a secret,
    # read in nested mode, exercises _load_nested's del-before-raise over real secret bytes.
    secret = "sk-file-flat-SECRET"
    backend = FileBackend()
    backend.set("app", "K", value=secret)   # flat store
    with pytest.raises(CredentialsError) as excinfo:
        backend.get("app", "K", namespace="a")   # read nested -> the str value is not an object
    err = excinfo.value
    assert secret not in str(err)
    assert err.__cause__ is None and err.__context__ is None
    assert not _secret_in_traceback_frames(err, secret)


def test_encrypted_flat_store_read_nested_error_is_content_and_traceback_free() -> None:
    secret = "sk-enc-nested-read-SECRET"
    backend = EncryptedFileBackend(passphrase=_PASSPHRASE)
    backend.set("app", "K", value=secret)   # flat encrypted store
    with pytest.raises(CredentialsError) as excinfo:
        backend.get("app", "K", namespace="a")   # _load_nested over real decrypted plaintext
    err = excinfo.value
    assert secret not in str(err)
    assert err.__cause__ is None and err.__context__ is None
    assert not _secret_in_traceback_frames(err, secret)


def test_encrypted_nested_store_read_flat_error_is_content_and_traceback_free() -> None:
    secret = "sk-enc-flat-read-SECRET"
    backend = EncryptedFileBackend(passphrase=_PASSPHRASE)
    backend.set("app", "K", value=secret, namespace="a")   # nested encrypted store
    with pytest.raises(CredentialsError) as excinfo:
        backend.get("app", "K")   # _load_flat over real decrypted plaintext
    err = excinfo.value
    assert secret not in str(err)
    assert err.__cause__ is None and err.__context__ is None
    assert not _secret_in_traceback_frames(err, secret)


# --- empty store, no-op unset, blank values, degenerate shapes -----------------------------------

def test_codec_empty_store_is_valid_in_both_modes() -> None:
    assert parse_store(b"{}") == {}
    assert parse_store(b"{}", nested=True) == {}


def test_file_emptied_store_can_be_rewritten_in_either_mode() -> None:
    # Emptying a namespaced store leaves a bare {} (see the last-key-drop test), which is valid in
    # both modes -- so the store can subsequently be written flat OR namespaced without a fault.
    backend = FileBackend()
    backend.set("app", "K", value="v", namespace="a")
    backend.unset("app", "K", namespace="a")
    assert (config_dir("app") / "credentials.json").read_bytes() == b"{}"
    backend.set("app", "K2", value="flat")   # flat write onto the emptied store -- no fault
    got = backend.get("app", "K2")
    assert got is not None and got.reveal() == "flat"


def test_file_namespaced_unset_of_absent_target_is_a_noop() -> None:
    # An absent file, an absent namespace, and an absent key must each be a silent no-op that does
    # NOT rewrite the store (bytes unchanged proves no needless write).
    backend = FileBackend()
    backend.unset("fresh", "K", namespace="a")   # absent file: no exception, no file created
    assert not (config_dir("fresh") / "credentials.json").exists()
    backend.set("app", "K", value="v", namespace="a")
    before = (config_dir("app") / "credentials.json").read_bytes()
    backend.unset("app", "K", namespace="absent")   # absent namespace
    backend.unset("app", "OTHER", namespace="a")    # absent key in an existing namespace
    assert (config_dir("app") / "credentials.json").read_bytes() == before   # never rewritten


def test_encrypted_namespaced_unset_of_absent_key_does_not_re_encrypt() -> None:
    # A re-encrypt draws a fresh nonce/salt, so identical bytes prove the no-op did not rewrite.
    backend = EncryptedFileBackend(passphrase=_PASSPHRASE)
    backend.set("app", "K", value="v", namespace="a")
    before = (config_dir("app") / "credentials.enc").read_bytes()
    backend.unset("app", "OTHER", namespace="a")   # absent key -> no re-encrypt
    assert (config_dir("app") / "credentials.enc").read_bytes() == before


def test_file_namespaced_blank_value_reads_as_absent() -> None:
    # The backend stores what it is given (the facade strips); a blank stored value must normalize
    # to absent on read within a namespace, so it falls through instead of winning as an empty Secret.
    backend = FileBackend()
    backend.set("app", "K", value="   ", namespace="a")   # backend does not strip
    assert backend.get("app", "K", namespace="a") is None


def test_facade_namespaced_set_strips_surrounding_whitespace() -> None:
    Credentials("app", namespace="a").set("K", value="  v  ")
    got = Credentials("app", namespace="a").secret("K")
    assert got is not None and got.reveal() == "v"


def test_namespace_may_equal_the_secret_name() -> None:
    # The degenerate shape {"same": {"same": "v"}} must round-trip: a level-confused lookup would
    # pass the isolation tests but fail here.
    FileBackend().set("app", "same", value="v", namespace="same")
    got = FileBackend().get("app", "same", namespace="same")
    assert got is not None and got.reveal() == "v"
    on_disk = json.loads((config_dir("app") / "credentials.json").read_text(encoding="utf-8"))
    assert on_disk == {"same": {"same": "v"}}


# --- keyring: the file-fallback paths carry the namespace too ------------------------------------

def _install_keyring_with_no_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install a fake ``keyring`` whose every operation raises ``NoKeyringError`` -- the 'no OS
    keyring backend exists' case that routes ``KeyringBackend`` to its file fallback."""
    errors = types.ModuleType("keyring.errors")

    class KeyringError(Exception): ...
    class NoKeyringErr(KeyringError): ...
    class PasswordDeleteError(KeyringError): ...

    errors.KeyringError = KeyringError                 # type: ignore[attr-defined]
    errors.NoKeyringError = NoKeyringErr               # type: ignore[attr-defined]
    errors.PasswordDeleteError = PasswordDeleteError   # type: ignore[attr-defined]

    def no_backend(*args: object) -> None:
        raise NoKeyringErr()

    module = types.ModuleType("keyring")
    module.errors = errors                # type: ignore[attr-defined]
    module.get_password = no_backend      # type: ignore[attr-defined]
    module.set_password = no_backend      # type: ignore[attr-defined]
    module.delete_password = no_backend   # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "keyring", module)
    monkeypatch.setitem(sys.modules, "keyring.errors", errors)


def test_keyring_no_backend_fallback_is_namespace_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    # When no OS keyring exists, get/set/unset delegate to the file fallback -- and MUST forward the
    # namespace. If namespace= were dropped, the fallback set would write flat onto the nested store
    # and fault; and reads/deletes would touch the wrong section. A sibling namespace must survive.
    _install_keyring_with_no_backend(monkeypatch)
    fallback = FileBackend()
    fallback.set("app", "X", value="sibling", namespace="other")   # pre-existing sibling section
    backend = KeyringBackend(fallback=fallback)
    backend.set("app", "K", value="v", namespace="target")
    target = backend.get("app", "K", namespace="target")
    assert target is not None and target.reveal() == "v"
    sibling = backend.get("app", "X", namespace="other")
    assert sibling is not None and sibling.reveal() == "sibling"   # untouched
    backend.unset("app", "K", namespace="target")
    assert backend.get("app", "K", namespace="target") is None
    assert backend.get("app", "X", namespace="other") is not None   # sibling still there


def test_keyring_names_and_stale_cleanup_are_namespace_scoped(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    # names() delegates to the fallback for the given namespace, and a successful keyring set clears
    # the stale fallback copy for THAT namespace only -- both forward the namespace.
    store: dict[tuple[str, str], str] = {}
    _install_fake_keyring(monkeypatch, store)
    fallback = FileBackend()
    fallback.set("app", "K", value="stale", namespace="target")   # stale plaintext, target section
    fallback.set("app", "S", value="keep", namespace="sibling")   # sibling section
    backend = KeyringBackend(fallback=fallback)
    assert backend.names("app", namespace="target") == ["K"]
    backend.set("app", "K", value="fresh", namespace="target")    # keyring ok -> clears stale copy
    assert fallback.get("app", "K", namespace="target") is None   # target's stale copy cleared
    kept = fallback.get("app", "S", namespace="sibling")
    assert kept is not None and kept.reveal() == "keep"           # sibling untouched


# --- cross-process atomicity of the namespaced read-modify-write ---------------------------------

def _write_namespaced_keys(keys: list[str]) -> None:
    """Module-level so a forked child can run it: write each key into its own namespace of one
    shared store."""
    backend = FileBackend()
    for key in keys:
        backend.set("crossns", key, value=f"v-{key}", namespace=f"ns-{key}")


def test_cross_process_nested_writes_all_survive_under_the_os_lock() -> None:
    # The thread barrier test covers one process; the OS file lock exists to serialize the whole-
    # store read-modify-write across PROCESSES. Two forked writers each populate N distinct
    # namespaces of one store concurrently; with the flock all 2N namespaces survive.
    if os.name != "posix":
        pytest.skip("advisory file locks (fork)")
    import multiprocessing as mp

    n = 25
    child_keys = [f"c{i}" for i in range(n)]
    parent_keys = [f"p{i}" for i in range(n)]
    proc = mp.get_context("fork").Process(target=_write_namespaced_keys, args=(child_keys,))
    proc.start()
    _write_namespaced_keys(parent_keys)
    proc.join(timeout=30)
    assert proc.exitcode == 0
    backend = FileBackend()
    for key in child_keys + parent_keys:
        got = backend.get("crossns", key, namespace=f"ns-{key}")
        assert got is not None and got.reveal() == f"v-{key}"


# --- unset must drop a namespace ONLY when it empties, not otherwise --------------

def test_file_unset_one_of_several_keeps_the_namespace() -> None:
    # Removing one key from a namespace that still holds others must NOT drop the whole namespace
    # (guards against an unconditional `del nested[namespace]`).
    backend = FileBackend()
    backend.set("app", "K1", value="v1", namespace="a")
    backend.set("app", "K2", value="v2", namespace="a")
    backend.unset("app", "K1", namespace="a")
    assert backend.names("app", namespace="a") == ["K2"]
    kept = backend.get("app", "K2", namespace="a")
    assert kept is not None and kept.reveal() == "v2"


def test_encrypted_emptied_namespace_leaves_a_reusable_store() -> None:
    # After the last key of the only namespace is unset, the decrypted store must be a bare {} (not
    # a residual {ns: {}}) -- proven by a subsequent FLAT set succeeding rather than faulting
    # NOT_STRING_VALUE on the leftover namespace object.
    backend = EncryptedFileBackend(passphrase=_PASSPHRASE)
    backend.set("app", "K", value="v", namespace="a")
    backend.unset("app", "K", namespace="a")
    backend.set("app", "K2", value="flat")   # flat write onto the emptied store -- must not fault
    got = backend.get("app", "K2")
    assert got is not None and got.reveal() == "flat"


def test_encrypted_namespaced_blank_value_reads_as_absent() -> None:
    # normalize_secret_value must run on the encrypted backend's namespaced get too (blank -> absent).
    backend = EncryptedFileBackend(passphrase=_PASSPHRASE)
    backend.set("app", "K", value="   ", namespace="a")   # backend stores raw; blank
    assert backend.get("app", "K", namespace="a") is None


def test_keyring_flat_and_namespaced_entries_coexist(monkeypatch: pytest.MonkeyPatch) -> None:
    # The wholly-flat-or-namespaced rule is a single-file-store property; keyring entries are
    # independent items, so an app's flat entry (service "app") and a namespaced one (service
    # "app/a") coexist without collision.
    store: dict[tuple[str, str], str] = {}
    _install_fake_keyring(monkeypatch, store)
    backend = KeyringBackend(fallback=FileBackend())
    backend.set("app", "K", value="flat-val")
    backend.set("app", "K", value="ns-val", namespace="a")
    flat = backend.get("app", "K")
    scoped = backend.get("app", "K", namespace="a")
    assert flat is not None and flat.reveal() == "flat-val"
    assert scoped is not None and scoped.reveal() == "ns-val"
    assert ("app", "K") in store and ("app/a", "K") in store   # two independent keyring items
