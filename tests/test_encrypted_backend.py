"""Tests for the [crypto] encrypted backend: roundtrip, fail-closed decryption, AAD-bound header,
and nonce freshness. Requires the ``cryptography`` extra (installed in the dev env)."""

from __future__ import annotations

import inspect
import json

import pytest

from credbox.backends.encrypted import EncryptedFileBackend
from credbox.errors import DecryptionError
from credbox.secret import Secret

SECRET = "sk_live_TOPSECRET_0123456789"
PASSPHRASE = Secret("correct horse battery staple")
_HEADER_LEN_BYTES = 4
_NONCE_LEN = 12


def _backend(passphrase: Secret = PASSPHRASE) -> EncryptedFileBackend:
    return EncryptedFileBackend(passphrase=passphrase)


def test_set_then_get_roundtrips_a_secret() -> None:
    backend = _backend()
    backend.set("myapp", "api_key", value=SECRET)
    got = backend.get("myapp", "api_key")
    assert isinstance(got, Secret)
    assert got.reveal() == SECRET


def test_value_persists_across_backend_instances() -> None:
    _backend().set("myapp", "api_key", value=SECRET)
    got = _backend().get("myapp", "api_key")   # a fresh instance, same passphrase
    assert got is not None and got.reveal() == SECRET


def test_unset_and_names() -> None:
    backend = _backend()
    backend.set("myapp", "a", value="va")
    backend.set("myapp", "b", value="vb")
    assert backend.names("myapp") == ["a", "b"]
    backend.unset("myapp", "a")
    assert backend.names("myapp") == ["b"]
    backend.unset("myapp", "a")   # idempotent


def test_encrypt_does_not_retain_the_passphrase_in_a_frame_on_a_late_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `del passphrase` after key derivation keeps it off the json.dumps / AESGCM.encrypt frame, so a
    # fault there cannot expose it to a frame-locals-dumping handler (rich/sentry/pytest --showlocals).
    # Without the del, _encrypt's frame would still bind `passphrase` when encrypt() raises.
    from credbox.backends import encrypted

    raw = PASSPHRASE.reveal()

    class _BoomAESGCM:
        def __init__(self, key: bytes) -> None:
            pass

        def encrypt(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
            raise RuntimeError("boom during encrypt")

    monkeypatch.setattr(encrypted, "AESGCM", _BoomAESGCM)
    with pytest.raises(RuntimeError) as excinfo:
        _backend().set("myapp", "api_key", value=SECRET)
    leaked = []
    tb = excinfo.value.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        # Only credbox's own frames matter -- this test frame legitimately holds `raw` for the
        # comparison. Snapshot f_locals with list() (a 3.13+ live proxy raises if iterated directly).
        if frame.f_globals.get("__name__", "").startswith("credbox"):
            for name, val in list(frame.f_locals.items()):
                if isinstance(val, str) and raw in val:
                    leaked.append((frame.f_code.co_name, name))
        tb = tb.tb_next
    assert leaked == [], f"passphrase retained in a credbox frame local: {leaked}"


def test_wrong_passphrase_fails_closed_content_free() -> None:
    _backend(Secret("right-passphrase")).set("myapp", "api_key", value=SECRET)
    with pytest.raises(DecryptionError) as excinfo:
        _backend(Secret("wrong-passphrase")).get("myapp", "api_key")
    err = excinfo.value
    assert SECRET not in str(err)
    assert err.__cause__ is None       # the InvalidTag never rides along
    assert err.__context__ is None     # ... on either link


def test_tampered_ciphertext_fails_closed() -> None:
    backend = _backend()
    backend.set("myapp", "api_key", value=SECRET)
    path = backend.path("myapp")
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0x01   # flip a ciphertext/tag bit
    path.write_bytes(bytes(blob))
    with pytest.raises(DecryptionError) as excinfo:
        _backend().get("myapp", "api_key")
    err = excinfo.value
    assert SECRET not in str(err)
    assert err.__cause__ is None and err.__context__ is None   # the InvalidTag never rides along


def test_tampered_header_fails_via_aad_binding() -> None:
    # A *semantically inert* header change (a benign extra JSON member, header re-parsed fine and
    # KDF params untouched) must still fail -- only the AES-GCM tag over the AAD can catch it. A
    # test that flipped a random header byte could pass without any AAD binding.
    backend = _backend()
    backend.set("myapp", "api_key", value=SECRET)
    path = backend.path("myapp")
    blob = path.read_bytes()
    header_len = int.from_bytes(blob[:_HEADER_LEN_BYTES], "big")
    header = json.loads(blob[_HEADER_LEN_BYTES:_HEADER_LEN_BYTES + header_len])
    rest = blob[_HEADER_LEN_BYTES + header_len:]        # nonce || ciphertext, left unchanged
    header["benign_extra"] = "inert"                    # parses fine, KDF params unchanged
    new_header = json.dumps(header, sort_keys=True).encode("utf-8")
    tampered = len(new_header).to_bytes(_HEADER_LEN_BYTES, "big") + new_header + rest
    path.write_bytes(tampered)
    with pytest.raises(DecryptionError) as excinfo:
        _backend().get("myapp", "api_key")
    err = excinfo.value
    assert SECRET not in str(err)
    assert err.__cause__ is None and err.__context__ is None


@pytest.mark.parametrize(
    "blob",
    [b"", b"\x00\x00\x00\x10short", b"not a credbox encrypted blob at all", b"\xff" * 64],
    ids=["empty", "truncated-header", "garbage-text", "garbage-bytes"],
)
def test_garbage_or_truncated_blob_fails_closed_content_free(blob: bytes) -> None:
    backend = _backend()
    backend.set("myapp", "api_key", value=SECRET)
    backend.path("myapp").write_bytes(blob)
    with pytest.raises(DecryptionError) as excinfo:
        _backend().get("myapp", "api_key")
    err = excinfo.value
    assert SECRET not in str(err)
    assert err.__cause__ is None
    assert err.__context__ is None


def test_recursion_error_in_the_header_parse_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A tampered header whose JSON nests thousands of levels raises RecursionError in json.loads;
    # it must be folded into a content-free DecryptionError, not escape as a traceback whose frames
    # retain passphrase/blob. Mock-forced rather than building the crashing input.
    backend = _backend()
    backend.set("myapp", "api_key", value=SECRET)

    def _raise(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("header nests too deep")

    monkeypatch.setattr("credbox.backends.encrypted.json.loads", _raise)
    with pytest.raises(DecryptionError):
        _backend().get("myapp", "api_key")


def test_set_on_a_store_written_with_another_passphrase_fails_closed() -> None:
    # set() must read-merge the existing store first, so a wrong passphrase fails closed there
    # rather than silently overwriting the store under a new key (which would strand the old data).
    _backend(Secret("right-passphrase")).set("myapp", "api_key", value=SECRET)
    with pytest.raises(DecryptionError):
        _backend(Secret("wrong-passphrase")).set("myapp", "other", value="v")


def test_unset_on_a_store_written_with_another_passphrase_fails_closed() -> None:
    _backend(Secret("right-passphrase")).set("myapp", "api_key", value=SECRET)
    with pytest.raises(DecryptionError):
        _backend(Secret("wrong-passphrase")).unset("myapp", "api_key")


def test_lone_surrogate_passphrase_roundtrips() -> None:
    # A passphrase holding a lone surrogate (e.g. sourced from an env var via surrogateescape)
    # must encode deterministically via surrogatepass on both write and read, not crash with a
    # UnicodeEncodeError whose frame would carry the passphrase.
    passphrase = Secret("pw-\udc80-\udcff")
    _backend(passphrase).set("myapp", "api_key", value=SECRET)
    got = _backend(passphrase).get("myapp", "api_key")
    assert got is not None and got.reveal() == SECRET


def test_infinite_kdf_param_in_header_fails_closed_not_overflow() -> None:
    # A tampered header param like {"t": 1e999} parses to float('inf'); int(inf) raises
    # OverflowError during key re-derivation, BEFORE the AAD/tag check. It must fold into a
    # content-free DecryptionError, not escape as an OverflowError whose frame retains
    # passphrase/blob.
    backend = _backend()
    backend.set("myapp", "api_key", value=SECRET)
    path = backend.path("myapp")
    blob = path.read_bytes()
    header_len = int.from_bytes(blob[:_HEADER_LEN_BYTES], "big")
    header = json.loads(blob[_HEADER_LEN_BYTES:_HEADER_LEN_BYTES + header_len])
    rest = blob[_HEADER_LEN_BYTES + header_len:]
    header["t"] = 1e999   # -> float('inf'); int(inf) raises OverflowError
    new_header = json.dumps(header, sort_keys=True).encode("utf-8")
    path.write_bytes(len(new_header).to_bytes(_HEADER_LEN_BYTES, "big") + new_header + rest)
    with pytest.raises(DecryptionError) as excinfo:
        _backend().get("myapp", "api_key")
    err = excinfo.value
    assert SECRET not in str(err)
    assert err.__cause__ is None
    assert err.__context__ is None


def test_unsupported_argon2id_build_fails_closed_content_free(monkeypatch: pytest.MonkeyPatch) -> None:
    # On a cryptography/OpenSSL build without Argon2id, the availability probe must raise a
    # content-free CredentialsError BEFORE any passphrase is revealed -- not let UnsupportedAlgorithm
    # escape with the passphrase in frame, and not misclassify it as DecryptionError (tampering).
    from cryptography.exceptions import UnsupportedAlgorithm

    import credbox.backends.encrypted as enc
    from credbox.errors import CredentialsError, DecryptionError

    class _NoArgon2id:
        def __init__(self, *args: object, **kwargs: object) -> None: ...
        def derive(self, *args: object, **kwargs: object) -> bytes:
            raise UnsupportedAlgorithm("this OpenSSL has no argon2id")

    monkeypatch.setattr(enc, "Argon2id", _NoArgon2id)
    monkeypatch.setattr(enc, "_kdf_available", False)   # force the probe to re-run against the mock
    backend = _backend()
    with pytest.raises(CredentialsError) as excinfo:
        backend.get("myapp", "api_key")
    assert not isinstance(excinfo.value, DecryptionError)   # not misreported as tampering
    assert PASSPHRASE.reveal() not in str(excinfo.value)
    with pytest.raises(CredentialsError):
        backend.set("myapp", "api_key", value=SECRET)


def _secrets_on_traceback(exc: BaseException, *needles: str) -> list[str]:
    """Every ``frame.local`` on ``exc``'s traceback that contains one of ``needles`` (as a str or
    within bytes). Used to prove a content-free error kept no passphrase/plaintext in a frame."""
    found = []
    tb = exc.__traceback__
    while tb is not None:
        for local_name, val in list(tb.tb_frame.f_locals.items()):   # snapshot: locals can mutate
            text = val if isinstance(val, str) else None
            raw = bytes(val) if isinstance(val, (bytes, bytearray)) else None
            for needle in needles:
                if (text is not None and needle in text) or (raw is not None and needle.encode() in raw):
                    found.append(f"{tb.tb_frame.f_code.co_name}.{local_name}")
        tb = tb.tb_next
    return found


def _frame_names(exc: BaseException) -> list[str]:
    """The function name of every frame on ``exc``'s traceback."""
    names = []
    tb = exc.__traceback__
    while tb is not None:
        names.append(tb.tb_frame.f_code.co_name)
        tb = tb.tb_next
    return names


def test_internal_error_at_real_derive_params_fails_closed_content_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The availability probe validates Argon2id at tiny params; a build can still reject the REAL
    # derive params (e.g. no thread support for lanes>1) with InternalError, which _try_decrypt's
    # catch tuple omits. _derive_key must SIGNAL this by return (never raise), so the escaping
    # CredentialsError -- content-free, not DecryptionError (a build failure, not tampering) --
    # carries the passphrase (read) or the plaintext store (write) in NO traceback frame, and has
    # __cause__/__context__ None. Simulated: probe passes (real Argon2id), then derive raises.
    from cryptography.exceptions import InternalError

    import credbox.backends.encrypted as enc
    from credbox.errors import CredentialsError, DecryptionError

    backend = _backend()
    backend.set("myapp", "api_key", value=SECRET)   # a real store, real KDF

    class _FaultyArgon2id:
        def __init__(self, *args: object, **kwargs: object) -> None: ...
        def derive(self, *args: object, **kwargs: object) -> bytes:
            raise InternalError("openssl argon2 internal failure", [])

    monkeypatch.setattr(enc, "Argon2id", _FaultyArgon2id)
    monkeypatch.setattr(enc, "_kdf_available", True)   # skip the probe; exercise the real derive

    # Read path: the passphrase must not survive on any frame of the escaping error.
    with pytest.raises(CredentialsError) as read_exc:
        _backend().get("myapp", "api_key")
    assert not isinstance(read_exc.value, DecryptionError)
    assert PASSPHRASE.reveal() not in str(read_exc.value)
    assert read_exc.value.__cause__ is None and read_exc.value.__context__ is None
    leaked = _secrets_on_traceback(read_exc.value, PASSPHRASE.reveal())
    assert leaked == [], f"passphrase retained on the read-path traceback: {leaked}"

    # Write path: use a FRESH app with no existing store, so _load returns {} without decrypting
    # and the fault fires in _save -> _encrypt -> _derive_key -- the actual write path. (Reusing
    # "myapp" would fault in _load's READ instead, never reaching _encrypt, making the crypto-frame
    # assertion below vacuous.) The passphrase must survive on NO frame, and _encrypt/_derive_key
    # must be off the traceback because they RETURNED the signal. The plaintext VALUE legitimately
    # lives in the set()/_save() frames -- the object-level write contract (file.py _save), not a
    # frame-level claim -- so it is checked only for absence from the error message.
    with pytest.raises(CredentialsError) as write_exc:
        _backend().set("writeapp", "other", value=SECRET)
    assert not isinstance(write_exc.value, DecryptionError)
    assert SECRET not in str(write_exc.value) and PASSPHRASE.reveal() not in str(write_exc.value)
    assert write_exc.value.__cause__ is None and write_exc.value.__context__ is None
    frames = _frame_names(write_exc.value)
    assert "_save" in frames, f"the fault did not reach the write path: {frames}"   # not vacuous
    assert "_encrypt" not in frames and "_derive_key" not in frames, (
        f"a secret-bearing crypto frame is on the write-path traceback: {frames}"
    )
    leaked = _secrets_on_traceback(write_exc.value, PASSPHRASE.reveal())
    assert leaked == [], f"passphrase retained on the write-path traceback: {leaked}"


def test_newer_version_blob_reports_upgrade_not_tampering() -> None:
    # A well-formed argon2id header with a version this build does not understand (a future v2)
    # must report "upgrade credbox" (CredentialsError), not misdiagnose as wrong-passphrase/
    # tampering (DecryptionError). The version check is before the tag check, so bumping v in an
    # otherwise-valid header exercises it.
    from credbox.errors import CredentialsError

    backend = _backend()
    backend.set("myapp", "api_key", value=SECRET)
    path = backend.path("myapp")
    blob = path.read_bytes()
    header_len = int.from_bytes(blob[:_HEADER_LEN_BYTES], "big")
    header = json.loads(blob[_HEADER_LEN_BYTES:_HEADER_LEN_BYTES + header_len])
    rest = blob[_HEADER_LEN_BYTES + header_len:]
    header["v"] = 2
    new_header = json.dumps(header, sort_keys=True).encode("utf-8")
    path.write_bytes(len(new_header).to_bytes(_HEADER_LEN_BYTES, "big") + new_header + rest)
    with pytest.raises(CredentialsError) as excinfo:
        _backend().get("myapp", "api_key")
    assert not isinstance(excinfo.value, DecryptionError)
    assert "upgrade" in str(excinfo.value).lower()


def test_blob_relocated_from_another_app_fails_closed() -> None:
    # The header binds the app (as AAD). A blob moved from another same-passphrase store decrypts
    # against its own header but its bound app will not match the store it now sits in, so it is
    # rejected rather than silently serving the other app's secrets.
    _backend().set("appA", "api_key", value=SECRET)
    # The blob is genuinely valid in its OWN store -- so the rejection below is proven to be the
    # app-binding, not a broken blob.
    assert _backend().get("appA", "api_key").reveal() == SECRET   # type: ignore[union-attr]
    stolen = EncryptedFileBackend(passphrase=PASSPHRASE).path("appA").read_bytes()
    victim_path = EncryptedFileBackend(passphrase=PASSPHRASE).path("appB")
    victim_path.parent.mkdir(parents=True, exist_ok=True)
    victim_path.write_bytes(stolen)
    with pytest.raises(DecryptionError):
        _backend().get("appB", "api_key")   # same passphrase, decrypts, but bound app != appB


def test_malformed_decrypted_store_leaves_no_plaintext_on_the_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A store that decrypts authentically but is not valid store JSON raises a content-free
    # CredentialsError. Its traceback must not retain the decrypted plaintext in a frame local
    # (the `del outcome` guard) -- otherwise a stored/logged exception keeps every secret alive.
    import credbox.backends.encrypted as enc
    from credbox._store_codec import StoreFault, StoreFaultKind
    from credbox.errors import CredentialsError

    _backend().set("myapp", "api_key", value=SECRET)
    monkeypatch.setattr(enc, "parse_store", lambda _b: StoreFault(StoreFaultKind.NOT_OBJECT))
    with pytest.raises(CredentialsError) as excinfo:
        _backend().get("myapp", "api_key")
    assert excinfo.value.__cause__ is None and excinfo.value.__context__ is None
    leaked = []
    tb = excinfo.value.__traceback__
    while tb is not None:
        for local_name, val in list(tb.tb_frame.f_locals.items()):   # snapshot: locals can mutate
            if isinstance(val, (bytes, bytearray)) and SECRET.encode() in bytes(val):
                leaked.append(f"{tb.tb_frame.f_code.co_name}.{local_name}")
            elif isinstance(val, str) and SECRET in val:
                leaked.append(f"{tb.tb_frame.f_code.co_name}.{local_name}")
        tb = tb.tb_next
    assert leaked == [], f"decrypted plaintext retained on the traceback: {leaked}"


def test_load_warns_on_a_group_readable_encrypted_store(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The file is ciphertext, but a group/world-readable .enc still invites an offline passphrase
    # attack, so _load nudges the owner to tighten it -- as the file backend does for its plaintext
    # store. The warning names only the path (no secret).
    import os
    import stat

    if os.name != "posix":
        pytest.skip("POSIX mode bits only")
    from credbox import permissions

    monkeypatch.setattr(permissions, "_warned_permissive_paths", set())
    backend = _backend()
    backend.set("myapp", "api_key", value=SECRET)
    path = backend.path("myapp")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)   # 0640: group-readable
    capsys.readouterr()
    backend.get("myapp", "api_key")
    err = capsys.readouterr().err
    assert "chmod 600" in err
    assert SECRET not in err   # the nudge names the path, never the secret


def test_each_encryption_uses_a_fresh_nonce() -> None:
    backend = _backend()
    backend.set("myapp", "k", value="v1")
    nonce1 = _nonce_of(backend.path("myapp").read_bytes())
    backend.set("myapp", "k", value="v2")
    nonce2 = _nonce_of(backend.path("myapp").read_bytes())
    assert nonce1 != nonce2


def test_constructor_has_no_fallback_parameter() -> None:
    params = inspect.signature(EncryptedFileBackend.__init__).parameters
    assert "passphrase" in params
    assert "fallback" not in params   # encrypted is terminal; the chain is unrepresentable


def _nonce_of(blob: bytes) -> bytes:
    header_len = int.from_bytes(blob[:_HEADER_LEN_BYTES], "big")
    start = _HEADER_LEN_BYTES + header_len
    return blob[start:start + _NONCE_LEN]
