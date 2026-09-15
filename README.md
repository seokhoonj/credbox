# credbox

[![check](https://github.com/seokhoonj/credbox/actions/workflows/check.yml/badge.svg)](https://github.com/seokhoonj/credbox/actions/workflows/check.yml)
[![PyPI](https://img.shields.io/pypi/v/credbox)](https://pypi.org/project/credbox/)
[![Python](https://img.shields.io/pypi/pyversions/credbox)](https://pypi.org/project/credbox/)
[![License](https://img.shields.io/pypi/l/credbox)](https://github.com/seokhoonj/credbox/blob/main/LICENSE)

**English** | [한국어](README.ko.md)

A secure **secret store** for Python apps and CLIs — XDG paths by default, OS-native (Linux/macOS/Windows) on request — leak-safe by construction.

Every command-line app has to resolve its secrets and find where its files live. credbox does
both, once, the same way on every OS — and treats *not leaking the secret* as the whole job:

- **Leak-safe.** A resolved secret comes back as a `Secret` that masks itself in a log or a
  traceback; you call `.reveal()` to get the raw value only at the point of use. A malformed
  store, a failing OS keyring, or a wrong encryption passphrase raises a **content-free** error —
  the value never rides along on the exception, its `__cause__`/`__context__` chain, or a
  traceback. The CLI and the git helper write a raw secret to stdout only on an explicit reveal.
- **Honest by default.** Storage is a plain `credentials.json` at mode 0600 in a 0700 directory —
  reliable headless and across machines. The OS keyring and an encrypted-file backend are
  **opt-in** upgrades; a missing keyring is an explicit, warned fallback, never a silent downgrade.
- **Zero-dep core.** The default file store pulls in nothing. `keyring` and `cryptography` are
  installed only if you ask for them, and the core's import graph can never reach them.
- **Shares and consolidates.** One key can be shared across apps, or several components' secrets
  consolidated into one file — see the shared store and namespaces in §3.

credbox stores secrets safely — atomic writes, correct permissions, cross-process locking, XDG
paths, and leak-scrubbing wired together as one tested unit. It is not a novel vault: it assembles
standard, well-understood techniques rather than inventing new cryptography. Directories follow the
[XDG Base Directory Specification](https://specifications.freedesktop.org/basedir/latest/).

## 1. Install

```sh
pip install credbox              # file store, zero runtime dependencies
pip install "credbox[keyring]"   # add the optional OS keyring backend
pip install "credbox[crypto]"    # add the optional encrypted-file backend (Argon2id + AES-GCM)
pip install "credbox[all]"       # both
```

Check it worked:

```sh
credbox --version
```

Requires Python 3.11+.

## 2. Quickstart

Store a secret once (prompted, without echo):

```sh
credbox set myapp API_KEY
```

Then read it back in code. `require` resolves it (`$API_KEY`, else `myapp`'s store) and raises if
it is set nowhere; the result is a `Secret`, so it will not land in a log by accident:

```python
from credbox import Credentials

secret = Credentials("myapp").require("API_KEY")   # a Secret, not a str
secret.reveal()                                    # the raw value, at the point of use
print(secret)                                      # 'API_...cdef' — masked, safe to log
```

## 3. Secrets

Secrets (passwords, tokens, API keys) live in **one `credentials.json` per app** —
`config_dir(app)/credentials.json`, e.g. `~/.config/myapp/credentials.json` for `myapp`. That one
file is the app's **store**. Which store is read is decided by the app name, so one app can name
another app's store and read it alongside its own (see **shared store** below).

```python
from credbox import Credentials, Secret

# Resolution order: override > environment > shared stores > this app's store
creds = Credentials("myapp", shared=["auth"])
key   = creds.require("API_KEY")          # env $API_KEY, then auth's store, then myapp's; raises if unset
maybe = creds.secret("API_KEY")           # same, but returns None instead of raising
creds.set("API_KEY", value="sk-...")      # writes myapp's own store (str or Secret; keyword-only)
creds.unset("API_KEY")                    # removes it from myapp's store (no-op if absent)
creds.names()                             # ["API_KEY", ...] — names only, never values

key.reveal()                              # -> "sk-..."  the raw string, for passing to an HTTP client
```

`secret` and `require` return a `Secret`; call `.reveal()` for the raw string. A `Secret` renders
masked in `str`/`repr`, compares in constant time, and is unhashable, so it cannot slip into a log
line or become a dict key by accident. `set` accepts a `str` or a `Secret`, refuses a blank value,
and strips surrounding whitespace so a stored key matches what resolution returns.

Two `Secret` footguns to know: using one where a string is expected — an f-string, a header value
(`f"Bearer {secret}"`) — inserts the **mask**, not the key, and raises no error, so always
`.reveal()` at the boundary; and `secret == "some-string"` is always `False` (equality compares
only two `Secret`s), so compare with `secret.reveal() == other` or wrap the other side in `Secret`.

The **shared store** is how a key common to several apps stops being duplicated: store it once
under a shared app (say `"auth"`), and every consumer resolves it with `shared=["auth"]`. A key
specific to one app stays in that app's own store.

A **namespace** goes the other way: it lets one app's store hold several components' secrets in
separate sections of the *same* file, without their key names colliding. Treat one app as the
container and give each component its own namespace inside it — the components need no app or file
of their own.
`Credentials(app, namespace="chat")` reads and writes only the `chat` section;
`namespace=None` (the default) is the original flat store, unchanged.

**Several components, one file.** Put every component's key under its own namespace of one host
app — from the CLI (`--namespace`, or `-n`) or from code:

```sh
credbox set yourapp GEMINI_API_KEY -n chat  # prompts without echo
credbox set yourapp SMTP_PASSWORD  -n mailer
credbox list yourapp -n chat                # inspect one section
```

```python
from credbox import Credentials
key = Credentials("yourapp", namespace="chat").require("GEMINI_API_KEY")   # read it back
```

Everything lands in one file, `~/.config/yourapp/credentials.json`:

```json
{ "chat": {"GEMINI_API_KEY": "…"}, "mailer": {"SMTP_PASSWORD": "…"} }
```

An app's credentials **file** is wholly flat or wholly namespaced: once it holds namespaces, a flat
access (no namespace) raises rather than corrupting, and the reverse too — so give a namespaced
store a fresh app name, or migrate an existing flat one (below). The namespace scopes only the
shared and app store tiers; the environment and override tiers resolve by name alone (the same
`name` reads the same env var whatever the namespace). Select a namespace on the CLI with
`--namespace/-n` or the `CREDBOX_NAMESPACE` environment variable; the git credential helper is
flat-only.

**Migrating a flat store to namespaces.** Flat and namespaced cannot coexist in one file, so empty
it in between: read each flat key (`credbox get app K --reveal`), remove them all
(`credbox unset app K` — the store is empty once the last is gone), then re-store each under a
namespace (`credbox set app K -n ns`).

Two caveats when several components share one store. The environment tier ignores the namespace, so
two components that both self-resolve the *same* generic name (`API_KEY`) from `$API_KEY` get the
same value — give each a distinct env name (as in the example, `GEMINI_API_KEY` and `SMTP_PASSWORD`)
so they stay separate. And a consolidated store
written from **multiple machines** over a synced folder (Dropbox, NFS) can lose one namespace's
update to a sync conflict, because the cross-process lock does not span machines — write a shared
store from a single machine, or keep components in separate stores.

## 4. The `credbox` command

Manage any app's secrets from one place, in one format:

```sh
credbox set myapp API_KEY               # prompts without echo; writes credentials.json (0600)
credbox set myapp API_KEY --value sk-…  # or pass it directly (exposes it in argv; prefer the prompt)
credbox list myapp                      # names only, never values
credbox get myapp API_KEY               # masked (API_...cdef); reads the stored value only
credbox get myapp API_KEY --reveal      # print in full (the only raw-secret-to-stdout path)
credbox get myapp API_KEY --resolve     # also consult the environment variable, not just the store
credbox unset myapp API_KEY
credbox set yourapp API_KEY -n chat     # -n/--namespace: operate within one section of the store
credbox path myapp                      # print the credentials.json path
credbox dirs myapp                      # print all five directories
credbox doctor                          # check every app's credentials file/dir permissions
```

`set` prompts (no echo) on a terminal; in a script or CI, pipe the value on stdin
(`printf %s "$TOKEN" | credbox set myapp API_KEY`) — the argv-safe path, since unlike `--value`
the secret never appears in the process argument list. `set`, `get`, `list`, and `unset` accept
`--namespace/-n` (or the `CREDBOX_NAMESPACE` environment variable, which the flag overrides) to
operate within one section of a namespaced store — see [§3](#3-secrets) for the "several
components, one file" recipe — and `--keyring` to use the OS keyring backend (requires
`credbox[keyring]`; the file store is used when the keyring is unavailable at runtime). The CLI
never prints a traceback: a runtime error becomes a one-line, content-free message on stderr. Exit
codes: `0` success, `1` a command failure (`doctor` finding a file/dir readable beyond its owner),
`2` a usage error.

## 5. Backends

Where a secret is physically stored is a `SecretBackend`. `Credentials` uses a `FileBackend` by
default; select another by passing `backend=`:

```python
from credbox import Credentials, Secret
from credbox import default_backend, file_backend, keyring_backend, encrypted_backend

Credentials("myapp")                                                    # file store (default)
Credentials("myapp", backend=default_backend(use_keyring=True))         # keyring over file
Credentials("myapp", backend=keyring_backend(fallback=file_backend()))  # the same, explicit
Credentials("myapp", backend=encrypted_backend(passphrase=Secret("…"))) # encrypted file [crypto]
```

- **File store** (default, zero-dep) — a `credentials.json` in the app's folder. Works reliably
  everywhere; stores the value in plaintext at mode `0600` (owner read/write only — a Linux/macOS
  file permission; see the Windows note in §7).
- **OS keyring** (`[keyring]`) — the OS-provided vault (macOS Keychain, GNOME Keyring, …). When
  reachable it is authoritative, and a successful `set`/`unset` also clears any stale plaintext
  copy from the fallback file. When *absent* (no backend on a server, cron, a container), every
  operation falls back to the file store with a one-time, content-free warning — so a user who
  turned the keyring on learns the value went to the file, never a silent downgrade. A *present but
  failing* keyring (locked, a transient error) **fails closed**: every operation raises rather than
  silently write plaintext or serve a stale value — the file fallback is reached only when no
  keyring backend exists *at all*. (One caveat: reconciliation runs only keyring → file; a value
  written to the file while the keyring was structurally absent is not migrated back, so re-set the
  key while the keyring is reachable.)
- **Encrypted file** (`[crypto]`) — a single AES-GCM blob keyed by an Argon2id hash of a passphrase.
  It is **terminal**: a wrong passphrase or a tampered file fails closed with a content-free
  `DecryptionError`, never a plaintext downgrade. The whole header is authenticated (AES-GCM AAD —
  additional data that is not encrypted but is covered by the tamper check, so an edited header
  fails to decrypt), a fresh nonce (a number used once per encryption) is drawn per write, and the
  deliberately expensive KDF (key-derivation function, here Argon2id) adds ~100 ms-scale latency
  per store open — a feature, not a bug. There is **no recovery path**: lose the passphrase and the
  store cannot be decrypted by anyone, so back the passphrase up independently.

The factories gate the optional import: `keyring_backend()` / `encrypted_backend()` raise a
`MissingExtraError` (with a `pip install credbox[…]` hint) when the extra is not installed.

The `credbox` CLI manages the file and keyring stores only; **populate an encrypted store from
code** with the same `Credentials`:

```python
from getpass import getpass
from credbox import Credentials, Secret, encrypted_backend

creds = Credentials("myapp", backend=encrypted_backend(passphrase=Secret(getpass("passphrase: "))))
creds.set("API_KEY", value="sk-...")     # writes credentials.enc (encrypted)
creds.require("API_KEY")                 # read it back with the same passphrase
```

## 6. Git credential helper

credbox can serve credentials to git. Point git at the installed helper:

```sh
git config --global credential.helper credbox
```

git then calls `git-credential-credbox` for `get`/`store`/`erase`, mapping the git `host` to a
credbox app and the git `username` to the secret name. On `get` the helper writes only the
credential reply to stdout; on any error it writes nothing (git prompts) and a content-free note to
stderr — never the secret, never a traceback.

The store is keyed by host only (not the protocol), so the helper serves nothing for a plaintext
`http://` request (it cannot tell an http-stored value from an https-stored one, and handing
either to git over cleartext would be a downgrade). A host with a port (`example.com:8443`) or an IPv6 literal is
handled. The helper reads the file store, not the OS keyring.

## 7. Directories

```python
from credbox import config_dir, data_dir, state_dir, cache_dir, runtime_dir

config_dir("myapp")   # ~/.config/myapp        (or $XDG_CONFIG_HOME/...)
data_dir("myapp")     # ~/.local/share/myapp   (or $XDG_DATA_HOME/...)
state_dir("myapp")    # ~/.local/state/myapp   (or $XDG_STATE_HOME/...)
cache_dir("myapp")    # ~/.cache/myapp         (or $XDG_CACHE_HOME/...)
runtime_dir("myapp")  # $XDG_RUNTIME_DIR/myapp, else a secured 0700 temp dir
```

The app name is validated as a single path segment, so a crafted name can never escape its base.
`data_dir` and `state_dir` honour a per-app `<PREFIX>_DATA_DIR` / `<PREFIX>_STATE_DIR` override (an
absolute path used as-is), where `<PREFIX>` is `env_var_prefix(app)`. By default paths use the XDG
`~/.config` layout on every OS; pass `layout="native"` for OS-native locations (Linux `~/.config`,
macOS `~/Library/Application Support`, Windows `%LOCALAPPDATA%`), or set `CREDBOX_LAYOUT`. The
layout selects **where the store lives**, so switching it points at a different location — it is
not a migration; move an existing store yourself (e.g. with `relocate_once`) if you change it.

**Windows note:** `0600` and `0700` are POSIX (Linux/macOS) permission settings — credbox writes
the secret **file** as `0600` (only its owner may read and write it) and the **folder** that holds
it as `0700` (only its owner may access it), so no other user on the machine can reach the secret.
Windows has no such Unix permission bits; it controls access with **ACLs** (Access Control Lists —
a per-account/-group list of allow/deny entries) instead. credbox cannot set `0600`/`0700` on
Windows, so it keeps secrets under your per-user `%LOCALAPPDATA%` folder: Windows creates that
folder with an ACL that grants access to your account only, and files created inside inherit it, so
they are private to your account automatically. credbox therefore does not claim the `0600`/`0700`
guarantee it cannot set there — it relies on the ACL protection the OS already provides.

## 8. Redacting secrets from logs

An API often echoes your key back inside an error message or a request URL, so logging an
unscrubbed exception can leak the very secret it failed with. These helpers replace known secret
values — and their URL-encoded forms — with `***` before anything is logged:

```python
from credbox import scrub_secrets, scrub_exception

scrub_secrets("failed with sk-abc123", [key])   # "failed with ***"
raise scrub_exception(err, [key])               # scrubs the whole __cause__/__context__ chain
```

Both helpers take the secret values to redact as either raw `str`s or `Secret`s — here `key` is a
`Secret` and is redacted as shown. `scrub_exception` never raises and rewrites each exception's
`args`, its transport URLs (`url`, `request.url`, `response.url`), and its PEP 678 `__notes__`. For
an exception with a custom `__str__`, also pass the rendered log line through `scrub_secrets`.

## 9. Single-instance locking

Stop a job from overlapping with another copy of itself — two cron runs, or a cron run and a manual
one — which redo work, produce duplicates, and race on shared state:

```python
from credbox import single_instance, FileLock

with single_instance("myapp", name="poll") as acquired:
    if not acquired:
        return   # another run holds the lock; skip rather than pile on
    ...
```

The lock lives in `runtime_dir` and is released by the OS when the process exits, even on a crash.
On a filesystem that cannot lock (some NFS mounts, which report `ENOLCK`), the guard falls open —
the job runs without cross-process protection and warns once, rather than skipping forever.

## 10. Public API reference

### Everyday API (`credbox`)

| Import | What it is |
|--------|------------|
| `Credentials(app, *, namespace=None, shared=(), backend=None)` | The four-tier secret resolver: `.secret` / `.require` / `.set` / `.unset` / `.names`. `namespace` scopes the store to a component's section within one app's store. |
| `Secret` / `mask_secret` | The leak-safe value type (`.reveal()` for the raw string) and its canonical mask. |
| `config_dir` / `data_dir` / `state_dir` / `cache_dir` / `runtime_dir` | XDG directories for an app. |
| `default_backend` / `file_backend` / `keyring_backend` / `encrypted_backend` | Backend chooser and factories. |
| `SecretBackend` / `FileBackend` | The backend protocol and the zero-dep file backend. |
| `scrub_secrets` / `scrub_exception` | Redact secret values from text and exception chains. |
| `single_instance` / `FileLock` | Single-instance advisory locking in `runtime_dir`. |
| `CredBoxError` / `CredentialsError` / `NoKeyringError` / `InsecureStorageError` / `InvalidAppNameError` / `InvalidLayoutError` / `BlankSecretError` / `LockHeldError` / `DecryptionError` / `MissingExtraError` | The exception hierarchy. |
| `__version__` | The installed package version string. |

### Building blocks (for library authors)

| Import | What it is |
|--------|------------|
| `ensure_dir` / `ensure_private_dir` / `restrict_dir_to_owner` / `warn_if_group_or_world_readable` / `warn_if_group_or_world_accessible` | Directory/file permission guarantees and checks (the last two warn when a credentials file or its directory is reachable beyond its owner). |
| `write_bytes_atomic` / `write_text_atomic` | Atomic 0600 writes. |
| `read_json` / `relocate_once` | Corruption-aware non-secret state read; idempotent, fail-closed relocation. |
| `env_var_prefix` / `colliding_env_var_prefixes` / `read_absolute_path_override` | Turn an app name into an env-var prefix and detect prefix collisions; read an absolute-path override. |
| `app_dir_segment` / `Layout` / `default_layout` / `set_default_layout` | Validate an app name; select the path layout. |

## 11. For library authors

credbox provides only the base layer — directories, secret resolution, permissions, atomic writes,
locking, masking. Your package keeps its own domain configuration (accounts, routes, topics) and
reaches under it for just the storage location and the secrets:

```python
from credbox import Credentials, config_dir

settings = config_dir("myapp") / "settings.toml"     # your own config file — you manage it
token    = Credentials("myapp").secret("API_TOKEN")  # credbox owns only the location and the secret
```

## 12. License

[MIT](LICENSE)
