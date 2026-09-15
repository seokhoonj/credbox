"""The ``git-credential-credbox`` adapter: speak git's credential protocol over stdin/stdout,
backed by a credbox store.

git invokes ``git-credential-credbox <get|store|erase>`` and writes ``key=value`` lines to stdin,
terminated by a blank line. The mapping is: the git ``host`` is the credbox ``app``, the git
``username`` is the credbox secret ``name``, and the password is the secret value.

The helper uses the plaintext file store (``default_backend()``); it does not consult the OS
keyring, so a credential stored with ``credbox set --keyring`` is not served here.

Two scope notes: the store is keyed by host only, so on a ``get`` for a plaintext ``http://``
request the helper serves nothing (it cannot distinguish an http-stored from an https-stored
value, and handing one to git over cleartext would be a downgrade). A host git sends with a port
(``example.com:8443``) or as an IPv6 literal is encoded to a valid store segment, consistently
across get/store/erase.

Leak-surface discipline: on ``get`` the only thing written to stdout is the credential
reply (``username=...\npassword=...``); on any error nothing is written to stdout (git treats an
empty reply as "no credential") and a content-free note goes to stderr -- never the secret, never
a traceback.
"""

from __future__ import annotations

import hashlib
import re
import sys
from collections.abc import Sequence
from typing import TextIO

from credbox.backends import default_backend
from credbox.credentials import Credentials
from credbox.errors import InvalidAppNameError
from credbox.paths import app_dir_segment

# git transports that use a TLS channel; a credential is served only for these (see _do_get).
_TLS_PROTOCOLS = frozenset({"https", "ftps"})


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``git-credential-credbox`` console script. Always returns 0 -- git
    reads the credential (if any) from stdout; an error is a content-free stderr note and an empty
    stdout, which git reads as "no credential"."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    operation = arguments[0] if arguments else ""
    try:
        # _read_fields is inside the try: git feeds `password=<secret>` on stdin, so the parsed
        # fields hold the secret. Any failure reading or handling them must be caught here and
        # not escape as a traceback whose frame-locals (`fields`) would expose the password under
        # a locals-dumping excepthook.
        fields = _read_fields(sys.stdin)
        if operation == "get":
            _do_get(fields)
        elif operation == "store":
            _do_store(fields)
        elif operation == "erase":
            _do_erase(fields)
        # any other operation: git ignores unknown helpers' output -- do nothing.
    except InvalidAppNameError:
        return 0   # the host does not map to a valid store name -> no credential, quietly
    except BaseException:
        # Catch BaseException, not just Exception: a KeyboardInterrupt/SystemExit while reading
        # stdin or handling the request would otherwise escape as a traceback, and `fields` holds
        # the password on a `store`. Every failure is content-free here: nothing on stdout (git
        # prompts), a generic note on stderr, never a secret and never a traceback.
        print("credbox: git-credential error", file=sys.stderr)
    return 0


def _do_get(fields: dict[str, str]) -> None:
    # Serve only over a TLS transport (a safelist, not an http denylist). credbox scopes a store by
    # host only (not by protocol), so it cannot tell an http-stored value from an https-stored one;
    # handing either to git over a cleartext transport (http, ftp) risks a downgrade -- a secret
    # saved for https:// leaking onto the wire (a crafted submodule URL or a redirect is enough).
    # git always sends `protocol` on a real get, so a missing or non-TLS protocol is refused (git
    # then prompts). Refusing an unknown/absent scheme fails safe; ssh/git:// never use a
    # username/password helper, so this cannot break them.
    if fields.get("protocol") not in _TLS_PROTOCOLS:
        return
    app = _derive_app_from_fields(fields)
    if app is None:
        return
    # Read the STORE ONLY (host-scoped) -- NOT Credentials.secret(), whose environment tier is
    # global and host-unscoped: git supplies the username, so a crafted URL
    # `https://SOME_ENV_VAR@evil.com/` would otherwise resolve `SOME_ENV_VAR` from os.environ and
    # hand that value to git as the password *for evil.com* -- a remote exfiltration of any env var.
    # A credential this helper serves must come from a store keyed to the requesting host.
    backend = default_backend()
    username = fields.get("username")
    if username:
        value = backend.get(app, username)
        if value is not None:
            _write_reply(sys.stdout, username=username, password=value.reveal())
        return
    # First contact without a username: use the sole stored name if exactly one exists. The helper
    # reads the file store only (default_backend()), so a name stored via `credbox set --keyring`
    # is not visible here and this yields nothing (a defined empty reply -> git prompts).
    names = backend.names(app)
    if len(names) == 1:
        value = backend.get(app, names[0])
        if value is not None:
            _write_reply(sys.stdout, username=names[0], password=value.reveal())


def _do_store(fields: dict[str, str]) -> None:
    app = _derive_app_from_fields(fields)
    username = fields.get("username")
    password = fields.get("password", "")
    if app is None or not username or not password.strip():
        return
    Credentials(app).set(username, value=password)


def _do_erase(fields: dict[str, str]) -> None:
    app = _derive_app_from_fields(fields)
    username = fields.get("username")
    if app is None or not username:
        return
    Credentials(app).unset(username)


def _derive_app_from_fields(fields: dict[str, str]) -> str | None:
    """The credbox app for this request, derived from the git ``host``. Returns ``None`` when
    there is no host (so ``get`` yields no credential rather than erroring). A host git sends with
    a port (``example.com:8443``) or as an IPv6 literal (``[::1]``) is not a valid store segment on
    its own, so it is encoded to one -- see ``_host_to_segment``."""
    host = fields.get("host")
    if not host:
        return None
    return _host_to_segment(host)


def _host_to_segment(host: str) -> str | None:
    """Map a git ``host`` (which per the protocol may include a port, and may be an IPv6 literal)
    to a valid store segment. A host that is already a valid segment is used verbatim, so existing
    stores and ``credbox set <host> ...`` keep working; anything else (a port's ``:``, IPv6
    ``[]``/``:``) is sanitized and suffixed with a short hash of the raw host, so two distinct hosts
    can never collide onto one store (which would cross-serve credentials)."""
    try:
        return app_dir_segment(host)
    except InvalidAppNameError:
        pass
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "-", host).strip("-._")
    digest = hashlib.sha256(host.encode("utf-8")).hexdigest()[:12]
    candidate = f"{sanitized}-{digest}" if sanitized else f"host-{digest}"
    try:
        return app_dir_segment(candidate)
    except InvalidAppNameError:
        # The sanitized candidate can still start with a reserved device label -- host
        # ``aux.example.com`` -> ``aux.example.com-<hash>``, still matched by the con/aux/... rule
        # (its ``.*`` tail). Fall back to a hash-only segment, which always validates and is
        # collision-free (distinct hosts -> distinct digests).
        return app_dir_segment(f"host-{digest}")


def _read_fields(stream: TextIO) -> dict[str, str]:
    """Parse the git credential ``key=value`` lines from ``stream`` until a blank line or EOF."""
    fields: dict[str, str] = {}
    for raw_line in stream:
        line = raw_line.rstrip("\r\n")   # tolerate CRLF, though git's protocol is LF-terminated
        if line == "":
            break
        key, sep, value = line.partition("=")
        if sep:
            fields[key] = value
    return fields


def _write_reply(stream: TextIO, *, username: str, password: str) -> None:
    """Write the git credential reply (the one deliberate raw-secret-to-stdout path) and nothing
    else. git's line protocol forbids a newline or NUL in a value; if a stored username/password
    contains one (only possible via a crafted value written through the Python API -- git's own
    line-based input cannot carry it), writing it verbatim would inject an extra reply line. Refuse
    to reply in that case: write nothing (git then prompts) rather than emit a malformed reply."""
    if any(c in username or c in password for c in ("\n", "\r", "\x00")):
        return
    stream.write(f"username={username}\n")
    stream.write(f"password={password}\n")
    stream.write("\n")
    stream.flush()


if __name__ == "__main__":
    raise SystemExit(main())
