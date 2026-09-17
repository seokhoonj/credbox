"""The ``credbox`` command: manage any app's stored secrets and inspect its directories.

``credbox set <app> <name>`` writes the same ``credentials.json`` (mode 0600) every consumer
reads; the value is prompted for without echo when omitted, so it never lands in shell history.
``get`` masks by default (``--reveal`` prints it in full), ``list`` shows names only, and
``doctor`` reports files readable beyond their owner. ``set``/``get``/``list``/``unset`` take
``--namespace/-n`` (or the ``CREDBOX_NAMESPACE`` env var) to operate within one section of a
namespaced store, so several components can share one app's store.

Leak-surface discipline (the only raw secret ever written to stdout is a ``get --reveal``):
everything else -- stderr, the ``set`` prompt, a masked ``get``, every error -- is content-free,
and the CLI never prints a traceback.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from credbox import __version__
from credbox.backends import FileBackend, default_backend
from credbox.backends._store import CREDENTIALS_FILE, ENCRYPTED_FILE
from credbox.credentials import Credentials
from credbox.errors import (
    CredBoxError,
    InvalidAppNameError,
    InvalidMigrationError,
    MissingExtraError,
)
from credbox.paths import (
    _valid_segment,
    app_dir_segment,
    cache_dir,
    config_dir,
    data_dir,
    state_dir,
)
from credbox.permissions import (
    warn_if_group_or_world_accessible,
    warn_if_group_or_world_readable,
)
from credbox.runtime import runtime_dir
from credbox.secret import mask_secret


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``credbox`` console script. Returns a process exit code: 0 on success,
    1 on a ``CredBoxError`` (reported as a one-line, content-free message -- never a traceback),
    2 on a usage error. ``MissingExtraError`` prints an actionable ``pip install`` hint."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        exit_code: int = args.run(args)
        return exit_code
    except InvalidAppNameError as err:
        print(f"credbox: error: {err}", file=sys.stderr)   # a bad app name is a usage mistake
        return 2
    except MissingExtraError as err:
        print(
            f"credbox: error: {err.extra} support is not installed; "
            f"run 'pip install {err.dist}'",
            file=sys.stderr,
        )
        return 1
    except CredBoxError as err:
        # Our errors are built content-free (path/name/kind only), so this never prints a secret.
        print(f"credbox: error: {err}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        # Ctrl-C at the no-echo `set` prompt: a clean content-free exit, not a traceback.
        print("credbox: aborted", file=sys.stderr)
        return 130
    except Exception:
        # Terminal guard: an unexpected exception must not reach the interpreter's excepthook,
        # whose frame-locals dump (under rich/cgitb/pytest) could expose a prompted `value`.
        # Content-free -- the specific catches above already handle every error we describe.
        print("credbox: error: unexpected internal error", file=sys.stderr)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="credbox", description=__doc__)
    parser.add_argument(
        "--version",
        action="version",
        version=f"credbox {__version__}",
        help="print the installed version and exit",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_set = sub.add_parser("set", help="store a secret (prompted without echo if omitted)")
    p_set.add_argument("app")
    p_set.add_argument("name")
    p_set.add_argument(
        "--value",
        help="the secret value; omit to be prompted without echo. Passing it here exposes the "
        "secret in the process argument list (/proc, shell history) -- prefer the prompt",
    )
    _add_namespace_flag(p_set)
    _add_keyring_flag(p_set)
    p_set.set_defaults(run=_cmd_set)

    p_get = sub.add_parser("get", help="print a stored secret (masked unless --reveal)")
    p_get.add_argument("app")
    p_get.add_argument("name")
    p_get.add_argument("--reveal", action="store_true", help="print the value in full")
    p_get.add_argument(
        "--resolve",
        action="store_true",
        help="also consult the environment variable, not just the stored value",
    )
    _add_namespace_flag(p_get)
    _add_keyring_flag(p_get)
    p_get.set_defaults(run=_cmd_get)

    p_list = sub.add_parser("list", help="list stored secret names (never values)")
    p_list.add_argument("app")
    _add_namespace_flag(p_list)
    _add_keyring_flag(p_list)
    p_list.set_defaults(run=_cmd_list)

    p_unset = sub.add_parser("unset", help="remove a stored secret")
    p_unset.add_argument("app")
    p_unset.add_argument("name")
    _add_namespace_flag(p_unset)
    _add_keyring_flag(p_unset)
    p_unset.set_defaults(run=_cmd_unset)

    p_path = sub.add_parser("path", help="print the credentials file path for an app")
    p_path.add_argument("app")
    p_path.set_defaults(run=_cmd_path)

    p_dirs = sub.add_parser("dirs", help="print the XDG directories for an app")
    p_dirs.add_argument("app")
    p_dirs.set_defaults(run=_cmd_dirs)

    p_doctor = sub.add_parser(
        "doctor",
        help="check credentials file permissions (exit 1 if any file/dir is readable beyond its owner)",
    )
    p_doctor.add_argument("app", nargs="*", help="apps to check; default: all under the config dir")
    p_doctor.set_defaults(run=_cmd_doctor)

    p_migrate = sub.add_parser(
        "migrate",
        help="copy an app's stored secrets to another app/namespace binding (--remove-source to move; "
        "a flat->namespace migration within the same app always moves)",
    )
    p_migrate.add_argument("--from-app", dest="from_app", required=True, help="the source app")
    p_migrate.add_argument(
        "--from-namespace", dest="from_namespace", default=None,
        help="source namespace (default: the flat store)")
    p_migrate.add_argument("--to-app", dest="to_app", required=True, help="the destination app")
    p_migrate.add_argument(
        "--to-namespace", dest="to_namespace", default=None,
        help="destination namespace (default: the flat store)")
    p_migrate.add_argument(
        "--remove-source", action="store_true",
        help="delete the secrets from the source store after copying them")
    _add_keyring_flag(p_migrate)
    p_migrate.set_defaults(run=_cmd_migrate)

    return parser


def _add_keyring_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--keyring",
        action="store_true",
        help="use the OS keyring backend (requires credbox[keyring]; falls back to the file "
        "store when the keyring is unavailable at runtime)",
    )


def _add_namespace_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--namespace",
        "-n",
        default=os.environ.get("CREDBOX_NAMESPACE") or None,
        help="operate within a namespace -- a named section of the app's store, so several "
        "components can share one store without their key names colliding. Defaults to the "
        "CREDBOX_NAMESPACE environment variable; omit both for the flat store.",
    )


def _target(args: argparse.Namespace) -> str:
    """The app, or ``app/namespace`` when a namespace is in play -- for the success/absent
    messages, so a namespaced operation reads unambiguously."""
    return args.app if args.namespace is None else f"{args.app}/{args.namespace}"


def _credentials(args: argparse.Namespace) -> Credentials:
    return Credentials(
        args.app, namespace=args.namespace, backend=default_backend(use_keyring=args.keyring)
    )


def _cmd_set(args: argparse.Namespace) -> int:
    if args.value is not None:
        value = args.value
    elif sys.stdin.isatty():
        value = getpass.getpass(f"{args.name}: ")   # interactive: no echo, never in shell history
    else:
        # Non-interactive stdin (a pipe or heredoc): read one line as the value. This is the
        # argv-safe scripted path -- unlike --value, the secret never appears in the process
        # argument list -- and avoids getpass's misleading "input may be echoed" warning on a pipe.
        line = sys.stdin.readline()
        if not line:
            print(
                "credbox: error: no value on stdin and no --value given",
                file=sys.stderr,
            )
            return 2
        value = line.rstrip("\n")
    if not value.strip():
        # A whitespace-only value reads back as absent, so reject it rather than store a false
        # "stored" (and rather than let Credentials.set raise a ValueError as a traceback).
        print("credbox: error: empty value; nothing stored", file=sys.stderr)
        return 1
    _credentials(args).set(args.name, value=value)
    print(f"stored {args.name} for {_target(args)}")
    return 0


def _cmd_get(args: argparse.Namespace) -> int:
    if args.resolve:
        value = _credentials(args).secret(args.name)                       # override > env > store
    else:
        # Store-only, but validate `app`/`namespace` exactly as the Credentials facade does before
        # reaching a backend -- a backend trusts pre-validated segments (protocol.py), and the
        # keyring backend composes its service as f"{app}/{namespace}", so an unvalidated "a/b"
        # here would collide with another app's store. Every other subcommand goes through the
        # facade via _credentials(); this store-only path must not be the one hole in that guard.
        app = app_dir_segment(args.app)
        namespace = _valid_segment(args.namespace, label="namespace") if args.namespace is not None else None
        value = default_backend(use_keyring=args.keyring).get(app, args.name, namespace=namespace)
    if value is None:
        print(f"credbox: {args.name} is not set for {_target(args)}", file=sys.stderr)
        return 1
    # The ONLY raw-secret-to-stdout path is --reveal; otherwise print the mask.
    print(value.reveal() if args.reveal else mask_secret(value.reveal()))
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    for name in _credentials(args).names():
        print(name)
    return 0


def _cmd_unset(args: argparse.Namespace) -> int:
    _credentials(args).unset(args.name)
    print(f"removed {args.name} from {_target(args)}")
    return 0


def _cmd_path(args: argparse.Namespace) -> int:
    print(FileBackend().path(args.app))
    return 0


def _cmd_dirs(args: argparse.Namespace) -> int:
    print(f"config  {config_dir(args.app)}")
    print(f"data    {data_dir(args.app)}")
    print(f"state   {state_dir(args.app)}")
    print(f"cache   {cache_dir(args.app)}")
    print(f"runtime {runtime_dir(args.app, create=False)}")
    return 0


def _cmd_migrate(args: argparse.Namespace) -> int:
    backend = default_backend(use_keyring=args.keyring)
    source = Credentials(args.from_app, namespace=args.from_namespace, backend=backend)
    dest = Credentials(args.to_app, namespace=args.to_namespace, backend=backend)
    if args.keyring:
        # names() lists only the file-fallback entries; a keyring-only secret cannot be enumerated,
        # so it cannot be swept -- say so rather than silently migrating a subset.
        print(
            "credbox: warning: the OS keyring cannot enumerate its own keys; only file-fallback "
            "entries migrate -- re-store any keyring-only secrets under the new binding",
            file=sys.stderr,
        )
    try:
        result = source.migrate_to(dest, remove_source=args.remove_source)
    except InvalidMigrationError as err:   # an illegal request (same store, or same-app namespaced->flat)
        print(f"credbox: error: {err}", file=sys.stderr)
        return 2
    verb = "moved" if result.moved else "copied"
    clobbered = f", {result.overwritten} overwritten" if result.overwritten else ""
    print(f"{verb} {result.migrated} secret(s) to {dest.store_location()}{clobbered}")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    apps = args.app or _discover_apps()
    checked = 0
    insecure = False
    for app in apps:
        store_files = [p for p in _store_paths(app) if p.exists()]
        if not store_files:
            continue
        for path in store_files:
            checked += 1
            # OR (not short-circuit) so every file and the dir warning always print.
            insecure = warn_if_group_or_world_readable(path, app=app) or insecure
        # The config dir holds every store file for this app; check it once.
        insecure = warn_if_group_or_world_accessible(config_dir(app), app=app) or insecure
    print(f"checked {checked} credentials file(s)")
    # Exit 1 when anything was found accessible beyond its owner, so a CI/monitoring gate can key
    # off the exit code; 0 when every checked file/dir is owner-only.
    return 1 if insecure else 0


def _store_paths(app: str) -> list[Path]:
    """Every on-disk store file ``app`` may have: the plaintext ``credentials.json`` and the
    encrypted ``credentials.enc``. ``doctor`` must inspect both -- an encrypted-store-only user
    would otherwise get a false clean bill from a security-diagnostic command."""
    base = config_dir(app)
    return [base / CREDENTIALS_FILE, base / ENCRYPTED_FILE]


def _discover_apps() -> list[str]:
    """App names that have a credentials file under the config base -- the immediate
    subdirectories of the config home that contain a ``credentials.json`` OR a ``credentials.enc``.
    A subdirectory whose name is not a valid app segment is skipped, so one stray neighbour cannot
    abort the sweep."""
    config_base = config_dir("credbox").parent   # the XDG config home itself
    if not config_base.is_dir():
        return []
    discovered_apps = []
    for child in config_base.iterdir():
        if not (child.is_dir() and ((child / CREDENTIALS_FILE).is_file()
                                    or (child / ENCRYPTED_FILE).is_file())):
            continue
        try:
            app_dir_segment(child.name)
        except InvalidAppNameError:
            continue
        discovered_apps.append(child.name)
    return sorted(discovered_apps)


if __name__ == "__main__":
    raise SystemExit(main())
