"""Reading non-secret JSON state from disk, corruption-aware.

This is for NON-secret state only -- watermarks, cursors, small config. The secret store uses
``_storecodec`` (the leak-safe returning-frame codec), never this module: a malformed secret
file must produce a content-free fault, whereas here a malformed *state* file is simply
treated as absent. A missing file or invalid JSON returns ``None``; a genuine ``OSError``
(permission denied, an I/O error) propagates so a real problem is not silently swallowed.
"""

from __future__ import annotations

import json
from pathlib import Path

__all__ = ["read_json"]


def read_json(path: Path) -> object | None:
    """Return the parsed JSON at ``path``, or ``None`` when the file is missing or its contents
    are not valid JSON (not UTF-8, or not JSON). A genuine ``OSError`` other than "not found"
    (permission denied, I/O error) propagates. For NON-secret state only."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    try:
        parsed: object = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        # A state file that will not parse is treated as absent rather than propagating a traceback.
        # ValueError covers json.JSONDecodeError (a subclass) AND the bare ValueError json.loads
        # raises for a number past the integer-string-conversion limit; RecursionError covers deep
        # nesting. A genuine OSError (handled above) still propagates.
        return None
    return parsed
