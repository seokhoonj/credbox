"""The backends subpackage.

Re-exports the ``SecretBackend`` protocol, the zero-dep ``FileBackend``, and the factories ONLY
-- never the extra backend classes (``KeyringBackend`` / ``EncryptedFileBackend``). This keeps the
core/extras boundary a physical import line: ``import credbox.backends`` reaches only ``file`` and
``factory`` (which import an extra module lazily, behind a find-spec gate), so the eager import
graph of the core can never pull ``keyring`` or ``cryptography``.
"""

from __future__ import annotations

from credbox.backends.factory import (
    default_backend,
    encrypted_backend,
    file_backend,
    keyring_backend,
)
from credbox.backends.file import FileBackend
from credbox.backends.protocol import SecretBackend, SupportsLocationDescription

__all__ = [
    "SecretBackend",
    "SupportsLocationDescription",
    "FileBackend",
    "file_backend",
    "keyring_backend",
    "encrypted_backend",
    "default_backend",
]
