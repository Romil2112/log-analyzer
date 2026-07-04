"""Field-level encryption at rest using Fernet (AES-128-CBC + HMAC-SHA256).

The operator supplies an arbitrary secret string via ``DB_ENCRYPTION_KEY``; we
derive a stable 32-byte Fernet key from it with SHA-256. When the variable is
unset, encryption is disabled gracefully and values pass through as plaintext,
so the tool keeps working without a key configured.

Fernet provides authenticated encryption (encrypt-then-HMAC-SHA256) with a fresh
random 128-bit IV per token and never uses ECB, satisfying the at-rest
confidentiality + integrity requirement. See decision_log.md D1 for why this is
kept over a raw AES-GCM scheme (backward compatibility of already-encrypted rows).
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken


def get_fernet() -> Optional[Fernet]:
    """Build a Fernet from ``DB_ENCRYPTION_KEY``, or return None if it is unset."""
    key = os.environ.get("DB_ENCRYPTION_KEY")
    if not key:
        return None
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_field(fernet: Optional[Fernet], value):
    """Encrypt a value for storage.

    ``None`` passes through unchanged, and when ``fernet`` is None (encryption
    disabled) the original value is returned so callers need no branching.
    """
    if fernet is None or value is None:
        return value
    if not isinstance(value, str):
        value = str(value)
    return fernet.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_field(fernet: Optional[Fernet], value):
    """Decrypt a stored value.

    ``None`` passes through. When encryption is disabled, or the value predates
    encryption (i.e. it was stored as plaintext), the value is returned
    unchanged — this keeps mixed plaintext/ciphertext data readable.
    """
    if fernet is None or value is None:
        return value
    try:
        return fernet.decrypt(value.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError):
        return value
