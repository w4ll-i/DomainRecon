# backend/app/crypto.py
"""
Transparent at-rest encryption for sensitive settings columns.

`EncryptedString` is a SQLAlchemy TypeDecorator: values are Fernet-encrypted
on the way into the database and decrypted on the way out, so the rest of the
application keeps seeing plaintext. Decryption is tolerant of legacy plaintext
rows (written before encryption was introduced) - they are returned as-is and
re-encrypted the next time they are written.

Key resolution order:
  1. ``DOMAINRECON_SECRET_KEY`` env var - any passphrase; a Fernet key is
     derived from its SHA-256 digest.
  2. A persisted random key file at ``data/.secret_key`` (created on first use,
     restricted to the owner where the OS allows it).
"""
import base64
import hashlib
import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import String
from sqlalchemy.types import TypeDecorator

_log = logging.getLogger("domainrecon")

_PREFIX = "enc:v1:"  # marks a value as encrypted by us


def _derive_fernet_key(passphrase: str) -> bytes:
    """Derive a urlsafe-base64 Fernet key from an arbitrary passphrase."""
    digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _load_or_create_keyfile() -> bytes:
    key_path = Path(__file__).resolve().parent.parent.parent / "data" / ".secret_key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        return key_path.read_bytes().strip()
    key = Fernet.generate_key()
    key_path.write_bytes(key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass  # best-effort on platforms without POSIX perms
    return key


def _build_fernet() -> Fernet:
    env_key = os.getenv("DOMAINRECON_SECRET_KEY")
    if env_key:
        return Fernet(_derive_fernet_key(env_key))
    return Fernet(_load_or_create_keyfile())


# Lazily-initialised singleton so importing this module never touches disk.
_fernet: Fernet | None = None


def _fernet_instance() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = _build_fernet()
    return _fernet


def encrypt(value: str) -> str:
    token = _fernet_instance().encrypt(value.encode("utf-8")).decode("ascii")
    return _PREFIX + token


def decrypt(stored: str) -> str:
    """Decrypt a stored value; return legacy plaintext unchanged."""
    if not stored.startswith(_PREFIX):
        return stored  # legacy plaintext row - not yet encrypted
    token = stored[len(_PREFIX):]
    try:
        return _fernet_instance().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        _log.warning("Failed to decrypt a settings value (wrong DOMAINRECON_SECRET_KEY?)")
        return ""


class EncryptedString(TypeDecorator):
    """A String column whose value is Fernet-encrypted at rest."""

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None or value == "":
            return value
        return encrypt(str(value))

    def process_result_value(self, value, dialect):
        if value is None or value == "":
            return value
        return decrypt(value)
