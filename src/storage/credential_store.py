"""Encrypted JSON-file credential storage using Fernet symmetric encryption."""

import json
import os
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet


class CredentialStore:
    """Persist credentials to disk with Fernet encryption.

    On first use, an encryption key is auto-generated and saved alongside
    the data file. All values are encrypted at rest — plaintext secrets are
    never written to disk.
    """

    def __init__(self, storage_path: str = "credentials.enc", key_path: Optional[str] = None):
        self._storage_path = Path(storage_path)
        self._key_path = Path(key_path) if key_path else self._storage_path.with_suffix(".key")
        self._fernet = self._load_or_create_key()

    def store(self, key: str, credentials: dict[str, Any]) -> None:
        """Encrypt and persist credentials under the given key."""
        data = self._load_all()
        data[key] = credentials
        self._save_all(data)

    def retrieve(self, key: str) -> Optional[dict[str, Any]]:
        """Return decrypted credentials, or None if the key doesn't exist."""
        data = self._load_all()
        return data.get(key)

    def delete(self, key: str) -> bool:
        """Remove a credential entry. Returns True if it existed."""
        data = self._load_all()
        if key not in data:
            return False
        del data[key]
        self._save_all(data)
        return True

    def list_keys(self) -> list[str]:
        return list(self._load_all().keys())

    def _load_or_create_key(self) -> Fernet:
        if self._key_path.exists():
            encryption_key = self._key_path.read_bytes().strip()
        else:
            encryption_key = Fernet.generate_key()
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_bytes(encryption_key)
            os.chmod(str(self._key_path), 0o600)
        return Fernet(encryption_key)

    def _load_all(self) -> dict[str, Any]:
        if not self._storage_path.exists():
            return {}
        encrypted = self._storage_path.read_bytes()
        if not encrypted:
            return {}
        plaintext = self._fernet.decrypt(encrypted)
        return json.loads(plaintext)

    def _save_all(self, data: dict[str, Any]) -> None:
        plaintext = json.dumps(data).encode()
        encrypted = self._fernet.encrypt(plaintext)
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._storage_path.write_bytes(encrypted)
