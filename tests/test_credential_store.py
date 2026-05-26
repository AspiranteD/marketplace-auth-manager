"""Tests for CredentialStore."""

import os
import tempfile

import pytest

from src.storage.credential_store import CredentialStore


@pytest.fixture
def store(tmp_path):
    return CredentialStore(
        storage_path=str(tmp_path / "creds.enc"),
        key_path=str(tmp_path / "creds.key"),
    )


class TestCredentialStore:
    def test_store_and_retrieve(self, store):
        store.store("ebay_main", {"client_id": "abc", "secret": "xyz"})
        result = store.retrieve("ebay_main")
        assert result == {"client_id": "abc", "secret": "xyz"}

    def test_retrieve_nonexistent(self, store):
        assert store.retrieve("ghost") is None

    def test_delete(self, store):
        store.store("key1", {"a": 1})
        assert store.delete("key1") is True
        assert store.retrieve("key1") is None

    def test_delete_nonexistent(self, store):
        assert store.delete("ghost") is False

    def test_list_keys(self, store):
        store.store("k1", {"a": 1})
        store.store("k2", {"b": 2})
        assert sorted(store.list_keys()) == ["k1", "k2"]

    def test_overwrite_existing(self, store):
        store.store("k1", {"v": "old"})
        store.store("k1", {"v": "new"})
        assert store.retrieve("k1") == {"v": "new"}

    def test_encryption_key_persisted(self, tmp_path):
        key_path = str(tmp_path / "test.key")
        store1 = CredentialStore(str(tmp_path / "data.enc"), key_path)
        store1.store("secret", {"password": "hunter2"})

        store2 = CredentialStore(str(tmp_path / "data.enc"), key_path)
        assert store2.retrieve("secret") == {"password": "hunter2"}

    def test_data_is_encrypted_on_disk(self, tmp_path):
        enc_path = tmp_path / "data.enc"
        store = CredentialStore(str(enc_path), str(tmp_path / "data.key"))
        store.store("secret", {"password": "hunter2"})
        raw = enc_path.read_bytes()
        assert b"hunter2" not in raw
