"""Tests for AccountManager."""

import pytest

from src.accounts.account_manager import AccountManager, AccountStatus


class TestAccountManager:
    def setup_method(self):
        self.mgr = AccountManager()

    def test_add_and_get_account(self):
        acct = self.mgr.add_account("wallapop", "main", {"token": "abc"})
        assert acct.name == "main"
        retrieved = self.mgr.get_account("wallapop", "main")
        assert retrieved is acct

    def test_add_duplicate_raises(self):
        self.mgr.add_account("wallapop", "main", {"token": "abc"})
        with pytest.raises(ValueError, match="already exists"):
            self.mgr.add_account("wallapop", "main", {"token": "xyz"})

    def test_get_all_accounts(self):
        self.mgr.add_account("ebay", "shop1", {"key": "k1"})
        self.mgr.add_account("ebay", "shop2", {"key": "k2"})
        assert len(self.mgr.get_all_accounts("ebay")) == 2

    def test_get_healthy_accounts(self):
        self.mgr.add_account("ebay", "shop1", {"key": "k1"})
        self.mgr.add_account("ebay", "shop2", {"key": "k2"}, status=AccountStatus.SUSPENDED)
        healthy = self.mgr.get_healthy_accounts("ebay")
        assert len(healthy) == 1
        assert healthy[0].name == "shop1"

    def test_remove_account(self):
        self.mgr.add_account("wallapop", "main", {"token": "abc"})
        assert self.mgr.remove_account("wallapop", "main") is True
        assert self.mgr.get_account("wallapop", "main") is None

    def test_remove_nonexistent_returns_false(self):
        assert self.mgr.remove_account("wallapop", "ghost") is False

    def test_update_credentials(self):
        self.mgr.add_account("ebay", "shop1", {"key": "old"})
        assert self.mgr.update_credentials("ebay", "shop1", {"key": "new"}) is True
        assert self.mgr.get_account("ebay", "shop1").credentials["key"] == "new"

    def test_update_credentials_nonexistent(self):
        assert self.mgr.update_credentials("ebay", "ghost", {"key": "x"}) is False

    def test_set_status(self):
        self.mgr.add_account("wallapop", "main", {"token": "abc"})
        self.mgr.set_status("wallapop", "main", AccountStatus.SUSPENDED)
        assert self.mgr.get_account("wallapop", "main").status == AccountStatus.SUSPENDED

    def test_platforms_property(self):
        self.mgr.add_account("wallapop", "a", {})
        self.mgr.add_account("ebay", "b", {})
        assert sorted(self.mgr.platforms) == ["ebay", "wallapop"]
