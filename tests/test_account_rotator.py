"""Tests for AccountRotator."""

import time
from unittest.mock import patch

import pytest

from src.accounts.account_manager import AccountManager, AccountStatus
from src.accounts.account_rotator import AccountRotator


def _setup_rotator(n_accounts: int = 3, cooldown: float = 60) -> tuple[AccountManager, AccountRotator]:
    mgr = AccountManager()
    for i in range(n_accounts):
        mgr.add_account("ebay", f"shop{i}", {"key": f"k{i}"})
    return mgr, AccountRotator(mgr, "ebay", cooldown_seconds=cooldown)


class TestAccountRotator:
    def test_round_robin_order(self):
        mgr, rotator = _setup_rotator(3)
        names = [rotator.get_next_account().name for _ in range(6)]
        assert names == ["shop0", "shop1", "shop2", "shop0", "shop1", "shop2"]

    def test_skips_suspended_accounts(self):
        mgr, rotator = _setup_rotator(3)
        mgr.set_status("ebay", "shop1", AccountStatus.SUSPENDED)
        names = [rotator.get_next_account().name for _ in range(4)]
        assert "shop1" not in names

    def test_returns_none_when_all_unhealthy(self):
        mgr, rotator = _setup_rotator(2)
        mgr.set_status("ebay", "shop0", AccountStatus.SUSPENDED)
        mgr.set_status("ebay", "shop1", AccountStatus.EXPIRED)
        assert rotator.get_next_account() is None

    def test_returns_none_when_no_accounts(self):
        mgr = AccountManager()
        rotator = AccountRotator(mgr, "ebay")
        assert rotator.get_next_account() is None

    def test_rate_limit_cooldown(self):
        mgr, rotator = _setup_rotator(2, cooldown=60)
        rotator.report_rate_limited("shop0")
        acct = rotator.get_next_account()
        assert acct.name == "shop1"

    def test_cooldown_expires(self):
        mgr, rotator = _setup_rotator(1, cooldown=0.05)
        rotator.report_rate_limited("shop0")
        mgr.set_status("ebay", "shop0", AccountStatus.ACTIVE)
        time.sleep(0.1)
        acct = rotator.get_next_account()
        assert acct is not None
        assert acct.name == "shop0"

    def test_clear_cooldown(self):
        mgr, rotator = _setup_rotator(1, cooldown=9999)
        rotator.report_rate_limited("shop0")
        assert rotator.get_next_account() is None
        rotator.clear_cooldown("shop0")
        assert rotator.get_next_account().name == "shop0"

    def test_usage_stats(self):
        mgr, rotator = _setup_rotator(2)
        for _ in range(5):
            rotator.get_next_account()
        stats = rotator.get_usage_stats()
        assert stats["shop0"] == 3
        assert stats["shop1"] == 2
