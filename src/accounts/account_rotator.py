"""Round-robin account rotation with health tracking and cooldown support."""

import time
from typing import Optional

from .account_manager import Account, AccountManager, AccountStatus


class AccountRotator:
    """Rotate through healthy accounts in round-robin order.

    Features:
    - Skips unhealthy (suspended / expired / rate-limited) accounts.
    - Applies per-account cooldown after rate-limit events.
    - Tracks cumulative usage count per account for monitoring.
    """

    DEFAULT_COOLDOWN_SECONDS = 60

    def __init__(
        self,
        manager: AccountManager,
        platform: str,
        cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS,
    ):
        self._manager = manager
        self._platform = platform
        self._cooldown_seconds = cooldown_seconds

        self._index = 0
        self._usage_count: dict[str, int] = {}
        self._cooldown_until: dict[str, float] = {}

    def get_next_account(self) -> Optional[Account]:
        """Return the next healthy, non-cooling-down account, or None."""
        accounts = self._manager.get_all_accounts(self._platform)
        if not accounts:
            return None

        total = len(accounts)
        for _ in range(total):
            account = accounts[self._index % total]
            self._index = (self._index + 1) % total

            if not account.is_healthy:
                continue
            if self._is_cooling_down(account.name):
                continue

            self._usage_count[account.name] = self._usage_count.get(account.name, 0) + 1
            return account

        return None

    def report_rate_limited(self, account_name: str) -> None:
        """Mark an account as rate-limited and start its cooldown timer."""
        self._cooldown_until[account_name] = time.time() + self._cooldown_seconds
        self._manager.set_status(
            self._platform, account_name, AccountStatus.RATE_LIMITED
        )

    def clear_cooldown(self, account_name: str) -> None:
        """Manually clear cooldown and reactivate an account."""
        self._cooldown_until.pop(account_name, None)
        self._manager.set_status(
            self._platform, account_name, AccountStatus.ACTIVE
        )

    def get_usage_stats(self) -> dict[str, int]:
        return dict(self._usage_count)

    def _is_cooling_down(self, account_name: str) -> bool:
        until = self._cooldown_until.get(account_name)
        if until is None:
            return False
        if time.time() >= until:
            self._cooldown_until.pop(account_name)
            self._manager.set_status(
                self._platform, account_name, AccountStatus.ACTIVE
            )
            return False
        return True
