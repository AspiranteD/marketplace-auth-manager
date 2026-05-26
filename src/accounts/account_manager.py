"""Multi-account credential management across marketplace platforms."""

from enum import Enum
from typing import Any, Optional


class AccountStatus(Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    RATE_LIMITED = "rate_limited"


class Account:
    """Represents a single marketplace account with its credentials and health state."""

    def __init__(
        self,
        platform: str,
        name: str,
        credentials: dict[str, Any],
        status: AccountStatus = AccountStatus.ACTIVE,
    ):
        self.platform = platform
        self.name = name
        self.credentials = credentials
        self.status = status

    @property
    def is_healthy(self) -> bool:
        return self.status == AccountStatus.ACTIVE

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "name": self.name,
            "credentials": self.credentials,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Account":
        return cls(
            platform=data["platform"],
            name=data["name"],
            credentials=data["credentials"],
            status=AccountStatus(data.get("status", "active")),
        )


class AccountManager:
    """Manage multiple accounts per marketplace platform.

    Provides CRUD operations on accounts, tracks health status, and serves as
    the single source of truth for credential lookup before rotation logic.
    """

    def __init__(self) -> None:
        self._accounts: dict[str, dict[str, Account]] = {}

    def add_account(
        self,
        platform: str,
        name: str,
        credentials: dict[str, Any],
        status: AccountStatus = AccountStatus.ACTIVE,
    ) -> Account:
        """Register a new account. Raises ValueError if it already exists."""
        if platform not in self._accounts:
            self._accounts[platform] = {}
        if name in self._accounts[platform]:
            raise ValueError(f"Account '{name}' already exists for platform '{platform}'")

        account = Account(platform, name, credentials, status)
        self._accounts[platform][name] = account
        return account

    def get_account(self, platform: str, name: str) -> Optional[Account]:
        return self._accounts.get(platform, {}).get(name)

    def get_all_accounts(self, platform: str) -> list[Account]:
        return list(self._accounts.get(platform, {}).values())

    def get_healthy_accounts(self, platform: str) -> list[Account]:
        return [a for a in self.get_all_accounts(platform) if a.is_healthy]

    def remove_account(self, platform: str, name: str) -> bool:
        """Remove an account. Returns True if it existed."""
        platform_accounts = self._accounts.get(platform, {})
        if name in platform_accounts:
            del platform_accounts[name]
            return True
        return False

    def update_credentials(
        self, platform: str, name: str, credentials: dict[str, Any]
    ) -> bool:
        """Replace credentials for an existing account. Returns True on success."""
        account = self.get_account(platform, name)
        if not account:
            return False
        account.credentials = credentials
        return True

    def set_status(self, platform: str, name: str, status: AccountStatus) -> bool:
        account = self.get_account(platform, name)
        if not account:
            return False
        account.status = status
        return True

    @property
    def platforms(self) -> list[str]:
        return list(self._accounts.keys())
