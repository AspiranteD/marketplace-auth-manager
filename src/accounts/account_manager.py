"""
Multi-account authentication manager.

Thread-safe manager that coordinates:
  - Loading accounts from any data source (via callbacks)
  - Token retrieval with automatic refresh
  - Account-level validation (hash matching)
  - Compatibility aliases for legacy code
"""
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Callable, Tuple, List

from src.token.jwt_utils import is_token_expired
from src.cookies.cookie_store import StoredCookies
from src.cookies.cookie_refresher import CookieRefresher, apply_refresh_to_stored

logger = logging.getLogger(__name__)


@dataclass
class Account:
    """Represents a marketplace account."""
    id: int
    account_name: str
    account_hash: str
    platform_name: str = "marketplace"
    is_active: bool = True
    extra: Dict = field(default_factory=dict)


class AccountAuthManager:
    """
    Manages authentication across multiple marketplace accounts.

    Thread-safe: all account access is protected by a lock.

    Architecture: database-agnostic. Uses callbacks for:
      - load_accounts_fn: () -> List[Account]
      - load_cookies_fn: (account_hash) -> Optional[StoredCookies]
      - persist_cookies_fn: (StoredCookies) -> bool
      - validate_token_fn: (access_token, account_hash) -> (bool, str)
    """

    def __init__(
        self,
        load_accounts_fn: Optional[Callable[[], List[Account]]] = None,
        load_cookies_fn: Optional[Callable[[str], Optional[StoredCookies]]] = None,
        persist_cookies_fn: Optional[Callable[[StoredCookies], bool]] = None,
        validate_token_fn: Optional[Callable[[str, str], Tuple[bool, str]]] = None,
        refresher: Optional[CookieRefresher] = None,
    ):
        self._accounts: Dict[int, Account] = {}
        self._lock = threading.Lock()
        self._load_accounts_fn = load_accounts_fn
        self._load_cookies_fn = load_cookies_fn
        self._persist_cookies_fn = persist_cookies_fn
        self._validate_token_fn = validate_token_fn
        self._refresher = refresher or CookieRefresher()

        if load_accounts_fn:
            self._load_accounts()

    def _load_accounts(self):
        """Load accounts using the provided callback."""
        if not self._load_accounts_fn:
            return
        try:
            accounts = self._load_accounts_fn()
            with self._lock:
                self._accounts.clear()
                for acct in accounts:
                    if acct.account_hash and acct.is_active:
                        self._accounts[acct.id] = acct
            logger.info("Loaded %d active accounts", len(self._accounts))
        except Exception as e:
            logger.error("Error loading accounts: %s", e)

    def reload_accounts(self):
        """Reload all accounts from the data source."""
        self._load_accounts()

    def add_account(self, account: Account):
        """Add or update an account in the in-memory registry."""
        with self._lock:
            self._accounts[account.id] = account

    def remove_account(self, account_id: int) -> bool:
        """Remove an account from the in-memory registry."""
        with self._lock:
            return self._accounts.pop(account_id, None) is not None

    def get_account_by_id(self, account_id: int) -> Optional[Account]:
        """Get an account by ID."""
        with self._lock:
            return self._accounts.get(account_id)

    def get_account_by_name(self, account_name: str) -> Optional[Account]:
        """Get an account by name."""
        with self._lock:
            for acct in self._accounts.values():
                if acct.account_name == account_name:
                    return acct
        return None

    def get_account_by_hash(self, account_hash: str) -> Optional[Account]:
        """Get an account by hash."""
        with self._lock:
            for acct in self._accounts.values():
                if acct.account_hash == account_hash:
                    return acct
        return None

    def get_all_accounts(self) -> Dict[int, Account]:
        """Get a snapshot of all registered accounts."""
        with self._lock:
            return self._accounts.copy()

    def get_access_token(
        self,
        account: Account,
        validate_hash: bool = True,
        max_refresh_attempts: int = 3,
    ) -> Optional[str]:
        """
        Get a valid access token for an account.

        Flow:
        1. Load stored cookies for the account
        2. If access token is present and not expired, return it
        3. If expired, attempt refresh
        4. Optionally validate the token's hash matches the account
        """
        if not account.account_hash:
            logger.error("Account %s has no account_hash", account.account_name)
            return None

        stored = self._get_stored_cookies(account.account_hash)
        if not stored:
            logger.warning("No cookies found for account %s", account.account_name)
            return None

        if stored.access_token and not is_token_expired(stored.access_token):
            stored.last_used_at = __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            )
            self._persist(stored)

            if validate_hash:
                valid, msg = self._validate_token(stored.access_token, account.account_hash)
                if not valid:
                    logger.error("Token validation failed for %s: %s", account.account_name, msg)
                    return None

            return stored.access_token

        result = self._refresher.refresh(stored, max_attempts=max_refresh_attempts)
        apply_refresh_to_stored(stored, result)
        self._persist(stored)

        if not result.success:
            logger.error(
                "Refresh failed for %s: %s", account.account_name, result.error
            )
            return None

        if validate_hash:
            valid, msg = self._validate_token(result.new_token, account.account_hash)
            if not valid:
                logger.error("Token validation failed for %s: %s", account.account_name, msg)
                return None

        return result.new_token

    def has_valid_cookies(self, account: Account) -> bool:
        """Check if an account has valid stored cookies."""
        if not account.account_hash:
            return False
        stored = self._get_stored_cookies(account.account_hash)
        if not stored:
            return False
        return stored.is_valid and stored.session_token is not None

    def _get_stored_cookies(self, account_hash: str) -> Optional[StoredCookies]:
        """Load stored cookies using the callback."""
        if not self._load_cookies_fn:
            return None
        try:
            return self._load_cookies_fn(account_hash)
        except Exception as e:
            logger.error("Error loading cookies for %s: %s", account_hash, e)
            return None

    def _persist(self, stored: StoredCookies):
        """Persist updated cookies using the callback."""
        if not self._persist_cookies_fn:
            return
        try:
            self._persist_cookies_fn(stored)
        except Exception as e:
            logger.error("Error persisting cookies for %s: %s", stored.account_hash, e)

    def _validate_token(self, token: str, expected_hash: str) -> Tuple[bool, str]:
        """Validate token using the callback, or skip if none provided."""
        if not self._validate_token_fn:
            return True, "No validator configured"
        try:
            return self._validate_token_fn(token, expected_hash)
        except Exception as e:
            return False, f"Validation error: {e}"

    # Legacy aliases
    def get_valid_bearer(self, account: Account, **kwargs) -> Optional[str]:
        """Deprecated: use get_access_token()."""
        return self.get_access_token(account, **kwargs)
