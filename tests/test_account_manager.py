"""Tests for account authentication manager."""
import base64
import json
import time
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock
from src.accounts.account_manager import AccountAuthManager, Account
from src.cookies.cookie_store import StoredCookies
from src.cookies.cookie_refresher import CookieRefresher, RefreshResult


def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"sig").decode().rstrip("=")
    return f"{header}.{body}.{sig}"


def _valid_token():
    return _make_jwt({"exp": int(time.time()) + 3600, "sub": "user"})


def _expired_token():
    return _make_jwt({"exp": int(time.time()) - 3600, "sub": "user"})


def _account(id=1, name="TestAccount", hash="testhash"):
    return Account(id=id, account_name=name, account_hash=hash)


def _stored(access_token=None, is_valid=True, session_token="sess"):
    return StoredCookies(
        account_hash="testhash",
        cookies_json=[{"name": "s", "value": "v"}],
        access_token=access_token,
        session_token=session_token,
        is_valid=is_valid,
    )


class TestAccountRegistry:
    def test_add_and_get_by_id(self):
        mgr = AccountAuthManager()
        acct = _account()
        mgr.add_account(acct)
        assert mgr.get_account_by_id(1) == acct

    def test_get_by_name(self):
        mgr = AccountAuthManager()
        mgr.add_account(_account(id=1, name="Alpha"))
        mgr.add_account(_account(id=2, name="Beta"))
        assert mgr.get_account_by_name("Beta").id == 2

    def test_get_by_hash(self):
        mgr = AccountAuthManager()
        mgr.add_account(_account(id=1, hash="h1"))
        mgr.add_account(_account(id=2, hash="h2"))
        assert mgr.get_account_by_hash("h2").id == 2

    def test_get_missing_returns_none(self):
        mgr = AccountAuthManager()
        assert mgr.get_account_by_id(999) is None
        assert mgr.get_account_by_name("nope") is None
        assert mgr.get_account_by_hash("nope") is None

    def test_remove_account(self):
        mgr = AccountAuthManager()
        mgr.add_account(_account(id=1))
        assert mgr.remove_account(1) is True
        assert mgr.get_account_by_id(1) is None

    def test_remove_missing(self):
        mgr = AccountAuthManager()
        assert mgr.remove_account(999) is False

    def test_get_all_accounts(self):
        mgr = AccountAuthManager()
        mgr.add_account(_account(id=1, name="A"))
        mgr.add_account(_account(id=2, name="B"))
        all_accts = mgr.get_all_accounts()
        assert len(all_accts) == 2
        assert 1 in all_accts
        assert 2 in all_accts

    def test_get_all_returns_copy(self):
        mgr = AccountAuthManager()
        mgr.add_account(_account(id=1))
        copy = mgr.get_all_accounts()
        copy[999] = _account(id=999)
        assert mgr.get_account_by_id(999) is None


class TestLoadAccounts:
    def test_loads_from_callback(self):
        accounts = [
            _account(id=1, name="A", hash="h1"),
            _account(id=2, name="B", hash="h2"),
        ]
        mgr = AccountAuthManager(load_accounts_fn=lambda: accounts)
        assert len(mgr.get_all_accounts()) == 2

    def test_skips_inactive(self):
        inactive = _account(id=1, name="A", hash="h1")
        inactive.is_active = False
        mgr = AccountAuthManager(load_accounts_fn=lambda: [inactive])
        assert len(mgr.get_all_accounts()) == 0

    def test_skips_no_hash(self):
        no_hash = _account(id=1, name="A", hash="")
        mgr = AccountAuthManager(load_accounts_fn=lambda: [no_hash])
        assert len(mgr.get_all_accounts()) == 0

    def test_handles_callback_error(self):
        def fail():
            raise RuntimeError("db down")

        mgr = AccountAuthManager(load_accounts_fn=fail)
        assert len(mgr.get_all_accounts()) == 0

    def test_reload(self):
        call_count = 0
        def loader():
            nonlocal call_count
            call_count += 1
            return [_account(id=call_count, name=f"V{call_count}", hash=f"h{call_count}")]

        mgr = AccountAuthManager(load_accounts_fn=loader)
        assert len(mgr.get_all_accounts()) == 1
        mgr.reload_accounts()
        all_accts = mgr.get_all_accounts()
        assert len(all_accts) == 1
        assert 2 in all_accts


class TestGetAccessToken:
    def test_valid_token_returned_directly(self):
        token = _valid_token()
        stored = _stored(access_token=token)
        mgr = AccountAuthManager(
            load_cookies_fn=lambda h: stored,
            persist_cookies_fn=lambda s: True,
        )
        result = mgr.get_access_token(_account(), validate_hash=False)
        assert result == token

    def test_expired_token_triggers_refresh(self):
        expired = _expired_token()
        new_token = _valid_token()
        stored = _stored(access_token=expired)

        def mock_get(url, cookies, timeout, user_agent):
            return 200, [("accessToken", new_token)], {}

        refresher = CookieRefresher(http_get=mock_get)
        mgr = AccountAuthManager(
            load_cookies_fn=lambda h: stored,
            persist_cookies_fn=lambda s: True,
            refresher=refresher,
        )
        result = mgr.get_access_token(_account(), validate_hash=False)
        assert result == new_token

    def test_no_cookies_returns_none(self):
        mgr = AccountAuthManager(load_cookies_fn=lambda h: None)
        result = mgr.get_access_token(_account(), validate_hash=False)
        assert result is None

    def test_no_hash_returns_none(self):
        mgr = AccountAuthManager()
        result = mgr.get_access_token(_account(hash=""), validate_hash=False)
        assert result is None

    def test_validation_pass(self):
        token = _valid_token()
        stored = _stored(access_token=token)
        mgr = AccountAuthManager(
            load_cookies_fn=lambda h: stored,
            persist_cookies_fn=lambda s: True,
            validate_token_fn=lambda t, h: (True, "ok"),
        )
        result = mgr.get_access_token(_account(), validate_hash=True)
        assert result == token

    def test_validation_fail(self):
        token = _valid_token()
        stored = _stored(access_token=token)
        mgr = AccountAuthManager(
            load_cookies_fn=lambda h: stored,
            persist_cookies_fn=lambda s: True,
            validate_token_fn=lambda t, h: (False, "hash mismatch"),
        )
        result = mgr.get_access_token(_account(), validate_hash=True)
        assert result is None

    def test_refresh_failure_returns_none(self):
        expired = _expired_token()
        stored = _stored(access_token=expired)

        def mock_get(url, cookies, timeout, user_agent):
            return 500, [], {}

        refresher = CookieRefresher(http_get=mock_get)
        mgr = AccountAuthManager(
            load_cookies_fn=lambda h: stored,
            persist_cookies_fn=lambda s: True,
            refresher=refresher,
        )
        result = mgr.get_access_token(
            _account(), validate_hash=False, max_refresh_attempts=1
        )
        assert result is None

    def test_no_load_fn_returns_none(self):
        mgr = AccountAuthManager()
        result = mgr.get_access_token(_account(), validate_hash=False)
        assert result is None


class TestHasValidCookies:
    def test_valid_cookies(self):
        stored = _stored(session_token="tok")
        mgr = AccountAuthManager(load_cookies_fn=lambda h: stored)
        assert mgr.has_valid_cookies(_account()) is True

    def test_invalid_cookies(self):
        stored = _stored(is_valid=False, session_token="tok")
        mgr = AccountAuthManager(load_cookies_fn=lambda h: stored)
        assert mgr.has_valid_cookies(_account()) is False

    def test_no_session_token(self):
        stored = _stored(session_token=None)
        mgr = AccountAuthManager(load_cookies_fn=lambda h: stored)
        assert mgr.has_valid_cookies(_account()) is False

    def test_no_hash(self):
        mgr = AccountAuthManager()
        assert mgr.has_valid_cookies(_account(hash="")) is False

    def test_no_stored_cookies(self):
        mgr = AccountAuthManager(load_cookies_fn=lambda h: None)
        assert mgr.has_valid_cookies(_account()) is False


class TestLegacyAlias:
    def test_get_valid_bearer(self):
        token = _valid_token()
        stored = _stored(access_token=token)
        mgr = AccountAuthManager(
            load_cookies_fn=lambda h: stored,
            persist_cookies_fn=lambda s: True,
        )
        result = mgr.get_valid_bearer(_account(), validate_hash=False)
        assert result == token


class TestAccount:
    def test_defaults(self):
        acct = Account(id=1, account_name="Test", account_hash="abc")
        assert acct.platform_name == "marketplace"
        assert acct.is_active is True
        assert acct.extra == {}

    def test_with_custom_fields(self):
        acct = Account(
            id=2,
            account_name="Custom",
            account_hash="xyz",
            platform_name="wallapop",
            is_active=False,
            extra={"region": "ES"},
        )
        assert acct.platform_name == "wallapop"
        assert acct.is_active is False
        assert acct.extra["region"] == "ES"
