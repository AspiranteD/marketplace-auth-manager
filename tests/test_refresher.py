"""Tests for cookie refresher."""
import base64
import json
import time
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from src.cookies.cookie_store import StoredCookies, ACCESS_TOKEN_COOKIE
from src.cookies.cookie_refresher import (
    CookieRefresher,
    RefreshResult,
    apply_refresh_to_stored,
)


def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"sig").decode().rstrip("=")
    return f"{header}.{body}.{sig}"


def _valid_token():
    return _make_jwt({"exp": int(time.time()) + 3600, "sub": "user"})


def _expired_token():
    return _make_jwt({"exp": int(time.time()) - 3600, "sub": "user"})


def _stored(access_token=None, cookies=None):
    return StoredCookies(
        account_hash="testhash",
        cookies_json=cookies or [{"name": "session", "value": "s123"}],
        access_token=access_token,
        session_token="s123",
    )


class TestSingleRefresh:
    def test_success_token_in_cookies(self):
        new_token = _valid_token()

        def mock_get(url, cookies, timeout, user_agent):
            return 200, [(ACCESS_TOKEN_COOKIE, new_token)], {}

        refresher = CookieRefresher(http_get=mock_get)
        stored = _stored()
        result = refresher._single_refresh(stored)
        assert result.success
        assert result.new_token == new_token
        assert result.updated_cookies is not None

    def test_success_token_in_set_cookie_header(self):
        new_token = _valid_token()

        def mock_get(url, cookies, timeout, user_agent):
            headers = {"Set-Cookie": f"{ACCESS_TOKEN_COOKIE}={new_token}; Path=/; HttpOnly"}
            return 200, [], headers

        refresher = CookieRefresher(http_get=mock_get)
        result = refresher._single_refresh(_stored())
        assert result.success
        assert result.new_token == new_token

    def test_fallback_to_existing_valid_token(self):
        valid = _valid_token()

        def mock_get(url, cookies, timeout, user_agent):
            return 200, [], {}

        refresher = CookieRefresher(http_get=mock_get)
        result = refresher._single_refresh(_stored(access_token=valid))
        assert result.success
        assert result.new_token == valid

    def test_no_fallback_for_expired_token(self):
        expired = _expired_token()

        def mock_get(url, cookies, timeout, user_agent):
            return 200, [], {}

        refresher = CookieRefresher(http_get=mock_get)
        result = refresher._single_refresh(_stored(access_token=expired))
        assert not result.success
        assert "No access token" in result.error

    def test_http_error(self):
        def mock_get(url, cookies, timeout, user_agent):
            return 401, [], {}

        refresher = CookieRefresher(http_get=mock_get)
        result = refresher._single_refresh(_stored())
        assert not result.success
        assert "401" in result.error
        assert "auth error" in result.error

    def test_http_500(self):
        def mock_get(url, cookies, timeout, user_agent):
            return 500, [], {}

        refresher = CookieRefresher(http_get=mock_get)
        result = refresher._single_refresh(_stored())
        assert not result.success
        assert "500" in result.error

    def test_timeout_error(self):
        def mock_get(url, cookies, timeout, user_agent):
            raise TimeoutError("timed out")

        refresher = CookieRefresher(http_get=mock_get)
        result = refresher._single_refresh(_stored())
        assert not result.success
        assert "timeout" in result.error.lower()

    def test_generic_exception(self):
        def mock_get(url, cookies, timeout, user_agent):
            raise RuntimeError("network down")

        refresher = CookieRefresher(http_get=mock_get)
        result = refresher._single_refresh(_stored())
        assert not result.success
        assert "network down" in result.error


class TestRefreshWithRetries:
    def test_success_on_first_attempt(self):
        token = _valid_token()

        def mock_get(url, cookies, timeout, user_agent):
            return 200, [(ACCESS_TOKEN_COOKIE, token)], {}

        refresher = CookieRefresher(http_get=mock_get)
        result = refresher.refresh(_stored(), max_attempts=3, retry_delay=0)
        assert result.success
        assert result.attempts_used == 1

    def test_success_on_second_attempt(self):
        token = _valid_token()
        call_count = 0

        def mock_get(url, cookies, timeout, user_agent):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return 500, [], {}
            return 200, [(ACCESS_TOKEN_COOKIE, token)], {}

        refresher = CookieRefresher(http_get=mock_get)
        result = refresher.refresh(_stored(), max_attempts=3, retry_delay=0)
        assert result.success
        assert result.attempts_used == 2

    def test_all_attempts_fail(self):
        def mock_get(url, cookies, timeout, user_agent):
            return 500, [], {}

        refresher = CookieRefresher(http_get=mock_get)
        result = refresher.refresh(_stored(), max_attempts=3, retry_delay=0)
        assert not result.success
        assert result.attempts_used == 3
        assert "3 attempts" in result.error

    def test_single_attempt(self):
        def mock_get(url, cookies, timeout, user_agent):
            return 500, [], {}

        refresher = CookieRefresher(http_get=mock_get)
        result = refresher.refresh(_stored(), max_attempts=1, retry_delay=0)
        assert not result.success
        assert result.attempts_used == 1


class TestExtractTokenFromResponse:
    def test_from_cookies_list(self):
        refresher = CookieRefresher()
        token = refresher._extract_token_from_response(
            [(ACCESS_TOKEN_COOKIE, "tok123")], {}
        )
        assert token == "tok123"

    def test_from_set_cookie_header(self):
        refresher = CookieRefresher()
        headers = {"Set-Cookie": f"{ACCESS_TOKEN_COOKIE}=tok456; Path=/"}
        token = refresher._extract_token_from_response([], headers)
        assert token == "tok456"

    def test_cookies_take_priority(self):
        refresher = CookieRefresher()
        headers = {"Set-Cookie": f"{ACCESS_TOKEN_COOKIE}=header_tok; Path=/"}
        token = refresher._extract_token_from_response(
            [(ACCESS_TOKEN_COOKIE, "cookie_tok")], headers
        )
        assert token == "cookie_tok"

    def test_no_token_found(self):
        refresher = CookieRefresher()
        token = refresher._extract_token_from_response(
            [("other", "val")], {"Content-Type": "text/html"}
        )
        assert token is None

    def test_set_cookie_without_access_token(self):
        refresher = CookieRefresher()
        headers = {"Set-Cookie": "session=abc; Path=/"}
        token = refresher._extract_token_from_response([], headers)
        assert token is None


class TestApplyRefreshToStored:
    def test_successful_refresh(self):
        token = _valid_token()
        stored = _stored()
        result = RefreshResult(
            success=True,
            new_token=token,
            updated_cookies=[{"name": "new", "value": "v"}],
        )
        updated = apply_refresh_to_stored(stored, result)
        assert updated.access_token == token
        assert updated.is_valid is True
        assert updated.last_error is None
        assert updated.cookies_json == [{"name": "new", "value": "v"}]
        assert updated.access_token_expires_at is not None
        assert updated.last_used_at is not None
        assert updated.updated_at is not None

    def test_failed_refresh(self):
        stored = _stored()
        stored.is_valid = True
        result = RefreshResult(success=False, error="network error")
        updated = apply_refresh_to_stored(stored, result)
        assert updated.is_valid is False
        assert updated.last_error == "network error"

    def test_no_updated_cookies_keeps_original(self):
        token = _valid_token()
        original_cookies = [{"name": "orig", "value": "v"}]
        stored = _stored(cookies=original_cookies)
        result = RefreshResult(success=True, new_token=token, updated_cookies=None)
        updated = apply_refresh_to_stored(stored, result)
        assert updated.cookies_json == original_cookies
