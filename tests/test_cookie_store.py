"""Tests for cookie store functions."""
import pytest
from datetime import datetime, timezone
from src.cookies.cookie_store import (
    StoredCookies,
    extract_cookie_value,
    get_cookie_expiration,
    cookies_to_dict,
    extract_account_hash_from_cookies,
    merge_response_cookies,
    validate_required_tokens,
    validate_account_match,
    SESSION_TOKEN_COOKIE,
    ACCESS_TOKEN_COOKIE,
    PUBLISHER_ID_COOKIE,
)


def _cookies(*items):
    """Build a cookie list from (name, value) tuples."""
    return [{"name": n, "value": v} for n, v in items]


class TestExtractCookieValue:
    def test_existing_cookie(self):
        cookies = _cookies(("a", "1"), ("b", "2"))
        assert extract_cookie_value(cookies, "a") == "1"
        assert extract_cookie_value(cookies, "b") == "2"

    def test_missing_cookie(self):
        cookies = _cookies(("a", "1"))
        assert extract_cookie_value(cookies, "x") is None

    def test_empty_list(self):
        assert extract_cookie_value([], "x") is None

    def test_cookie_with_empty_value(self):
        cookies = [{"name": "a", "value": ""}]
        assert extract_cookie_value(cookies, "a") == ""

    def test_duplicate_names_returns_first(self):
        cookies = _cookies(("a", "first"), ("a", "second"))
        assert extract_cookie_value(cookies, "a") == "first"


class TestGetCookieExpiration:
    def test_with_expiration_date(self):
        cookies = [{"name": "token", "value": "x", "expirationDate": 1700000000}]
        exp = get_cookie_expiration(cookies, "token")
        assert exp is not None
        assert exp.tzinfo == timezone.utc
        assert abs(exp.timestamp() - 1700000000) < 1

    def test_without_expiration_date(self):
        cookies = [{"name": "token", "value": "x"}]
        assert get_cookie_expiration(cookies, "token") is None

    def test_missing_cookie(self):
        cookies = [{"name": "other", "value": "x", "expirationDate": 1700000000}]
        assert get_cookie_expiration(cookies, "token") is None

    def test_empty_list(self):
        assert get_cookie_expiration([], "token") is None


class TestCookiesToDict:
    def test_basic_conversion(self):
        cookies = _cookies(("a", "1"), ("b", "2"), ("c", "3"))
        result = cookies_to_dict(cookies)
        assert result == {"a": "1", "b": "2", "c": "3"}

    def test_skips_missing_name(self):
        cookies = [{"value": "orphan"}, {"name": "ok", "value": "v"}]
        result = cookies_to_dict(cookies)
        assert result == {"ok": "v"}

    def test_skips_missing_value(self):
        cookies = [{"name": "novalue"}, {"name": "ok", "value": "v"}]
        result = cookies_to_dict(cookies)
        assert result == {"ok": "v"}

    def test_empty_list(self):
        assert cookies_to_dict([]) == {}

    def test_duplicate_names_last_wins(self):
        cookies = _cookies(("a", "first"), ("a", "second"))
        result = cookies_to_dict(cookies)
        assert result == {"a": "second"}


class TestExtractAccountHash:
    def test_standard_publisher_id(self):
        cookies = _cookies((PUBLISHER_ID_COOKIE, "w67de45e456x000000000000000000"))
        assert extract_account_hash_from_cookies(cookies) == "w67de45e456x"

    def test_no_trailing_zeros(self):
        cookies = _cookies((PUBLISHER_ID_COOKIE, "abcdef123"))
        assert extract_account_hash_from_cookies(cookies) == "abcdef123"

    def test_all_zeros(self):
        cookies = _cookies((PUBLISHER_ID_COOKIE, "0000000000"))
        assert extract_account_hash_from_cookies(cookies) is None

    def test_no_publisher_id(self):
        cookies = _cookies(("other", "value"))
        assert extract_account_hash_from_cookies(cookies) is None

    def test_empty_list(self):
        assert extract_account_hash_from_cookies([]) is None

    def test_single_trailing_zero(self):
        cookies = _cookies((PUBLISHER_ID_COOKIE, "hash0"))
        assert extract_account_hash_from_cookies(cookies) == "hash"


class TestMergeResponseCookies:
    def test_update_existing(self):
        original = _cookies(("a", "old"), ("b", "keep"))
        response = [("a", "new")]
        result = merge_response_cookies(original, response)
        by_name = {c["name"]: c["value"] for c in result}
        assert by_name["a"] == "new"
        assert by_name["b"] == "keep"

    def test_add_new_cookie(self):
        original = _cookies(("a", "1"))
        response = [("b", "2")]
        result = merge_response_cookies(original, response)
        by_name = {c["name"]: c["value"] for c in result}
        assert by_name["a"] == "1"
        assert by_name["b"] == "2"

    def test_empty_original(self):
        result = merge_response_cookies([], [("a", "1")])
        assert len(result) == 1
        assert result[0]["name"] == "a"

    def test_empty_response(self):
        original = _cookies(("a", "1"))
        result = merge_response_cookies(original, [])
        assert len(result) == 1

    def test_preserves_extra_fields(self):
        original = [{"name": "a", "value": "old", "domain": ".test.com", "path": "/"}]
        response = [("a", "new")]
        result = merge_response_cookies(original, response)
        assert result[0]["value"] == "new"
        assert result[0]["domain"] == ".test.com"


class TestValidateRequiredTokens:
    def test_session_token_present(self):
        cookies = _cookies((SESSION_TOKEN_COOKIE, "token123"))
        errors = validate_required_tokens(cookies)
        assert errors == []

    def test_session_token_missing(self):
        cookies = _cookies(("other", "value"))
        errors = validate_required_tokens(cookies)
        assert len(errors) == 1
        assert SESSION_TOKEN_COOKIE in errors[0]

    def test_empty_cookies(self):
        errors = validate_required_tokens([])
        assert len(errors) == 1


class TestValidateAccountMatch:
    def test_matching_hash(self):
        cookies = _cookies((PUBLISHER_ID_COOKIE, "myhash00000000"))
        assert validate_account_match(cookies, "myhash") is None

    def test_mismatched_hash(self):
        cookies = _cookies((PUBLISHER_ID_COOKIE, "wrong00000000"))
        error = validate_account_match(cookies, "expected")
        assert error is not None
        assert "wrong" in error
        assert "expected" in error

    def test_no_publisher_id_returns_none(self):
        cookies = _cookies(("other", "val"))
        assert validate_account_match(cookies, "hash") is None


class TestStoredCookies:
    def test_default_values(self):
        sc = StoredCookies(account_hash="abc")
        assert sc.account_hash == "abc"
        assert sc.cookies_json == []
        assert sc.is_valid is True
        assert sc.access_token is None
        assert sc.last_error is None

    def test_with_all_fields(self):
        now = datetime.now(timezone.utc)
        sc = StoredCookies(
            account_hash="abc",
            cookies_json=[{"name": "a", "value": "1"}],
            access_token="tok",
            session_token="sess",
            access_token_expires_at=now,
            session_expires_at=now,
            is_valid=False,
            last_error="some error",
            last_used_at=now,
            created_at=now,
            updated_at=now,
        )
        assert sc.is_valid is False
        assert sc.last_error == "some error"
        assert sc.access_token == "tok"
