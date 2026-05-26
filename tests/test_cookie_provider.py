"""Tests for CookieAuthProvider."""

import base64
import json
import time

import pytest

from src.providers.cookie_provider import CookieAuthProvider


def _make_jwt(payload: dict, header: dict | None = None) -> str:
    """Build a fake JWT (header.payload.signature) for testing."""
    header = header or {"alg": "HS256", "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.fake_signature"


class TestCookieAuthProvider:
    def test_authenticate_with_known_cookie_name(self):
        token = _make_jwt({"sub": "user1", "exp": time.time() + 3600})
        provider = CookieAuthProvider({"access_token": token})
        assert provider.authenticate() is True
        assert provider.get_token() == token

    def test_authenticate_with_custom_cookie_name(self):
        token = _make_jwt({"sub": "user1", "exp": time.time() + 3600})
        provider = CookieAuthProvider({"my_token": token}, token_cookie_name="my_token")
        assert provider.authenticate() is True

    def test_authenticate_fails_no_matching_cookie(self):
        provider = CookieAuthProvider({"session_id": "abc123"})
        assert provider.authenticate() is False

    def test_is_valid_with_future_expiry(self):
        token = _make_jwt({"exp": time.time() + 3600})
        provider = CookieAuthProvider({"access_token": token})
        provider.authenticate()
        assert provider.is_valid() is True

    def test_is_valid_with_expired_token(self):
        token = _make_jwt({"exp": time.time() - 100})
        provider = CookieAuthProvider({"access_token": token})
        provider.authenticate()
        assert provider.is_valid() is False

    def test_get_token_returns_none_when_expired(self):
        token = _make_jwt({"exp": time.time() - 100})
        provider = CookieAuthProvider({"access_token": token})
        provider.authenticate()
        assert provider.get_token() is None

    def test_is_valid_with_no_exp_claim(self):
        token = _make_jwt({"sub": "user1"})
        provider = CookieAuthProvider({"access_token": token})
        provider.authenticate()
        assert provider.is_valid() is True

    def test_non_jwt_token_no_expiry(self):
        provider = CookieAuthProvider({"access_token": "plain-api-key"})
        provider.authenticate()
        assert provider.is_valid() is True

    def test_auth_type_is_cookie(self):
        provider = CookieAuthProvider({})
        from src.providers.base import AuthType
        assert provider.auth_type == AuthType.COOKIE

    def test_get_auth_header(self):
        token = _make_jwt({"exp": time.time() + 3600})
        provider = CookieAuthProvider({"access_token": token})
        provider.authenticate()
        header = provider.get_auth_header()
        assert header == {"Authorization": f"Bearer {token}"}
