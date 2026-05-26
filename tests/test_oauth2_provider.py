"""Tests for OAuth2Provider."""

import time
from unittest.mock import MagicMock, patch

import pytest

from src.providers.oauth2_provider import OAuth2Provider


def _make_provider(**kwargs) -> OAuth2Provider:
    defaults = {
        "client_id": "test_client",
        "client_secret": "test_secret",
        "auth_url": "https://auth.example.com/authorize",
        "token_url": "https://auth.example.com/token",
        "redirect_uri": "https://app.example.com/callback",
        "scopes": ["read", "write"],
    }
    defaults.update(kwargs)
    return OAuth2Provider(**defaults)


class TestOAuth2Provider:
    def test_auth_type_is_oauth2(self):
        from src.providers.base import AuthType
        provider = _make_provider()
        assert provider.auth_type == AuthType.OAUTH2

    def test_get_authorization_url_contains_params(self):
        provider = _make_provider()
        url = provider.get_authorization_url(state="xyz")
        assert "response_type=code" in url
        assert "client_id=test_client" in url
        assert "state=xyz" in url
        assert "scope=read+write" in url

    def test_authenticate_without_code_returns_false_initially(self):
        provider = _make_provider()
        assert provider.authenticate() is False

    @patch("src.providers.oauth2_provider.requests.Session.post")
    def test_authenticate_with_code_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "at_123",
            "refresh_token": "rt_456",
            "expires_in": 3600,
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        provider = _make_provider()
        assert provider.authenticate(authorization_code="auth_code_here") is True
        assert provider.get_token() == "at_123"
        assert provider.is_valid() is True

    @patch("src.providers.oauth2_provider.requests.Session.post")
    def test_authenticate_with_code_failure(self, mock_post):
        mock_post.side_effect = Exception("network error")
        provider = _make_provider()
        assert provider.authenticate(authorization_code="bad_code") is False

    @patch("src.providers.oauth2_provider.requests.Session.post")
    def test_refresh_token_flow(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "access_token": "at_new",
            "refresh_token": "rt_new",
            "expires_in": 3600,
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        provider = _make_provider()
        provider.load_tokens("at_old", "rt_old", time.time() - 100)
        assert provider.is_valid() is False
        assert provider.refresh() is True
        assert provider.is_valid() is True

    def test_refresh_without_refresh_token(self):
        provider = _make_provider()
        provider.load_tokens("at_old", "", time.time() - 100)
        assert provider.refresh() is False

    def test_load_tokens(self):
        provider = _make_provider()
        provider.load_tokens("at", "rt", time.time() + 3600)
        assert provider.is_valid() is True
        assert provider.get_token() == "at"
