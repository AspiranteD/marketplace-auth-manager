"""Tests for AuthMiddleware."""

from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import requests

from src.middleware.auth_middleware import AuthMiddleware
from src.providers.base import AuthProvider, AuthType


def _mock_provider(token: str = "test_token", valid: bool = True, refresh_ok: bool = True):
    provider = MagicMock(spec=AuthProvider)
    provider.auth_type = AuthType.BEARER
    provider.get_token.return_value = token if valid else None
    provider.is_valid.return_value = valid
    provider.refresh.return_value = refresh_ok
    provider.get_auth_header.return_value = {"Authorization": f"Bearer {token}"} if valid else None
    return provider


class TestAuthMiddleware:
    def test_prepare_request_injects_header(self):
        provider = _mock_provider()
        mw = AuthMiddleware(provider)
        req = requests.Request("GET", "https://api.example.com/items").prepare()
        mw.prepare_request(req)
        assert req.headers["Authorization"] == "Bearer test_token"

    def test_prepare_request_no_header_when_invalid(self):
        provider = _mock_provider(valid=False)
        mw = AuthMiddleware(provider)
        req = requests.Request("GET", "https://api.example.com/items").prepare()
        mw.prepare_request(req)
        assert "Authorization" not in req.headers

    @patch("requests.Session.request")
    def test_send_injects_auth(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        provider = _mock_provider()
        mw = AuthMiddleware(provider)
        session = requests.Session()
        resp = mw.send(session, "GET", "https://api.example.com/items")

        assert resp.status_code == 200
        call_kwargs = mock_request.call_args
        assert call_kwargs[1]["headers"]["Authorization"] == "Bearer test_token"

    @patch("requests.Session.request")
    def test_retry_on_401_with_refresh(self, mock_request):
        resp_401 = MagicMock()
        resp_401.status_code = 401
        resp_200 = MagicMock()
        resp_200.status_code = 200
        mock_request.side_effect = [resp_401, resp_200]

        provider = _mock_provider()
        provider.refresh.return_value = True
        mw = AuthMiddleware(provider)
        session = requests.Session()
        resp = mw.send(session, "GET", "https://api.example.com/items")

        assert resp.status_code == 200
        assert provider.refresh.called

    @patch("requests.Session.request")
    def test_no_retry_when_refresh_fails(self, mock_request):
        resp_401 = MagicMock()
        resp_401.status_code = 401
        mock_request.return_value = resp_401

        provider = _mock_provider(refresh_ok=False)
        provider.refresh.return_value = False
        mw = AuthMiddleware(provider)
        session = requests.Session()
        resp = mw.send(session, "GET", "https://api.example.com/items")

        assert resp.status_code == 401

    @patch("requests.Session.request")
    def test_get_convenience_method(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        provider = _mock_provider()
        mw = AuthMiddleware(provider)
        session = requests.Session()
        resp = mw.get(session, "https://api.example.com/items")
        assert resp.status_code == 200

    @patch("requests.Session.request")
    def test_post_convenience_method(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_request.return_value = mock_response

        provider = _mock_provider()
        mw = AuthMiddleware(provider)
        session = requests.Session()
        resp = mw.post(session, "https://api.example.com/items", json={"name": "test"})
        assert resp.status_code == 201

    def test_provider_property(self):
        provider = _mock_provider()
        mw = AuthMiddleware(provider)
        assert mw.provider is provider
