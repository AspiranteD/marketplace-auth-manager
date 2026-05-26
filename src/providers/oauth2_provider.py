"""OAuth2 authorization code grant provider.

Implements the full OAuth2 flow used by platforms like eBay:
authorization URL generation, code exchange, token storage with expiry
tracking, and automatic refresh via refresh tokens.
"""

import time
import urllib.parse
from typing import Optional

import requests

from .base import AuthProvider, AuthType


class OAuth2Provider(AuthProvider):
    """OAuth2 Authorization Code Grant with automatic token refresh.

    Handles the complete lifecycle: authorization URL generation → code exchange
    → access token caching → silent refresh when expired.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        auth_url: str,
        token_url: str,
        redirect_uri: str,
        scopes: Optional[list[str]] = None,
    ):
        self._client_id = client_id
        self._client_secret = client_secret
        self._auth_url = auth_url
        self._token_url = token_url
        self._redirect_uri = redirect_uri
        self._scopes = scopes or []

        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expiry: float = 0
        self._session = requests.Session()

    @property
    def auth_type(self) -> AuthType:
        return AuthType.OAUTH2

    def get_authorization_url(self, state: Optional[str] = None) -> str:
        """Build the URL the user must visit to authorize the application."""
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
        }
        if self._scopes:
            params["scope"] = " ".join(self._scopes)
        if state:
            params["state"] = state
        return f"{self._auth_url}?{urllib.parse.urlencode(params)}"

    def authenticate(self, authorization_code: Optional[str] = None) -> bool:
        """Exchange an authorization code for access + refresh tokens."""
        if not authorization_code:
            return self._access_token is not None and self.is_valid()

        data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": self._redirect_uri,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        return self._request_token(data)

    def get_token(self) -> Optional[str]:
        if not self._access_token:
            return None
        if not self.is_valid():
            if not self.refresh():
                return None
        return self._access_token

    def is_valid(self) -> bool:
        if not self._access_token:
            return False
        return time.time() < self._token_expiry

    def refresh(self) -> bool:
        """Use the refresh token to obtain a new access token."""
        if not self._refresh_token:
            return False
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        return self._request_token(data)

    def load_tokens(
        self, access_token: str, refresh_token: str, expires_at: float
    ) -> None:
        """Restore tokens from persistent storage (skip the auth code exchange)."""
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._token_expiry = expires_at

    def _request_token(self, data: dict) -> bool:
        """POST to the token endpoint and store the response."""
        try:
            resp = self._session.post(self._token_url, data=data, timeout=30)
            resp.raise_for_status()
            body = resp.json()
            self._access_token = body["access_token"]
            self._refresh_token = body.get("refresh_token", self._refresh_token)
            self._token_expiry = time.time() + body.get("expires_in", 3600)
            return True
        except Exception:
            return False
