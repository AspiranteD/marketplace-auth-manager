"""Cookie-based authentication provider.

Extracts bearer tokens from browser cookies (e.g. Wallapop-style platforms
that store JWT access tokens in cookies after browser login).
"""

import base64
import json
import time
from typing import Optional

from .base import AuthProvider, AuthType


class CookieAuthProvider(AuthProvider):
    """Extract and manage bearer tokens embedded in browser cookies.

    Some platforms (e.g. Wallapop) set authentication tokens as HTTP cookies
    after a browser-based login. This provider parses those cookies, extracts
    the JWT-like bearer token, and validates its expiry.
    """

    TOKEN_COOKIE_NAMES = ("_wallapop_session", "access_token", "bearer", "auth_token", "token")

    def __init__(self, cookies: dict, token_cookie_name: Optional[str] = None):
        self._cookies = cookies
        self._token_cookie_name = token_cookie_name
        self._token: Optional[str] = None
        self._token_expiry: Optional[float] = None

    @property
    def auth_type(self) -> AuthType:
        return AuthType.COOKIE

    def authenticate(self) -> bool:
        """Extract and validate a bearer token from the provided cookies."""
        token = self._extract_token()
        if not token:
            return False

        self._token = token
        self._token_expiry = self._extract_expiry(token)
        return True

    def get_token(self) -> Optional[str]:
        if self._token and self.is_valid():
            return self._token
        return None

    def is_valid(self) -> bool:
        if not self._token:
            return False
        if self._token_expiry is None:
            return True
        return time.time() < self._token_expiry

    def refresh(self) -> bool:
        """Re-extract token from cookies (cookies must be updated externally)."""
        return self.authenticate()

    def _extract_token(self) -> Optional[str]:
        """Find the bearer token among known cookie names."""
        if self._token_cookie_name:
            return self._cookies.get(self._token_cookie_name)

        for name in self.TOKEN_COOKIE_NAMES:
            if name in self._cookies:
                return self._cookies[name]
        return None

    @staticmethod
    def _extract_expiry(token: str) -> Optional[float]:
        """Decode the JWT payload to read the `exp` claim without signature verification."""
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return float(payload["exp"]) if "exp" in payload else None
        except (ValueError, KeyError, json.JSONDecodeError):
            return None
