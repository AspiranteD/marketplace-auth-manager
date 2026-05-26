"""Simple API key authentication provider.

Used for platforms that authenticate via a static API key
sent in a header (e.g. X-API-Key).
"""

from typing import Optional

from .base import AuthProvider, AuthType


class ApiKeyProvider(AuthProvider):
    """Static API key authentication.

    The simplest provider: wraps a pre-issued API key and injects it
    into requests via a custom header. Supports optional key rotation
    by replacing the key at runtime.
    """

    def __init__(self, api_key: str, header_name: str = "X-API-Key"):
        self._api_key = api_key
        self._header_name = header_name
        self._active = True

    @property
    def auth_type(self) -> AuthType:
        return AuthType.API_KEY

    def authenticate(self) -> bool:
        self._active = bool(self._api_key)
        return self._active

    def get_token(self) -> Optional[str]:
        if self._active and self._api_key:
            return self._api_key
        return None

    def is_valid(self) -> bool:
        return self._active and bool(self._api_key)

    def refresh(self) -> bool:
        return self.is_valid()

    def rotate_key(self, new_key: str) -> None:
        """Replace the API key (e.g. after scheduled rotation)."""
        self._api_key = new_key
        self._active = True

    def get_auth_header(self) -> Optional[dict]:
        token = self.get_token()
        if not token:
            return None
        return {self._header_name: token}
