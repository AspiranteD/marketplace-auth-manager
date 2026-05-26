"""Abstract base class for authentication providers."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional


class AuthType(Enum):
    COOKIE = "cookie"
    OAUTH2 = "oauth2"
    API_KEY = "api_key"
    BEARER = "bearer"


class AuthProvider(ABC):
    """Base authentication provider defining the interface all providers must implement.

    Each provider encapsulates a single authentication strategy (cookie extraction,
    OAuth2 flow, API key) and exposes a uniform interface for token lifecycle management.
    """

    @property
    @abstractmethod
    def auth_type(self) -> AuthType:
        """Return the authentication type this provider handles."""

    @abstractmethod
    def authenticate(self) -> bool:
        """Perform initial authentication. Returns True on success."""

    @abstractmethod
    def get_token(self) -> Optional[str]:
        """Return the current valid token, or None if unavailable."""

    @abstractmethod
    def is_valid(self) -> bool:
        """Check whether the current token is still valid."""

    @abstractmethod
    def refresh(self) -> bool:
        """Attempt to refresh the token. Returns True on success."""

    def get_auth_header(self) -> Optional[dict]:
        """Build the Authorization header dict for HTTP requests."""
        token = self.get_token()
        if not token:
            return None

        if self.auth_type == AuthType.API_KEY:
            return {"X-API-Key": token}
        return {"Authorization": f"Bearer {token}"}
