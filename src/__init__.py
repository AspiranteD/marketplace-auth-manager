"""Marketplace Auth Manager - Multi-platform authentication management."""

from .providers.base import AuthProvider, AuthType
from .providers.cookie_provider import CookieAuthProvider
from .providers.oauth2_provider import OAuth2Provider
from .providers.apikey_provider import ApiKeyProvider
from .accounts.account_manager import AccountManager
from .accounts.account_rotator import AccountRotator
from .storage.credential_store import CredentialStore
from .middleware.auth_middleware import AuthMiddleware

__version__ = "1.0.0"
__all__ = [
    "AuthProvider",
    "AuthType",
    "CookieAuthProvider",
    "OAuth2Provider",
    "ApiKeyProvider",
    "AccountManager",
    "AccountRotator",
    "CredentialStore",
    "AuthMiddleware",
]
