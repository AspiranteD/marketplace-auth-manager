"""
Token refresh via session cookies.

Uses stored session cookies to request a fresh access token from
the platform's auth endpoint. Handles:
  - Building a requests session from stored cookies
  - Extracting the new access token from response cookies or Set-Cookie headers
  - Falling back to the existing token if still valid
  - Merging updated response cookies back into storage
  - Retry logic with configurable attempts
"""
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Callable, Dict, List, Tuple

from src.token.jwt_utils import is_token_expired, get_jwt_expiration
from src.cookies.cookie_store import (
    StoredCookies,
    ACCESS_TOKEN_COOKIE,
    cookies_to_dict,
    merge_response_cookies,
)

DEFAULT_REFRESH_ENDPOINT = "https://es.wallapop.com/api/auth/session"
DEFAULT_TIMEOUT = 15
DEFAULT_RETRY_DELAY = 2
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


@dataclass
class RefreshResult:
    """Result of a token refresh attempt."""
    success: bool
    new_token: Optional[str] = None
    updated_cookies: Optional[list] = None
    error: Optional[str] = None
    attempts_used: int = 0


class CookieRefresher:
    """
    Refreshes access tokens using stored session cookies.

    Architecture: framework-agnostic. Accepts a `persist_fn` callback
    to persist updated cookies and tokens to whatever storage backend
    the caller uses (database, file, etc.).
    """

    def __init__(
        self,
        refresh_endpoint: str = DEFAULT_REFRESH_ENDPOINT,
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        http_get: Optional[Callable] = None,
    ):
        self.refresh_endpoint = refresh_endpoint
        self.timeout = timeout
        self.user_agent = user_agent
        self._http_get = http_get

    def refresh(
        self,
        stored: StoredCookies,
        max_attempts: int = 3,
        retry_delay: float = DEFAULT_RETRY_DELAY,
    ) -> RefreshResult:
        """
        Attempt to refresh the access token.

        Tries up to max_attempts times, with retry_delay seconds between.
        """
        last_error = None

        for attempt in range(1, max_attempts + 1):
            result = self._single_refresh(stored)
            if result.success:
                result.attempts_used = attempt
                return result
            last_error = result.error
            if attempt < max_attempts:
                time.sleep(retry_delay)

        return RefreshResult(
            success=False,
            error=f"Failed after {max_attempts} attempts: {last_error}",
            attempts_used=max_attempts,
        )

    def _single_refresh(self, stored: StoredCookies) -> RefreshResult:
        """Execute a single refresh attempt."""
        try:
            cookies_dict = cookies_to_dict(stored.cookies_json)

            response_status, response_cookies, response_headers = self._do_request(
                cookies_dict
            )

            if response_status != 200:
                is_auth_error = response_status in (401, 403)
                return RefreshResult(
                    success=False,
                    error=f"HTTP {response_status}{' (auth error)' if is_auth_error else ''}",
                )

            new_token = self._extract_token_from_response(
                response_cookies, response_headers
            )

            if not new_token and stored.access_token:
                if not is_token_expired(stored.access_token):
                    new_token = stored.access_token

            if not new_token:
                return RefreshResult(
                    success=False,
                    error="No access token found in response cookies or headers",
                )

            merged = merge_response_cookies(
                stored.cookies_json,
                response_cookies,
            )

            return RefreshResult(
                success=True,
                new_token=new_token,
                updated_cookies=merged,
            )

        except TimeoutError:
            return RefreshResult(success=False, error="Request timeout")
        except Exception as e:
            return RefreshResult(success=False, error=str(e))

    def _do_request(
        self, cookies_dict: Dict[str, str]
    ) -> Tuple[int, List[Tuple[str, str]], Dict[str, str]]:
        """
        Execute the HTTP request. Uses injected http_get if provided,
        otherwise uses requests library.

        Returns (status_code, response_cookies_list, response_headers).
        """
        if self._http_get:
            return self._http_get(
                self.refresh_endpoint, cookies_dict, self.timeout, self.user_agent
            )

        import requests

        session = requests.Session()
        for name, value in cookies_dict.items():
            session.cookies.set(name, value)

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        }

        try:
            resp = session.get(
                self.refresh_endpoint,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
            )
        except requests.exceptions.Timeout:
            raise TimeoutError("Request timed out")

        resp_cookies = [(c.name, c.value) for c in session.cookies]
        resp_headers = dict(resp.headers)

        return resp.status_code, resp_cookies, resp_headers

    def _extract_token_from_response(
        self,
        response_cookies: List[Tuple[str, str]],
        response_headers: Dict[str, str],
    ) -> Optional[str]:
        """
        Extract the access token from the response.

        Search order:
        1. Response cookies (session jar)
        2. Set-Cookie headers
        """
        for name, value in response_cookies:
            if name == ACCESS_TOKEN_COOKIE:
                return value

        for header_name, header_value in response_headers.items():
            if header_name.lower() == "set-cookie":
                if ACCESS_TOKEN_COOKIE in header_value:
                    parts = header_value.split(";")
                    for part in parts:
                        if "=" in part and part.strip().startswith(ACCESS_TOKEN_COOKIE):
                            return part.split("=", 1)[1].strip()

        return None


def apply_refresh_to_stored(
    stored: StoredCookies, result: RefreshResult
) -> StoredCookies:
    """
    Apply a successful refresh result to a StoredCookies object.

    Returns the updated StoredCookies (mutates in place).
    """
    if not result.success or not result.new_token:
        stored.is_valid = False
        stored.last_error = result.error
        return stored

    stored.access_token = result.new_token
    stored.access_token_expires_at = get_jwt_expiration(result.new_token)
    stored.last_used_at = datetime.now(timezone.utc)
    stored.updated_at = datetime.now(timezone.utc)
    stored.last_error = None
    stored.is_valid = True

    if result.updated_cookies:
        stored.cookies_json = result.updated_cookies

    return stored
