"""
Cookie storage and extraction.

Manages browser-exported cookies (Cookie Editor JSON format),
extracting specific tokens, computing expiration dates, and
converting between list-of-dicts and flat-dict formats.

Also handles account hash extraction from publisherId cookies
and merging updated cookies from HTTP responses.
"""
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional


PUBLISHER_ID_COOKIE = "publisherId"
ACCESS_TOKEN_COOKIE = "accessToken"
SESSION_TOKEN_COOKIE = "__Secure-next-auth.session-token"


@dataclass
class StoredCookies:
    account_hash: str
    cookies_json: list[dict] = field(default_factory=list)
    access_token: Optional[str] = None
    session_token: Optional[str] = None
    access_token_expires_at: Optional[datetime] = None
    session_expires_at: Optional[datetime] = None
    is_valid: bool = True
    last_error: Optional[str] = None
    last_used_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


def extract_cookie_value(cookies: list[dict], name: str) -> Optional[str]:
    """Extract a cookie value by name from Cookie Editor format."""
    for cookie in cookies:
        if cookie.get("name") == name:
            return cookie.get("value")
    return None


def get_cookie_expiration(cookies: list[dict], name: str) -> Optional[datetime]:
    """Get the expiration datetime of a specific cookie."""
    for cookie in cookies:
        if cookie.get("name") == name:
            exp = cookie.get("expirationDate")
            if exp:
                return datetime.fromtimestamp(exp, tz=timezone.utc)
    return None


def cookies_to_dict(cookies: list[dict]) -> dict[str, str]:
    """Convert Cookie Editor list format to {name: value} dict."""
    result = {}
    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if name and value:
            result[name] = value
    return result


def extract_account_hash_from_cookies(cookies: list[dict]) -> Optional[str]:
    """
    Extract account hash from publisherId cookie.

    publisherId format: w67de45e456x000000000000000000000000000000
    The account_hash is the part before the trailing zeros.
    """
    publisher_id = extract_cookie_value(cookies, PUBLISHER_ID_COOKIE)
    if not publisher_id:
        return None
    hash_part = publisher_id.rstrip("0")
    return hash_part if hash_part else None


def merge_response_cookies(
    original: list[dict], response_cookies: list[tuple[str, str]]
) -> list[dict]:
    """
    Merge response cookies into the original cookie list.

    Updates existing cookies and adds new ones from the HTTP response.
    response_cookies is a list of (name, value) tuples.
    """
    updated = {}
    for cookie in original:
        name = cookie.get("name")
        if name:
            updated[name] = cookie.copy()

    for name, value in response_cookies:
        if name in updated:
            updated[name]["value"] = value
        else:
            updated[name] = {"name": name, "value": value}

    return list(updated.values())


def validate_required_tokens(cookies: list[dict]) -> list[str]:
    """
    Validate that required tokens are present in the cookie set.

    Returns list of error messages. Empty list = all required present.
    """
    errors = []
    session_token = extract_cookie_value(cookies, SESSION_TOKEN_COOKIE)
    if not session_token:
        errors.append(
            f"Missing required cookie: {SESSION_TOKEN_COOKIE}. "
            "Ensure you are logged in and exported ALL cookies."
        )
    return errors


def validate_account_match(
    cookies: list[dict], expected_hash: str
) -> Optional[str]:
    """
    Validate that cookies belong to the expected account.

    Returns error message if mismatch, None if OK or can't verify.
    """
    cookies_hash = extract_account_hash_from_cookies(cookies)
    if cookies_hash and cookies_hash != expected_hash:
        return (
            f"Cookies belong to account '{cookies_hash}' "
            f"but expected '{expected_hash}'"
        )
    return None
