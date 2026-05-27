# Marketplace Auth Manager
> **Portfolio context:** Extracted from founder-led production systems — multi-marketplace inventory, orders, and warehouse execution. **[Full portfolio](https://github.com/AspiranteD/AspiranteD)** · [aspiranted.github.io](https://aspiranted.github.io)

Multi-account authentication library for cookie-based marketplace APIs. Manages the full lifecycle: JWT decoding, cookie storage/validation, automatic token refresh via session cookies, and thread-safe multi-account coordination.

Extracted from a production system that manages 10+ marketplace accounts simultaneously.

## Architecture

```
src/
+-- token/
¦   +-- jwt_utils.py          # JWT payload decoding (no signature verification)
+-- cookies/
¦   +-- cookie_store.py        # Cookie storage, extraction, hash matching
¦   +-- cookie_refresher.py    # Token refresh via session cookies with retry
+-- accounts/
    +-- account_manager.py     # Thread-safe multi-account coordination
```

## Key Features

### JWT Payload Decoding (`jwt_utils.py`)
- Decodes JWT payloads without signature verification (we only need expiration checks)
- Base64url decoding with automatic padding correction
- Extracts arbitrary claims from tokens

### Cookie Store (`cookie_store.py`)
- Parses **Cookie Editor** browser extension JSON export format
- Extracts account hash from `publisherId` cookie (strips trailing zeros)
- Validates cookie sets for required tokens (`session-token`)
- Cross-checks cookies against expected account hash to prevent account mixups
- Merges response cookies back into stored cookies after refresh

### Token Refresher (`cookie_refresher.py`)
- Refreshes access tokens by hitting the auth endpoint with stored session cookies
- **3-layer token extraction**: response cookies ? `Set-Cookie` headers ? existing valid token fallback
- Configurable retry with delay between attempts
- Framework-agnostic: accepts injectable `http_get` function for testing
- Returns structured `RefreshResult` with success/error details

### Account Manager (`account_manager.py`)
- Thread-safe account registry with lock-protected access
- Callback-driven architecture (no database dependency):
  - `load_accounts_fn` — fetch accounts from any source
  - `load_cookies_fn` — load stored cookies per account
  - `persist_cookies_fn` — save updated cookies
  - `validate_token_fn` — verify token belongs to correct account
- Automatic refresh on expired tokens
- Optional hash validation (API hash must match account hash)
- Legacy method aliases for backward compatibility

## Design Decisions

| Decision | Rationale |
|---|---|
| JWT parsed without verification | Only need expiry tracking — the server validates signatures |
| Callback-driven persistence | Database-agnostic: works with PostgreSQL, SQLite, files, etc. |
| Injectable HTTP client | Makes testing deterministic without mocking `requests` |
| publisherId hash extraction | Prevents saving cookies for the wrong account |
| 3-layer token extraction | Platforms return tokens inconsistently (cookies vs headers) |
| Thread-safe account registry | Production system runs extractors concurrently per account |

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```python
from src.token.jwt_utils import is_token_expired, decode_jwt_payload
from src.cookies.cookie_store import (
    extract_cookie_value, extract_account_hash_from_cookies,
    validate_required_tokens, StoredCookies,
)
from src.cookies.cookie_refresher import CookieRefresher, apply_refresh_to_stored
from src.accounts.account_manager import AccountAuthManager, Account

# 1. Check if a JWT is still valid
if is_token_expired(access_token):
    print("Token expired, need refresh")

# 2. Validate cookies before storing
errors = validate_required_tokens(browser_cookies)
if errors:
    print(f"Missing: {errors}")

# 3. Refresh tokens automatically
refresher = CookieRefresher()
stored = StoredCookies(account_hash="abc", cookies_json=browser_cookies)
result = refresher.refresh(stored, max_attempts=3)
if result.success:
    apply_refresh_to_stored(stored, result)

# 4. Multi-account management
manager = AccountAuthManager(
    load_accounts_fn=lambda: load_from_db(),
    load_cookies_fn=lambda hash: get_cookies(hash),
    persist_cookies_fn=lambda stored: save_cookies(stored),
)
token = manager.get_access_token(account, validate_hash=True)
```

## Running Tests

```bash
pytest tests/ -v
```

101 tests covering JWT decoding, cookie operations, refresh logic, and multi-account coordination.

## License

MIT
