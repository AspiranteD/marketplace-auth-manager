"""
JWT utilities for marketplace authentication.

Decodes JWT payloads without signature verification (used to check
expiration and extract claims from access tokens issued by the platform).
"""
import base64
import json
from datetime import datetime, timezone
from typing import Optional


def decode_jwt_payload(token: str) -> Optional[dict]:
    """
    Decode JWT payload without verifying the signature.

    Only inspects the payload (part 2 of 3) for claims like 'exp'.
    Does NOT verify the signature - this is intentional since we
    just need to check expiration before making API calls.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_json = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_json)
    except Exception:
        return None


def get_jwt_expiration(token: str) -> Optional[datetime]:
    """Get the expiration datetime from a JWT's 'exp' claim."""
    payload = decode_jwt_payload(token)
    if not payload:
        return None
    exp = payload.get("exp")
    if not exp:
        return None
    return datetime.fromtimestamp(exp, tz=timezone.utc)


def is_token_expired(token: str) -> bool:
    """Check if a JWT has expired. Returns True if expired or unparseable."""
    exp_date = get_jwt_expiration(token)
    if not exp_date:
        return True
    return datetime.now(timezone.utc) >= exp_date


def get_jwt_claim(token: str, claim: str) -> Optional[str]:
    """Extract a specific claim from a JWT payload."""
    payload = decode_jwt_payload(token)
    if not payload:
        return None
    return payload.get(claim)
