"""Tests for JWT utilities."""
import base64
import json
import time
import pytest
from datetime import datetime, timezone, timedelta
from src.token.jwt_utils import (
    decode_jwt_payload,
    get_jwt_expiration,
    is_token_expired,
    get_jwt_claim,
)


def _make_jwt(payload: dict) -> str:
    """Build a fake JWT with the given payload (no signature verification)."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"fake-signature").decode().rstrip("=")
    return f"{header}.{body}.{sig}"


class TestDecodeJwtPayload:
    def test_valid_token(self):
        token = _make_jwt({"sub": "user123", "exp": 9999999999})
        payload = decode_jwt_payload(token)
        assert payload is not None
        assert payload["sub"] == "user123"
        assert payload["exp"] == 9999999999

    def test_invalid_token_not_three_parts(self):
        assert decode_jwt_payload("not.a.valid.jwt.token") is None
        assert decode_jwt_payload("only-one-part") is None
        assert decode_jwt_payload("") is None

    def test_invalid_base64(self):
        assert decode_jwt_payload("a.!!!invalid!!!.c") is None

    def test_payload_with_padding_needed(self):
        payload = {"a": "b" * 100}
        token = _make_jwt(payload)
        result = decode_jwt_payload(token)
        assert result is not None
        assert result["a"] == "b" * 100

    def test_empty_payload(self):
        token = _make_jwt({})
        result = decode_jwt_payload(token)
        assert result == {}

    def test_nested_payload(self):
        payload = {"user": {"name": "test", "roles": ["admin", "user"]}}
        token = _make_jwt(payload)
        result = decode_jwt_payload(token)
        assert result["user"]["name"] == "test"
        assert "admin" in result["user"]["roles"]


class TestGetJwtExpiration:
    def test_with_exp_claim(self):
        future_ts = int(time.time()) + 3600
        token = _make_jwt({"exp": future_ts})
        exp = get_jwt_expiration(token)
        assert exp is not None
        assert exp.tzinfo == timezone.utc
        assert abs(exp.timestamp() - future_ts) < 1

    def test_without_exp_claim(self):
        token = _make_jwt({"sub": "user"})
        assert get_jwt_expiration(token) is None

    def test_invalid_token(self):
        assert get_jwt_expiration("garbage") is None

    def test_past_exp(self):
        past_ts = int(time.time()) - 3600
        token = _make_jwt({"exp": past_ts})
        exp = get_jwt_expiration(token)
        assert exp is not None
        assert exp < datetime.now(timezone.utc)


class TestIsTokenExpired:
    def test_future_token_not_expired(self):
        future_ts = int(time.time()) + 3600
        token = _make_jwt({"exp": future_ts})
        assert is_token_expired(token) is False

    def test_past_token_expired(self):
        past_ts = int(time.time()) - 3600
        token = _make_jwt({"exp": past_ts})
        assert is_token_expired(token) is True

    def test_no_exp_means_expired(self):
        token = _make_jwt({"sub": "user"})
        assert is_token_expired(token) is True

    def test_invalid_token_means_expired(self):
        assert is_token_expired("not-a-jwt") is True

    def test_just_expired(self):
        ts = int(time.time()) - 1
        token = _make_jwt({"exp": ts})
        assert is_token_expired(token) is True


class TestGetJwtClaim:
    def test_existing_claim(self):
        token = _make_jwt({"sub": "user123", "email": "a@b.com"})
        assert get_jwt_claim(token, "sub") == "user123"
        assert get_jwt_claim(token, "email") == "a@b.com"

    def test_missing_claim(self):
        token = _make_jwt({"sub": "user123"})
        assert get_jwt_claim(token, "email") is None

    def test_invalid_token(self):
        assert get_jwt_claim("bad", "sub") is None

    def test_numeric_claim_returned_as_is(self):
        token = _make_jwt({"exp": 12345})
        assert get_jwt_claim(token, "exp") == 12345
