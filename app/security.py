from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.config import get_settings

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def _encode(claims: dict[str, Any], ttl: timedelta, token_type: str) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload = {**claims, "type": token_type, "iat": now, "exp": now + ttl, "jti": secrets.token_hex(8)}
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm)


def create_tokens(user: dict[str, Any]) -> dict[str, Any]:
    s = get_settings()
    claims = {"sub": str(user["user_id"]), "tid": int(user["tenant_id"]), "role": user["role"], "email": user["email"]}
    return {
        "access_token": _encode(claims, timedelta(minutes=s.access_token_minutes), "access"),
        "refresh_token": _encode(claims, timedelta(days=s.refresh_token_days), "refresh"),
        "token_type": "bearer",
        "expires_in": s.access_token_minutes * 60,
    }


def decode_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    s = get_settings()
    payload = jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_algorithm])
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError("wrong token type")
    return payload


def new_webhook_secret() -> str:
    # Standard Webhooks format: "whsec_" + base64 of the raw key bytes.
    return "whsec_" + base64.b64encode(secrets.token_bytes(24)).decode()


API_KEY_PREFIX = "prv_"


def new_api_key() -> tuple[str, str, str]:
    """Return (key_id, secret, full_token). Only key_id and sha256(secret) are stored."""
    key_id = secrets.token_hex(6)  # 12 hex chars, public part
    secret = secrets.token_urlsafe(32)
    return key_id, secret, f"{API_KEY_PREFIX}{key_id}_{secret}"


def hash_api_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()
