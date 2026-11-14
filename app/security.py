"""Cryptographic primitives: passwords, tokens, API keys, secret encryption, checkpoint signatures."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings

ISSUER = "provenance-cloud"

# ---- passwords (Argon2id, library defaults follow RFC 9106's low-memory profile) ------------
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


# ---- access tokens (short-lived JWT) --------------------------------------------------------
def create_access_token(user_id: int, tenant_id: int, token_version: int) -> tuple[str, int]:
    """Return (token, lifetime in seconds). Role is NOT a claim: it is read from the database on
    every request, so a demotion or deactivation takes effect immediately."""
    s = get_settings()
    now = datetime.now(UTC)
    ttl = timedelta(minutes=s.access_token_minutes)
    payload = {"iss": ISSUER, "sub": str(user_id), "tid": tenant_id, "ver": token_version, "typ": "access",
               "iat": now, "exp": now + ttl, "jti": secrets.token_hex(8)}
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm), int(ttl.total_seconds())


def decode_access_token(token: str) -> dict[str, Any]:
    s = get_settings()
    payload = jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_algorithm], issuer=ISSUER,
                         options={"require": ["exp", "iat", "sub", "tid", "ver"]})
    if payload.get("typ") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return payload


# ---- refresh tokens (opaque, stored hashed, rotated on use) ---------------------------------
REFRESH_PREFIX = "prt_"


def new_refresh_token() -> tuple[str, str]:
    """Return (token, sha256 hex). The token is high-entropy, so a fast hash is appropriate."""
    token = REFRESH_PREFIX + secrets.token_urlsafe(48)
    return token, sha256_hex(token)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---- API keys --------------------------------------------------------------------------------
API_KEY_PREFIX = "prv_"


def new_api_key() -> tuple[str, str, str]:
    """Return (key_id, secret, full_token). Only key_id and sha256(secret) are stored."""
    key_id = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    return key_id, secret, f"{API_KEY_PREFIX}{key_id}_{secret}"


# ---- webhook secrets and encryption at rest ----------------------------------------------------
def new_webhook_secret() -> str:
    # Standard Webhooks format: "whsec_" + base64 of the raw key bytes.
    return "whsec_" + base64.b64encode(secrets.token_bytes(24)).decode()


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def random_key_b64(n: int = 32) -> str:
    return _b64e(secrets.token_bytes(n))


@lru_cache
def _aead() -> AESGCM:
    return AESGCM(_b64d(get_settings().data_encryption_key))


def encrypt_secret(plaintext: str, context: str) -> str:
    """AES-256-GCM. `context` is bound as associated data, so a ciphertext copied into another
    row or tenant fails to decrypt."""
    nonce = secrets.token_bytes(12)
    return "v1." + _b64e(nonce + _aead().encrypt(nonce, plaintext.encode(), context.encode()))


def decrypt_secret(ciphertext: str, context: str) -> str:
    version, _, body = ciphertext.partition(".")
    if version != "v1":
        raise ValueError("unknown secret format")
    raw = _b64d(body)
    try:
        return _aead().decrypt(raw[:12], raw[12:], context.encode()).decode()
    except InvalidTag as exc:
        raise ValueError("secret cannot be decrypted (wrong key or tampered value)") from exc


# ---- audit checkpoints (Ed25519) --------------------------------------------------------------
@lru_cache
def _signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_b64d(get_settings().checkpoint_signing_key))


def _raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@lru_cache
def checkpoint_public_key() -> dict[str, str]:
    raw = _raw_public(_signing_key().public_key())
    return {"key_id": hashlib.sha256(raw).hexdigest()[:16], "algorithm": "Ed25519", "public_key": _b64e(raw)}


def checkpoint_message(tenant_id: int, chain_seq: int, row_hash: str, created_at: datetime) -> bytes:
    stamp = created_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return f"provenance-cloud/checkpoint/v1\n{tenant_id}\n{chain_seq}\n{row_hash}\n{stamp}".encode()


def sign_checkpoint(tenant_id: int, chain_seq: int, row_hash: str, created_at: datetime) -> str:
    return _b64e(_signing_key().sign(checkpoint_message(tenant_id, chain_seq, row_hash, created_at)))


def verify_checkpoint(tenant_id: int, chain_seq: int, row_hash: str, created_at: datetime, signature: str,
                      public_key: str | None = None) -> bool:
    try:
        key = (Ed25519PublicKey.from_public_bytes(_b64d(public_key)) if public_key
               else _signing_key().public_key())
        key.verify(_b64d(signature), checkpoint_message(tenant_id, chain_seq, row_hash, created_at))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---- platform operators: TOTP (RFC 6238) and platform tokens ---------------------------------
TOTP_PERIOD = 30
TOTP_DIGITS = 6
_clock = time.time  # replaceable in tests


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** TOTP_DIGITS
    return str(value).zfill(TOTP_DIGITS)


def current_step() -> int:
    return int(_clock() // TOTP_PERIOD)


def verify_totp(secret: str, code: str, last_step: int) -> int | None:
    """Return the matched time step (to be stored, so the code cannot be reused) or None.
    Accepts one step of clock drift either way; never a step at or before `last_step`."""
    code = (code or "").strip().replace(" ", "")
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return None
    now = current_step()
    for step in (now - 1, now, now + 1):
        if step > last_step and hmac.compare_digest(totp_at(secret, step), code):
            return step
    return None


def totp_uri(secret: str, account: str, issuer: str) -> str:
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}")


PLATFORM_AUDIENCE = "provenance-platform"


def _platform_key() -> str:
    # Derived from JWT_SECRET but different: a tenant token can never verify as a platform token or vice versa.
    return hmac.new(get_settings().jwt_secret.encode(), b"provenance-platform-token-v1", hashlib.sha256).hexdigest()


def create_platform_token(user_id: int, token_version: int, mfa_at: int, kind: str = "platform",
                          minutes: int | None = None) -> tuple[str, int]:
    s = get_settings()
    now = datetime.now(UTC)
    ttl = timedelta(minutes=minutes or s.platform_token_minutes)
    payload = {"iss": ISSUER, "aud": PLATFORM_AUDIENCE, "sub": str(user_id), "typ": kind, "ver": token_version,
               "mfa_at": mfa_at, "iat": now, "exp": now + ttl, "jti": secrets.token_hex(8)}
    return jwt.encode(payload, _platform_key(), algorithm="HS256"), int(ttl.total_seconds())


def decode_platform_token(token: str, kind: str = "platform") -> dict[str, Any]:
    payload = jwt.decode(token, _platform_key(), algorithms=["HS256"], issuer=ISSUER, audience=PLATFORM_AUDIENCE,
                         options={"require": ["exp", "iat", "sub", "typ", "ver"]})
    if payload.get("typ") != kind:
        raise jwt.InvalidTokenError("wrong token type")
    return payload


def platform_checkpoint_message(seq: int, row_hash: str, created_at: datetime) -> bytes:
    stamp = created_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return f"provenance-cloud/platform-checkpoint/v1\n{seq}\n{row_hash}\n{stamp}".encode()


def sign_platform_checkpoint(seq: int, row_hash: str, created_at: datetime) -> str:
    return _b64e(_signing_key().sign(platform_checkpoint_message(seq, row_hash, created_at)))


def verify_platform_checkpoint(seq: int, row_hash: str, created_at: datetime, signature: str) -> bool:
    try:
        _signing_key().public_key().verify(_b64d(signature), platform_checkpoint_message(seq, row_hash, created_at))
        return True
    except (InvalidSignature, ValueError):
        return False
