"""API key authentication for machine clients (legacy systems, connectors).

Keys look like `prv_<key_id>_<secret>` and are sent as `Authorization: Bearer <key>`.
Only sha256(secret) is stored. Each key belongs to one tenant and carries scopes.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from typing import Iterator

from fastapi import Depends, HTTPException, Request, status

from app import ratelimit
from app.config import get_settings
from app.db import Db, system_session, tenant_session
from app.security import hash_api_secret

SCOPES = ("events:write", "events:read")
_KEY = re.compile(r"^prv_([0-9a-f]{12})_([A-Za-z0-9_-]{20,100})$")


@dataclass(frozen=True)
class ApiPrincipal:
    key_id: str
    tenant_id: int
    name: str
    scopes: frozenset[str]

    @property
    def actor(self) -> str:
        return f"apikey:{self.name}"


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"})


def get_api_principal(request: Request) -> ApiPrincipal:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise _unauthorized("API key required (Authorization: Bearer prv_...)")
    match = _KEY.match(header[7:].strip())
    if not match:
        raise _unauthorized("Malformed API key")
    key_id, secret = match.groups()
    with system_session() as db:
        row = db.one(
            "SELECT key_id, tenant_id, name, secret_hash, scopes, revoked_at FROM api_keys WHERE key_id = :k",
            {"k": key_id},
        )
        # Compare in constant time; an unknown key id still costs a hash.
        expected = row["secret_hash"] if row else "0" * 64
        if not hmac.compare_digest(hash_api_secret(secret), expected) or not row:
            raise _unauthorized("Invalid API key")
        if row["revoked_at"] is not None:
            raise _unauthorized("API key has been revoked")
        db.execute("UPDATE api_keys SET last_used_at = SYS_EXTRACT_UTC(SYSTIMESTAMP) WHERE key_id = :k", {"k": key_id})
        db.commit()
    # Per-key limit, so one noisy integration cannot starve the others.
    ratelimit.hit(f"apikey:{key_id}", get_settings().api_key_rate_limit_per_minute)
    return ApiPrincipal(key_id, int(row["tenant_id"]), row["name"], frozenset(row["scopes"].split(",")))


def require_scope(scope: str):
    def dependency(principal: ApiPrincipal = Depends(get_api_principal)) -> ApiPrincipal:
        if scope not in principal.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"API key lacks scope '{scope}'")
        return principal

    return dependency


def api_db(request: Request, principal: ApiPrincipal) -> Iterator[Db]:
    with tenant_session(principal.tenant_id, None, principal.actor, request.state.request_id) as db:
        yield db
