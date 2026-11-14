"""Authentication and authorization for every request.

Two kinds of caller share one model:

* people, with a short-lived JWT access token (`Authorization: Bearer eyJ...`);
* machines, with an API key (`Authorization: Bearer prv_<key id>_<secret>`).

Both resolve to a `Principal` holding a tenant and a set of permissions. Endpoints declare the
one permission they need with `Depends(require("orders:write"))` and receive a `Ctx`: the
principal plus a database connection already scoped to the principal's tenant.

A person's permissions come from their role, read from the database on every request (so a
demotion or deactivation applies immediately). An API key's permissions are its scopes.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

import jwt
from fastapi import Depends, Request

from app import ratelimit
from app.config import get_settings
from app.db import Context, Db, session
from app.errors import ApiError
from app.security import decode_access_token, sha256_hex

# ---- permissions ----------------------------------------------------------------------------
READ = frozenset({
    "catalog:read", "orders:read", "audit:read", "alerts:read", "approvals:read",
    "sources:read", "settings:read", "events:read",
})
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": READ,
    # Auditors read everything and can take evidence out, but cannot change business data.
    "auditor": READ | {"audit:export", "audit:verify"},
    "staff": READ | {"catalog:write", "orders:write", "alerts:manage", "imports:write",
                     "audit:export", "audit:verify"},
}
ALL_PERMISSIONS = ROLE_PERMISSIONS["staff"] | ROLE_PERMISSIONS["auditor"] | {
    "catalog:delete", "approvals:review", "webhooks:manage", "sources:manage", "apikeys:manage",
    "users:manage", "settings:manage", "events:write", "activity:read",
}
ROLE_PERMISSIONS["admin"] = ALL_PERMISSIONS - {"events:write"}  # ingestion is for API keys

# What an API key may be granted. Deliberately narrow: keys cannot manage users, keys or webhooks.
API_KEY_SCOPES: dict[str, str] = {
    "events:write": "Send events and reconciliation snapshots",
    "events:read": "Read ingested events and reconstructed records",
    "audit:read": "Read the audit log, provenance and time travel",
    "audit:verify": "Run audit-chain verification and read checkpoints",
    "audit:export": "Export audit evidence",
}

_API_KEY = re.compile(r"^prv_([0-9a-f]{12})_([A-Za-z0-9_-]{20,100})$")


@dataclass(frozen=True)
class Principal:
    kind: Literal["user", "api_key"]
    tenant_id: int
    actor: str
    permissions: frozenset[str]
    user_id: int | None = None
    email: str | None = None
    full_name: str | None = None
    role: str | None = None
    key_id: str | None = None

    def can(self, permission: str) -> bool:
        return permission in self.permissions


@dataclass
class Ctx:
    """What an endpoint works with: who is calling, and their tenant-scoped connection."""

    principal: Principal
    db: Db
    request_id: str

    @property
    def tenant_id(self) -> int:
        return self.principal.tenant_id

    @property
    def actor(self) -> str:
        return self.principal.actor


def unauthenticated(detail: str = "Not authenticated", code: str = "UNAUTHENTICATED") -> ApiError:
    return ApiError(401, detail, code, headers={"WWW-Authenticate": "Bearer"})


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise unauthenticated()
    return header[7:].strip()


def _api_key_principal(db: Db, token: str) -> Principal:
    match = _API_KEY.match(token)
    if not match:
        raise unauthenticated("Malformed API key", "INVALID_API_KEY")
    key_id, secret = match.groups()
    row = db.one("SELECT * FROM prov.auth_api_key(%s)", (key_id,))
    db.rollback()  # end the tenant-less transaction before switching identity
    # Constant-time comparison; an unknown key id still costs a hash.
    expected = row["secret_hash"] if row else "0" * 64
    if not hmac.compare_digest(sha256_hex(secret), expected) or not row:
        raise unauthenticated("Invalid API key", "INVALID_API_KEY")
    if row["revoked_at"] is not None:
        raise unauthenticated("API key has been revoked", "API_KEY_REVOKED")
    if row["expires_at"] is not None and row["expires_at"] <= datetime.now(UTC):
        raise unauthenticated("API key has expired", "API_KEY_EXPIRED")
    # Per-key limit, so one noisy integration cannot starve the others.
    ratelimit.hit(f"apikey:{key_id}", get_settings().api_key_rate_limit_per_minute)
    principal = Principal("api_key", int(row["tenant_id"]), f"apikey:{row['name']}",
                          frozenset(row["scopes"]) & frozenset(API_KEY_SCOPES), key_id=key_id)
    db.use(Context(principal.tenant_id, None, principal.actor, db.ctx.request_id))
    _require_active_org(db)
    # Throttled so a busy key does not turn every request into a write.
    db.execute("UPDATE api_keys SET last_used_at = now() WHERE key_id = %s "
               "AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')", (key_id,))
    db.commit()
    return principal


def _require_active_org(db: Db) -> None:
    """A suspended organization (set by a platform super admin) loses all access until reactivated."""
    status = db.scalar("SELECT status FROM tenants")
    db.rollback()  # end this read so the caller can switch identity afterwards
    if status is None:
        raise unauthenticated("Organization no longer exists", "INVALID_TOKEN")
    if status != "ACTIVE":
        raise ApiError(403, "This organization is suspended. Contact support.", "ORGANIZATION_SUSPENDED")


def _user_principal(db: Db, token: str) -> Principal:
    try:
        claims = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise unauthenticated("Access token expired", "TOKEN_EXPIRED") from None
    except jwt.PyJWTError:
        raise unauthenticated("Invalid access token", "INVALID_TOKEN") from None
    user_id, tenant_id = int(claims["sub"]), int(claims["tid"])
    db.use(Context(tenant_id, user_id, None, db.ctx.request_id))
    row = db.one("SELECT user_id, email, full_name, role, is_active, token_version FROM users WHERE user_id = %s",
                 (user_id,))
    db.rollback()
    if not row or not row["is_active"]:
        raise unauthenticated("User is inactive or no longer exists", "USER_INACTIVE")
    # Password changes and "sign out everywhere" bump token_version, revoking older tokens.
    if int(claims["ver"]) != row["token_version"]:
        raise unauthenticated("Access token has been revoked", "TOKEN_REVOKED")
    _require_active_org(db)  # only after the caller is authenticated, so it reveals nothing to strangers
    ratelimit.hit(f"user:{user_id}", get_settings().user_rate_limit_per_minute)
    db.use(Context(tenant_id, user_id, row["email"], db.ctx.request_id))
    return Principal("user", tenant_id, row["email"], ROLE_PERMISSIONS[row["role"]], user_id=user_id,
                     email=row["email"], full_name=row["full_name"], role=row["role"])


def get_ctx(request: Request) -> Iterator[Ctx]:
    token = _bearer(request)
    request_id: str = request.state.request_id
    with session(None, None, None, request_id) as db:
        principal = (_api_key_principal if token.startswith("prv_") else _user_principal)(db, token)
        request.state.tenant_id = principal.tenant_id
        request.state.actor = principal.actor
        request.state.user_id = principal.user_id
        request.state.key_id = principal.key_id
        yield Ctx(principal, db, request_id)


def require(permission: str) -> Callable[[Ctx], Ctx]:
    """Dependency factory: the caller must hold `permission`."""
    assert permission in ALL_PERMISSIONS, permission

    def dependency(ctx: Ctx = Depends(get_ctx)) -> Ctx:
        if not ctx.principal.can(permission):
            who = "API key lacks scope" if ctx.principal.kind == "api_key" else "Your role does not allow"
            raise ApiError(403, f"{who} '{permission}'", "FORBIDDEN", required=permission)
        return ctx

    dependency.__name__ = f"require_{permission.replace(':', '_')}"
    return dependency


def require_user(permission: str) -> Callable[[Ctx], Ctx]:
    """Like require(), but only for people (endpoints that record a human decision)."""
    base = require(permission)

    def dependency(ctx: Ctx = Depends(base)) -> Ctx:
        if ctx.principal.kind != "user":
            raise ApiError(403, "This operation needs a signed-in user, not an API key", "FORBIDDEN")
        return ctx

    return dependency


def any_user(ctx: Ctx = Depends(get_ctx)) -> Ctx:
    if ctx.principal.kind != "user":
        raise ApiError(403, "This operation needs a signed-in user, not an API key", "FORBIDDEN")
    return ctx
