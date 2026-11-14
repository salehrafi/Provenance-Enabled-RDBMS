"""Platform console API (/api/platform/v1): global administration and break-glass access.

Separate from the organization API in every respect: its own operators, mandatory TOTP MFA, its own token type
(signed with a derived key, so tokens cannot be swapped with organization tokens), its own database role with no
access to tenant tables, and its own tamper-evident audit chain. Every request is recorded in that chain by the
middleware; break-glass reads and recoveries are additionally recorded *before* access is granted (fail closed).
"""

from __future__ import annotations

import csv
import io
import secrets
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import jwt
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.config import get_settings
from app.db import Db, dumps, platform_enabled, platform_session, pool_stats, session
from app.errors import ApiError, not_found
from app.ratelimit import client_ip, hit, rate_limit
from app.security import (
    checkpoint_public_key,
    create_platform_token,
    decode_platform_token,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    new_totp_secret,
    password_needs_rehash,
    sha256_hex,
    totp_uri,
    verify_password,
    verify_totp,
)
from app.services import platform as svc

router = APIRouter(prefix="/api/platform/v1", tags=["platform console"])

_DUMMY = hash_password(secrets.token_hex(16))


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginIn(_In):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    totp: str | None = Field(default=None, max_length=8)


class EnrollIn(_In):
    setup_token: str = Field(max_length=2000)
    code: str = Field(min_length=6, max_length=8)


class StepUpIn(_In):
    totp: str = Field(min_length=6, max_length=8)


class OperatorIn(_In):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=120)
    role: Literal["super_admin", "security_officer"]


class OperatorUpdate(_In):
    role: Literal["super_admin", "security_officer"] | None = None
    is_active: bool | None = None


class SuspendIn(_In):
    reason: str = Field(min_length=10, max_length=500)


class GrantIn(_In):
    tenant_id: int
    scope: Literal["READ_ONLY", "ACCOUNT_RECOVERY"] = "READ_ONLY"
    reason: str = Field(min_length=20, max_length=2000)
    ticket_ref: str = Field(min_length=3, max_length=100)
    duration_minutes: int = Field(default=60, ge=5, le=240)
    notify_customer: bool = Field(default=True, description="False only under a documented legal hold (reason >= 40 chars)")


class NoteIn(_In):
    note: str | None = Field(default=None, max_length=500)


class VerifyIn(_In):
    checkpoints: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)


# ---- operator context --------------------------------------------------------------------------
@dataclass
class Operator:
    user_id: int
    email: str
    full_name: str
    role: str
    mfa_at: int


@dataclass
class PCtx:
    op: Operator
    db: Db
    request: Request

    @property
    def request_id(self) -> str:
        return str(self.request.state.request_id)

    def log(self, action: str, outcome: str = "SUCCESS", tenant_id: int | None = None, target: str | None = None,
            **details: Any) -> None:
        svc.append(self.db, actor=self.op.email, actor_id=self.op.user_id, action=action, outcome=outcome,
                   tenant_id=tenant_id, target=target, ip=_ip(self.request),
                   user_agent=self.request.headers.get("user-agent"), request_id=self.request_id, details=details)


def _ip(request: Request) -> str | None:
    return client_ip(request)


def _unauth(detail: str, code: str) -> ApiError:
    return ApiError(401, detail, code, headers={"WWW-Authenticate": "Bearer"})


def _enabled() -> None:
    if not platform_enabled():
        raise ApiError(503, "The platform console is not configured (DATABASE_PLATFORM_URL)", "PLATFORM_DISABLED")


def operator_ctx(request: Request) -> Iterator[PCtx]:
    _enabled()
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise _unauth("Not authenticated", "UNAUTHENTICATED")
    try:
        claims = decode_platform_token(header[7:].strip())
    except jwt.ExpiredSignatureError:
        raise _unauth("Platform session expired", "TOKEN_EXPIRED") from None
    except jwt.PyJWTError:
        raise _unauth("Invalid platform token", "INVALID_TOKEN") from None
    with platform_session() as db:
        row = db.one("SELECT platform_user_id, email, full_name, role, is_active, mfa_enabled, token_version "
                     "FROM platform_users WHERE platform_user_id = %s", (int(claims["sub"]),))
        db.rollback()
        if not row or not row["is_active"] or not row["mfa_enabled"] or row["token_version"] != claims["ver"]:
            raise _unauth("Operator is inactive or the session was revoked", "TOKEN_REVOKED")
        op = Operator(row["platform_user_id"], row["email"], row["full_name"], row["role"], int(claims.get("mfa_at") or 0))
        request.state.platform_actor, request.state.platform_actor_id = op.email, op.user_id
        yield PCtx(op, db, request)


def require(*roles: str):
    def dep(ctx: PCtx = Depends(operator_ctx)) -> PCtx:
        if ctx.op.role not in roles:
            raise ApiError(403, f"Requires platform role {' or '.join(roles)}", "FORBIDDEN")
        return ctx
    return dep


ANY = require("super_admin", "security_officer")
SUPER = require("super_admin")


def fresh_mfa(ctx: PCtx) -> None:
    window = get_settings().platform_mfa_fresh_minutes * 60
    if time.time() - ctx.op.mfa_at > window:
        raise ApiError(403, f"This action needs a TOTP check within the last {window // 60} minutes; "
                       "call /auth/step-up first", "MFA_STEP_UP_REQUIRED")


def _public(row: dict[str, Any]) -> dict[str, Any]:
    return {k: row[k] for k in ("platform_user_id", "email", "full_name", "role", "is_active", "mfa_enabled",
                                "created_at", "created_by", "last_login_at") if k in row}


def _issue(user: dict[str, Any]) -> dict[str, Any]:
    token, ttl = create_platform_token(user["platform_user_id"], user["token_version"], int(time.time()))
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl, "operator": _public(user)}


# ---- authentication ---------------------------------------------------------------------------------
@router.post("/auth/login", summary="Operator sign-in: password + TOTP (first sign-in starts MFA enrolment)")
def login(body: LoginIn, request: Request):
    _enabled()
    email = body.email.lower()
    rate_limit(request, "platform-login", limit=10)
    hit(f"platform-login:{sha256_hex(email)[:32]}", 10, 900)
    request.state.platform_actor = email
    with platform_session() as db:
        row = db.one("SELECT * FROM platform_users WHERE email = %s", (email,))
        if not row:
            verify_password(body.password, _DUMMY)
            request.state.platform_action = "platform.login_failed"
            raise _unauth("Invalid email, password or code", "INVALID_CREDENTIALS")
        request.state.platform_actor_id = row["platform_user_id"]
        if not verify_password(body.password, row["password_hash"]):
            request.state.platform_action = "platform.login_failed"
            raise _unauth("Invalid email, password or code", "INVALID_CREDENTIALS")
        if not row["is_active"]:
            request.state.platform_action = "platform.login_blocked"
            raise ApiError(403, "Operator account is deactivated", "ACCOUNT_DEACTIVATED")
        ctx_name = f"platform-mfa:{row['platform_user_id']}"
        if password_needs_rehash(row["password_hash"]):
            db.execute("UPDATE platform_users SET password_hash = %s WHERE platform_user_id = %s",
                       (hash_password(body.password), row["platform_user_id"]))
        if not row["mfa_enabled"]:
            secret = decrypt_secret(row["mfa_secret_enc"], ctx_name) if row["mfa_secret_enc"] else new_totp_secret()
            db.execute("UPDATE platform_users SET mfa_secret_enc = %s WHERE platform_user_id = %s",
                       (encrypt_secret(secret, ctx_name), row["platform_user_id"]))
            db.commit()
            setup, ttl = create_platform_token(row["platform_user_id"], row["token_version"], 0, kind="platform_mfa_setup",
                                               minutes=10)
            request.state.platform_action = "platform.mfa_setup_started"
            return {"mfa_setup_required": True, "setup_token": setup, "expires_in": ttl, "secret": secret,
                    "otpauth_uri": totp_uri(secret, email, get_settings().platform_mfa_issuer)}
        if not body.totp:
            db.commit()
            raise _unauth("A TOTP code from your authenticator app is required", "MFA_REQUIRED")
        step = verify_totp(decrypt_secret(row["mfa_secret_enc"], ctx_name), body.totp, row["mfa_last_step"])
        if step is None:
            request.state.platform_action = "platform.login_failed"
            db.commit()
            raise _unauth("Invalid email, password or code", "INVALID_CREDENTIALS")
        db.execute("UPDATE platform_users SET mfa_last_step = %s, last_login_at = now() WHERE platform_user_id = %s",
                   (step, row["platform_user_id"]))
        db.commit()
        request.state.platform_action = "platform.login"
        return _issue(row)


@router.post("/auth/mfa/enroll", summary="Confirm MFA enrolment with the first code from the authenticator app")
def enroll(body: EnrollIn, request: Request):
    _enabled()
    rate_limit(request, "platform-enroll", limit=10)
    try:
        claims = decode_platform_token(body.setup_token, kind="platform_mfa_setup")
    except jwt.PyJWTError:
        raise _unauth("Enrolment session expired; sign in again", "INVALID_TOKEN") from None
    with platform_session() as db:
        row = db.one("SELECT * FROM platform_users WHERE platform_user_id = %s FOR UPDATE", (int(claims["sub"]),))
        if not row or not row["is_active"] or row["mfa_enabled"] or row["token_version"] != claims["ver"] or not row["mfa_secret_enc"]:
            raise _unauth("Enrolment is not possible for this operator", "INVALID_TOKEN")
        request.state.platform_actor, request.state.platform_actor_id = row["email"], row["platform_user_id"]
        step = verify_totp(decrypt_secret(row["mfa_secret_enc"], f"platform-mfa:{row['platform_user_id']}"), body.code, 0)
        if step is None:
            raise ApiError(422, "That code is not valid; check the time on your device and try again", "INVALID_MFA_CODE")
        db.execute("UPDATE platform_users SET mfa_enabled = true, mfa_last_step = %s, last_login_at = now() "
                   "WHERE platform_user_id = %s", (step, row["platform_user_id"]))
        db.commit()
        request.state.platform_action = "platform.mfa_enrolled"
        return _issue(row)


@router.post("/auth/step-up", summary="Re-check TOTP to unlock sensitive actions for a few minutes")
def step_up(body: StepUpIn, ctx: PCtx = Depends(operator_ctx)):
    db = ctx.db
    row = db.one("SELECT * FROM platform_users WHERE platform_user_id = %s FOR UPDATE", (ctx.op.user_id,))
    assert row
    step = verify_totp(decrypt_secret(row["mfa_secret_enc"], f"platform-mfa:{row['platform_user_id']}"), body.totp,
                       row["mfa_last_step"])
    if step is None:
        db.rollback()
        ctx.request.state.platform_action = "platform.step_up_failed"
        raise ApiError(403, "Invalid or already used code", "INVALID_MFA_CODE")
    db.execute("UPDATE platform_users SET mfa_last_step = %s WHERE platform_user_id = %s", (step, row["platform_user_id"]))
    db.commit()
    ctx.request.state.platform_action = "platform.step_up"
    return _issue(row)


@router.post("/auth/logout", status_code=204, summary="End every session of this operator")
def logout(ctx: PCtx = Depends(operator_ctx)):
    ctx.db.execute("UPDATE platform_users SET token_version = token_version + 1 WHERE platform_user_id = %s", (ctx.op.user_id,))
    ctx.db.commit()
    ctx.request.state.platform_action = "platform.logout"
    return Response(status_code=204)


@router.get("/me", summary="Current operator")
def me(ctx: PCtx = Depends(operator_ctx)):
    row = ctx.db.one("SELECT * FROM platform_users WHERE platform_user_id = %s", (ctx.op.user_id,))
    assert row
    mfa_left = max(0, get_settings().platform_mfa_fresh_minutes * 60 - int(time.time() - ctx.op.mfa_at))
    return {**_public(row), "mfa_fresh_seconds": mfa_left}


# ---- system health and organizations (metadata only) ------------------------------------------------
@router.get("/health", summary="System health and usage (no customer data)")
def health(ctx: PCtx = Depends(ANY)):
    from app.worker import worker
    metrics = ctx.db.one("SELECT * FROM prov.platform_system_metrics()")
    head = ctx.db.one("SELECT last_seq, last_at FROM platform_chain_head")
    cp = ctx.db.one("SELECT seq, created_at FROM platform_checkpoints ORDER BY seq DESC LIMIT 1")
    ctx.db.rollback()
    return {"database": "ok", "metrics": metrics, "pool": pool_stats(), "worker": worker.last_run,
            "platform_audit": {"records": head and head["last_seq"], "last_at": head and head["last_at"],
                               "latest_checkpoint": cp, "anchor_configured": bool(get_settings().platform_anchor_path)}}


def _orgs(db: Db) -> list[dict[str, Any]]:
    return db.all("SELECT * FROM prov.platform_org_overview()")


@router.get("/organizations", summary="Organizations with usage and security metadata (counts only)")
def organizations(ctx: PCtx = Depends(ANY)):
    rows = _orgs(ctx.db)
    ctx.db.rollback()
    return {"items": rows}


@router.get("/security/signals", summary="Failed and denied traffic by organization and IP address")
def signals(hours: int = Query(24, ge=1, le=720), ctx: PCtx = Depends(ANY)):
    rows = ctx.db.all("SELECT * FROM prov.platform_security_signals(%s)", (hours,))
    ctx.db.rollback()
    return {"items": rows, "hours": hours}


def _set_status(ctx: PCtx, tenant_id: int, status: str, reason: str | None) -> dict[str, Any]:
    fresh_mfa(ctx)
    n = ctx.db.scalar("SELECT prov.platform_set_tenant_status(%s, %s, %s, %s, %s)",
                      (tenant_id, status, reason, ctx.op.email, ctx.request_id))
    ctx.db.commit()
    org = next((o for o in _orgs(ctx.db) if o["tenant_id"] == tenant_id), None)
    ctx.db.rollback()
    if org is None:
        raise not_found("Organization")
    ctx.request.state.platform_action = f"organization.{status.lower()}"
    ctx.request.state.platform_tenant = tenant_id
    ctx.request.state.platform_details = {"reason": reason, "changed": bool(n)}
    return org


@router.post("/organizations/{tenant_id}/suspend", summary="Suspend an organization (sign-ins and API keys stop working)")
def suspend(tenant_id: int, body: SuspendIn, ctx: PCtx = Depends(SUPER)):
    return _set_status(ctx, tenant_id, "SUSPENDED", body.reason)


@router.post("/organizations/{tenant_id}/reactivate", summary="Lift a suspension")
def reactivate(tenant_id: int, ctx: PCtx = Depends(SUPER)):
    return _set_status(ctx, tenant_id, "ACTIVE", None)


# ---- operators ------------------------------------------------------------------------------------
@router.get("/operators", summary="Platform operators")
def operators(ctx: PCtx = Depends(SUPER)):
    rows = ctx.db.all("SELECT * FROM platform_users ORDER BY platform_user_id")
    ctx.db.rollback()
    return {"items": [_public(r) for r in rows]}


@router.post("/operators", status_code=201, summary="Add an operator (temporary password shown once; MFA enrolment forced)")
def add_operator(body: OperatorIn, ctx: PCtx = Depends(SUPER)):
    fresh_mfa(ctx)
    password = secrets.token_urlsafe(15)
    new_id = svc.create_operator(ctx.db, body.email, body.full_name, body.role, password, ctx.op.email)
    ctx.db.commit()
    ctx.request.state.platform_action = "operator.created"
    ctx.request.state.platform_details = {"operator_id": new_id, "email": body.email.lower(), "role": body.role}
    return {"platform_user_id": new_id, "email": body.email.lower(), "role": body.role, "temporary_password": password,
            "note": "Shown once. The operator must enrol TOTP MFA at first sign-in."}


@router.patch("/operators/{operator_id}", summary="Change an operator's role or status (not your own)")
def update_operator(operator_id: int, body: OperatorUpdate, ctx: PCtx = Depends(SUPER)):
    fresh_mfa(ctx)
    if operator_id == ctx.op.user_id:
        raise ApiError(403, "You cannot change your own role or status", "SELF_ESCALATION")
    sets: list[str] = []
    params: list[Any] = []
    if body.role is not None:
        sets.append("role = %s")
        params.append(body.role)
    if body.is_active is not None:
        sets.append("is_active = %s")
        params.append(body.is_active)
        sets.append("token_version = token_version + 1")
    if not sets:
        raise ApiError(422, "Nothing to change", "VALIDATION_ERROR")
    if not ctx.db.execute(f"UPDATE platform_users SET {', '.join(sets)} WHERE platform_user_id = %s", (*params, operator_id)):
        raise not_found("Operator")
    ctx.db.commit()  # the "keep one active super admin" constraint is checked here
    ctx.request.state.platform_action = "operator.updated"
    ctx.request.state.platform_details = {"operator_id": operator_id, **body.model_dump(exclude_none=True)}
    row = ctx.db.one("SELECT * FROM platform_users WHERE platform_user_id = %s", (operator_id,))
    ctx.db.rollback()
    return _public(row or {})


@router.post("/operators/{operator_id}/reset-mfa", summary="Force an operator to re-enrol MFA (not your own)")
def reset_mfa(operator_id: int, ctx: PCtx = Depends(SUPER)):
    fresh_mfa(ctx)
    if operator_id == ctx.op.user_id:
        raise ApiError(403, "You cannot reset your own MFA", "SELF_ESCALATION")
    if not ctx.db.execute("UPDATE platform_users SET mfa_enabled = false, mfa_secret_enc = NULL, mfa_last_step = 0, "
                          "token_version = token_version + 1 WHERE platform_user_id = %s", (operator_id,)):
        raise not_found("Operator")
    ctx.db.commit()
    ctx.request.state.platform_action = "operator.mfa_reset"
    ctx.request.state.platform_details = {"operator_id": operator_id}
    return {"reset": True}


# ---- break-glass ----------------------------------------------------------------------------------
_GRANT_SQL = """
    SELECT g.*, r.email AS requested_by_email, d.email AS decided_by_email, e.email AS ended_by_email,
           (g.status = 'ACTIVE' AND g.expires_at > now()) AS is_live
      FROM break_glass_grants g
      JOIN platform_users r ON r.platform_user_id = g.requested_by
      LEFT JOIN platform_users d ON d.platform_user_id = g.decided_by
      LEFT JOIN platform_users e ON e.platform_user_id = g.ended_by
"""


def _grant(db: Db, grant_id: int, lock: bool = False) -> dict[str, Any]:
    row = db.one(_GRANT_SQL + " WHERE g.grant_id = %s" + (" FOR UPDATE OF g" if lock else ""), (grant_id,))
    if not row:
        raise not_found("Break-glass request")
    return row


def _mark(ctx: PCtx, action: str, g: dict[str, Any], **details: Any) -> None:
    ctx.request.state.platform_action = action
    ctx.request.state.platform_tenant = g["tenant_id"]
    ctx.request.state.platform_details = {"grant_id": g["grant_id"], **details}


@router.get("/break-glass", summary="Break-glass requests")
def list_grants(status: str | None = Query(None, max_length=10), ctx: PCtx = Depends(ANY)):
    rows = ctx.db.all(_GRANT_SQL + " WHERE (%s::text IS NULL OR g.status = %s) ORDER BY g.grant_id DESC LIMIT 200",
                      (status, status))
    names = {o["tenant_id"]: o["name"] for o in _orgs(ctx.db)}
    ctx.db.rollback()
    for r in rows:
        r["tenant_name"] = names.get(r["tenant_id"])
    return {"items": rows}


@router.post("/break-glass", status_code=201, summary="Request emergency access to one organization")
def request_grant(body: GrantIn, ctx: PCtx = Depends(ANY)):
    fresh_mfa(ctx)
    gid = ctx.db.insert(
        "INSERT INTO break_glass_grants (tenant_id, scope, reason, ticket_ref, duration_minutes, notify_customer, requested_by) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (body.tenant_id, body.scope, body.reason, body.ticket_ref, body.duration_minutes, body.notify_customer,
         ctx.op.user_id), "grant_id")
    ctx.db.commit()
    g = _grant(ctx.db, gid)
    ctx.db.rollback()
    _mark(ctx, "breakglass.requested", g, scope=body.scope, ticket=body.ticket_ref, minutes=body.duration_minutes,
          notify_customer=body.notify_customer)
    return g


@router.get("/break-glass/{grant_id}", summary="One break-glass request")
def get_grant(grant_id: int, ctx: PCtx = Depends(ANY)):
    g = _grant(ctx.db, grant_id)
    ctx.db.rollback()
    return g


def _decide(ctx: PCtx, grant_id: int, status: str, note: str | None) -> dict[str, Any]:
    fresh_mfa(ctx)
    g = _grant(ctx.db, grant_id, lock=True)
    if g["requested_by"] == ctx.op.user_id:
        raise ApiError(403, "Four-eyes rule: a different operator must decide this request", "FOUR_EYES")
    ctx.db.execute("UPDATE break_glass_grants SET status = %s, decided_by = %s, decision_note = %s WHERE grant_id = %s",
                   (status, ctx.op.user_id, note, grant_id))
    ctx.db.commit()
    g = _grant(ctx.db, grant_id)
    ctx.db.rollback()
    _mark(ctx, f"breakglass.{status.lower()}", g, note=note)
    return g


@router.post("/break-glass/{grant_id}/approve", summary="Approve (a different operator, fresh MFA)")
def approve(grant_id: int, body: NoteIn, ctx: PCtx = Depends(ANY)):
    return _decide(ctx, grant_id, "APPROVED", body.note)


@router.post("/break-glass/{grant_id}/reject", summary="Reject (a different operator, fresh MFA)")
def reject(grant_id: int, body: NoteIn, ctx: PCtx = Depends(ANY)):
    return _decide(ctx, grant_id, "REJECTED", body.note)


@router.post("/break-glass/{grant_id}/activate", summary="Start the access window (requester only, fresh MFA)")
def activate(grant_id: int, ctx: PCtx = Depends(ANY)):
    fresh_mfa(ctx)
    g = _grant(ctx.db, grant_id, lock=True)
    if g["requested_by"] != ctx.op.user_id:
        raise ApiError(403, "Only the requester can activate this grant", "FORBIDDEN")
    ctx.db.execute("UPDATE break_glass_grants SET status = 'ACTIVE' WHERE grant_id = %s", (grant_id,))
    ctx.db.commit()
    g = _grant(ctx.db, grant_id)
    ctx.db.rollback()
    _mark(ctx, "breakglass.activated", g, expires_at=g["expires_at"].isoformat())
    return g


@router.post("/break-glass/{grant_id}/revoke", summary="Revoke a request or an active grant (any operator)")
def revoke(grant_id: int, body: NoteIn, ctx: PCtx = Depends(ANY)):
    _grant(ctx.db, grant_id, lock=True)
    ctx.db.execute("UPDATE break_glass_grants SET status = 'REVOKED', ended_by = %s, end_note = %s WHERE grant_id = %s",
                   (ctx.op.user_id, body.note, grant_id))
    ctx.db.commit()
    g = _grant(ctx.db, grant_id)
    ctx.db.rollback()
    _mark(ctx, "breakglass.revoked", g, note=body.note)
    return g


@router.post("/break-glass/{grant_id}/close", summary="End your active access early")
def close(grant_id: int, body: NoteIn, ctx: PCtx = Depends(ANY)):
    g = _grant(ctx.db, grant_id, lock=True)
    if g["requested_by"] != ctx.op.user_id:
        raise ApiError(403, "Only the requester can close this grant; others can revoke it", "FORBIDDEN")
    ctx.db.execute("UPDATE break_glass_grants SET status = 'CLOSED', ended_by = %s, end_note = %s WHERE grant_id = %s",
                   (ctx.op.user_id, body.note, grant_id))
    ctx.db.commit()
    g = _grant(ctx.db, grant_id)
    ctx.db.rollback()
    _mark(ctx, "breakglass.closed", g, note=body.note)
    return g


def _live_grant(ctx: PCtx, grant_id: int, what: str, scope: str | None = None) -> dict[str, Any]:
    """Authorise a break-glass use and record it in the platform chain BEFORE any data is touched.
    If the record cannot be written, access is refused."""
    g = _grant(ctx.db, grant_id)
    ctx.db.rollback()
    ok = (g["is_live"] and g["requested_by"] == ctx.op.user_id and (scope is None or g["scope"] == scope))
    if not ok:
        ctx.log("breakglass.access_denied", "DENIED", g["tenant_id"], what, grant_id=grant_id, status=g["status"])
        raise ApiError(403, "Break-glass access is not active for you on this grant", "BREAK_GLASS_NOT_ACTIVE")
    try:
        ctx.log("breakglass.access", "SUCCESS", g["tenant_id"], what, grant_id=grant_id, scope=g["scope"])
    except Exception:
        raise ApiError(503, "Access refused: the platform audit record could not be written", "AUDIT_UNAVAILABLE") from None
    if g["notify_customer"]:
        with session(g["tenant_id"], None, f"platform:{ctx.op.email}", ctx.request_id) as tdb:
            tdb.execute("INSERT INTO activity_log (actor, action, method, route, path, status_code, outcome, ip_address, "
                        "request_id, details) VALUES (%s, 'breakglass.access', 'GET', '/platform/break-glass', %s, 200, "
                        "'SUCCESS', NULLIF(%s, '')::inet, %s, %s)",
                        (f"platform:{ctx.op.email}", f"/platform/break-glass/{grant_id}/{what}", _ip(ctx.request) or "",
                         ctx.request_id, dumps({"grant_id": grant_id, "resource": what})))
            tdb.commit()
    return g


# Read-only views of tenant data. Secrets (password hashes, key hashes, webhook secrets) are never selectable.
TABLES: dict[str, tuple[str, str]] = {
    "customers": ("customer_id, name, email, phone, created_at", "customer_id"),
    "products": ("product_id, sku, name, price, active, created_at", "product_id"),
    "orders": ("order_id, customer_id, status, total_amount, currency, notes, created_at, updated_at", "order_id"),
    "order_items": ("order_id, product_id, quantity, unit_price, line_total", "order_id"),
    "payments": ("payment_id, order_id, amount, method, status, reference, created_at", "payment_id"),
    "alerts": ("alert_id, rule_code, severity, entity, entity_id, title, status, created_at", "alert_id"),
    "change_requests": ("change_request_id, entity, entity_id, change_type, payload, status, requested_by, reviewed_by, requested_at, reviewed_at", "change_request_id"),
    "sources": ("source_id, code, name, capture_method, trust_level, status, created_at, last_event_at", "source_id"),
    "external_events": ("event_pk, source_id, source_event_id, event_type, subject, occurred_at, received_at, payload", "event_pk"),
    "audit_log": ("audit_id, chain_seq, entity, record_pk, operation, old_values, new_values, actor, changed_at, row_hash", "audit_id"),
    "activity_log": ("activity_id, occurred_at, actor, action, method, path, status_code, outcome, host(ip_address) AS ip_address", "activity_id"),
    "users": ("user_id, email, full_name, role, is_active, created_at, last_login_at", "user_id"),
    "webhooks": ("webhook_id, url, event_types, is_active, created_at", "webhook_id"),
}


def _read(ctx: PCtx, grant_id: int, query: str, params: tuple) -> list[dict[str, Any]]:
    # The application role, under RLS. breakglass_begin re-checks the grant in the database, sets the tenant and
    # switches the transaction to READ ONLY, so even a bug here cannot write.
    with session(None, None, None, ctx.request_id) as db:
        db.one("SELECT * FROM prov.breakglass_begin(%s, %s, %s)", (grant_id, ctx.op.user_id, ctx.request_id))
        rows = db.all(query, params)
        db.rollback()
    return rows


@router.get("/break-glass/{grant_id}/data/{table}", summary="Read-only view of one table of the organization")
def bg_data(grant_id: int, table: str, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
            ctx: PCtx = Depends(ANY)):
    if table not in TABLES:
        raise ApiError(404, f"Table not available. Use one of {sorted(TABLES)}", "NOT_FOUND")
    _live_grant(ctx, grant_id, f"data/{table}")
    cols, key = TABLES[table]
    rows = _read(ctx, grant_id, f"SELECT {cols} FROM {table} ORDER BY {key} DESC LIMIT %s OFFSET %s", (limit, offset))
    return {"table": table, "items": rows, "limit": limit, "offset": offset, "read_only": True}


@router.get("/break-glass/{grant_id}/history/{entity}/{record_pk}", summary="Change history of one record")
def bg_history(grant_id: int, entity: str, record_pk: str, ctx: PCtx = Depends(ANY)):
    _live_grant(ctx, grant_id, f"history/{entity}/{record_pk}")
    rows = _read(ctx, grant_id, "SELECT chain_seq, operation, old_values, new_values, actor, changed_at, row_hash "
                 "FROM audit_log WHERE entity = %s AND record_pk = %s ORDER BY chain_seq", (entity, record_pk))
    return {"entity": entity, "record_pk": record_pk, "history": rows}


@router.get("/break-glass/{grant_id}/users", summary="Users of the organization (for account recovery)")
def bg_users(grant_id: int, ctx: PCtx = Depends(ANY)):
    _live_grant(ctx, grant_id, "users")
    rows = ctx.db.all("SELECT * FROM prov.breakglass_list_users(%s, %s)", (grant_id, ctx.op.user_id))
    ctx.db.rollback()
    return {"items": rows}


@router.post("/break-glass/{grant_id}/users/{user_id}/{action}",
             summary="Account recovery: reset-password, reactivate or revoke-sessions (ACCOUNT_RECOVERY scope, fresh MFA)")
def bg_recover(grant_id: int, user_id: int, action: Literal["reset-password", "reactivate", "revoke-sessions"],
               ctx: PCtx = Depends(ANY)):
    fresh_mfa(ctx)
    _live_grant(ctx, grant_id, f"users/{user_id}/{action}", scope="ACCOUNT_RECOVERY")
    password = secrets.token_urlsafe(12) if action == "reset-password" else None
    email = ctx.db.scalar("SELECT prov.breakglass_recover_user(%s, %s, %s, %s, %s, %s)",
                          (grant_id, ctx.op.user_id, user_id, action.replace("-", "_"),
                           hash_password(password) if password else None, ctx.request_id))
    ctx.db.commit()
    ctx.request.state.platform_action = f"breakglass.recovery.{action}"
    out: dict[str, Any] = {"user_id": user_id, "email": email, "action": action}
    if password:
        out["temporary_password"] = password
        out["note"] = "Shown once. Give it to the verified account owner over a separate channel."
    return out


# ---- platform audit chain ---------------------------------------------------------------------------
_AUDIT_COLS = ("audit_id, seq, occurred_at, actor, actor_id, action, outcome, target_tenant_id, target, "
               "host(ip_address) AS ip_address, user_agent, request_id, details, prev_hash, row_hash")


def _audit_filters(actor, action, tenant_id, outcome, since, until, before_seq) -> tuple[str, list[Any]]:
    conds, params = ["seq IS NOT NULL"], []
    if actor:
        conds.append("actor ILIKE %s")
        params.append(f"%{actor}%")
    if action:
        conds.append("action ILIKE %s")
        params.append(f"%{action}%")
    for col, val in (("target_tenant_id", tenant_id), ("outcome", outcome)):
        if val:
            conds.append(f"{col} = %s")
            params.append(val)
    if since:
        conds.append("occurred_at >= %s")
        params.append(since)
    if until:
        conds.append("occurred_at <= %s")
        params.append(until)
    if before_seq:
        conds.append("seq < %s")
        params.append(before_seq)
    return " WHERE " + " AND ".join(conds), params


@router.get("/audit", summary="Platform audit chain (newest first)")
def audit(actor: str | None = Query(None, max_length=254), action: str | None = Query(None, max_length=120),
          tenant_id: int | None = None, outcome: Literal["SUCCESS", "DENIED", "FAILURE"] | None = None,
          since: datetime | None = None, until: datetime | None = None, before_seq: int | None = None,
          limit: int = Query(50, ge=1, le=500), ctx: PCtx = Depends(ANY)):
    where, params = _audit_filters(actor, action, tenant_id, outcome, since, until, before_seq)
    rows = ctx.db.all(f"SELECT {_AUDIT_COLS} FROM platform_audit_log{where} ORDER BY seq DESC LIMIT %s", (*params, limit))
    ctx.db.rollback()
    return {"items": rows, "next_before_seq": rows[-1]["seq"] if len(rows) == limit else None}


@router.get("/audit/export", summary="Export the platform audit chain as CSV")
def audit_export(actor: str | None = None, action: str | None = None, tenant_id: int | None = None,
                 since: datetime | None = None, until: datetime | None = None, ctx: PCtx = Depends(ANY)):
    where, params = _audit_filters(actor, action, tenant_id, None, since, until, None)
    rows = ctx.db.all(f"SELECT {_AUDIT_COLS} FROM platform_audit_log{where} ORDER BY seq LIMIT 100000", tuple(params))
    ctx.db.rollback()
    ctx.request.state.platform_action = "platform.audit_export"
    cols = ["seq", "occurred_at", "actor", "action", "outcome", "target_tenant_id", "target", "ip_address", "user_agent",
            "request_id", "details", "prev_hash", "row_hash"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([("'" + v if isinstance(v, str) and v[:1] in "=+-@\t\r" else v) for v in
                    (r["seq"], r["occurred_at"].isoformat(), r["actor"], r["action"], r["outcome"], r["target_tenant_id"],
                     r["target"], r["ip_address"], r["user_agent"], r["request_id"], dumps(r["details"]), r["prev_hash"],
                     r["row_hash"])])
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="platform-audit-{stamp}.csv"'})


@router.post("/audit/verify", summary="Verify the platform chain, stored and anchored checkpoints, and any you kept")
def audit_verify(body: VerifyIn | None = None, ctx: PCtx = Depends(ANY)):
    result = svc.verify_all(ctx.db, body.checkpoints if body else [])
    ctx.request.state.platform_action = "platform.audit_verify"
    ctx.request.state.platform_details = {"ok": result["ok"], "reason": result.get("reason")}
    return result


@router.get("/audit/checkpoints", summary="Signed platform checkpoints")
def checkpoints(ctx: PCtx = Depends(ANY)):
    rows = ctx.db.all("SELECT seq, row_hash, created_at, key_id, signature FROM platform_checkpoints ORDER BY seq DESC LIMIT 100")
    ctx.db.rollback()
    return {"items": rows, "signing_key": checkpoint_public_key(), "anchor_configured": bool(get_settings().platform_anchor_path)}


@router.post("/audit/checkpoints", status_code=201, summary="Sign a platform checkpoint now")
def create_checkpoint(ctx: PCtx = Depends(ANY)):
    return svc.create_checkpoint(ctx.db, ctx.op.email, ctx.op.user_id) or {"ok": True, "message": "Nothing new to sign"}
