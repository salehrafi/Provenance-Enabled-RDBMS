"""Sign-up, sign-in and session management.

Access tokens are short-lived JWTs. Refresh tokens are opaque, stored only as SHA-256, and
rotated on every use. The browser gets the refresh token in an HttpOnly, SameSite=Strict cookie
scoped to this router's path, so page scripts can never read it; other clients may send it in
the request body instead.
"""

from __future__ import annotations

import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.security import OAuth2PasswordRequestForm

from app.auth import ROLE_PERMISSIONS, Ctx, any_user
from app.common import emit_event
from app.config import get_settings
from app.db import Context, Db, Row, session
from app.errors import ApiError
from app.ratelimit import hit, rate_limit
from app.schemas import LoginIn, PasswordChangeIn, RefreshIn, SignupIn
from app.security import (
    create_access_token,
    hash_password,
    new_refresh_token,
    password_needs_rehash,
    sha256_hex,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

COOKIE = "prov_refresh"
COOKIE_PATH = "/api/v1/auth"
# Two tabs can race to rotate the same token. Within this window the loser is told to retry
# (the browser already holds the winner's cookie) instead of being treated as an attacker.
ROTATION_GRACE = timedelta(seconds=10)

# Verify against a dummy hash when the email is unknown, so response time does not reveal
# which emails are registered.
_DUMMY_HASH = hash_password(secrets.token_hex(16))

_USER_SQL = """
    SELECT u.user_id, u.tenant_id, u.email, u.full_name, u.role, u.is_active, u.token_version,
           t.name AS tenant_name, t.slug AS tenant_slug, t.plan
      FROM users u JOIN tenants t ON t.tenant_id = u.tenant_id
     WHERE u.user_id = %s
"""


def public_user(row: Row) -> dict[str, Any]:
    return {
        "user_id": row["user_id"], "email": row["email"], "full_name": row["full_name"], "role": row["role"],
        "permissions": sorted(ROLE_PERMISSIONS[row["role"]]),
        "tenant": {"tenant_id": row["tenant_id"], "name": row["tenant_name"], "slug": row["tenant_slug"],
                   "plan": row["plan"]},
    }


def _slug(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "org"
    return f"{base}-{secrets.token_hex(3)}"


def _set_cookie(response: Response, token: str) -> None:
    s = get_settings()
    response.set_cookie(COOKIE, token, max_age=s.refresh_token_days * 86400, path=COOKIE_PATH,
                        httponly=True, secure=s.cookie_secure, samesite="strict")


def _clear_cookie(response: Response) -> None:
    s = get_settings()
    response.delete_cookie(COOKIE, path=COOKIE_PATH, httponly=True, secure=s.cookie_secure, samesite="strict")


def _issue(db: Db, request: Request, response: Response, user: Row, family_id: uuid.UUID | None = None,
           replaces: int | None = None) -> dict[str, Any]:
    """Create a token pair for `user` inside the current (tenant-scoped) transaction."""
    s = get_settings()
    token, token_hash = new_refresh_token()
    new_id = db.insert(
        "INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at, user_agent) "
        "VALUES (%s, %s, %s, %s, %s)",
        (user["user_id"], family_id or uuid.uuid4(), token_hash,
         datetime.now(UTC) + timedelta(days=s.refresh_token_days),
         (request.headers.get("user-agent") or "")[:200] or None),
        "token_id",
    )
    if replaces is not None:
        db.execute("UPDATE refresh_tokens SET used_at = now(), replaced_by = %s WHERE token_id = %s", (new_id, replaces))
    access, expires_in = create_access_token(user["user_id"], user["tenant_id"], user["token_version"])
    _set_cookie(response, token)
    return {"access_token": access, "token_type": "bearer", "expires_in": expires_in, "refresh_token": token,
            "user": public_user(user)}


def _mark(request: Request, tenant_id: int, user_id: int | None, actor: str, action: str, **details: Any) -> None:
    """Tell the activity log (written by middleware after the response) what happened, even if we then raise."""
    request.state.tenant_id = tenant_id
    request.state.user_id = user_id
    request.state.actor = actor
    request.state.activity_action = action
    request.state.activity_details = details


def _as_user(db: Db, tenant_id: int, user_id: int, email: str) -> None:
    db.rollback()
    db.use(Context(tenant_id, user_id, email, db.ctx.request_id))


@router.post("/signup", status_code=201, summary="Create an organization and its first admin")
def signup(body: SignupIn, request: Request, response: Response):
    rate_limit(request, "signup")
    email = body.email.lower()
    with session(None, None, email, request.state.request_id) as db:
        # A unique-violation on the email becomes 409 EMAIL_TAKEN in the global handler.
        created = db.one("SELECT * FROM prov.create_organization(%s, %s, %s, %s, %s, %s)",
                         (body.organization, _slug(body.organization), email, body.full_name,
                          hash_password(body.password), request.state.request_id))
        db.commit()
        assert created is not None
        _mark(request, created["tenant_id"], created["user_id"], email, "auth.signup", organization=body.organization)
        _as_user(db, created["tenant_id"], created["user_id"], email)
        user = db.one(_USER_SQL, (created["user_id"],))
        assert user is not None
        result = _issue(db, request, response, user)
        db.commit()
    return result


def _login(request: Request, response: Response, email: str, password: str) -> dict[str, Any]:
    email = email.strip().lower()
    rate_limit(request, "login")
    # A second limit per account, so a distributed guesser cannot hammer one user from many addresses.
    hit(f"login-account:{sha256_hex(email)[:32]}", get_settings().login_rate_limit_per_minute * 3, 900)
    invalid = ApiError(401, "Invalid email or password", "INVALID_CREDENTIALS")
    with session(None, None, email, request.state.request_id) as db:
        row = db.one("SELECT * FROM prov.auth_user_by_email(%s)", (email,))
        if not row:
            verify_password(password, _DUMMY_HASH)
            raise invalid
        if not verify_password(password, row["password_hash"]):
            _mark(request, row["tenant_id"], row["user_id"], email, "auth.login_failed", reason="wrong password")
            raise invalid
        if not row["is_active"]:
            _mark(request, row["tenant_id"], row["user_id"], email, "auth.login_blocked", reason="account deactivated")
            raise ApiError(403, "Account is deactivated", "ACCOUNT_DEACTIVATED")
        _as_user(db, row["tenant_id"], row["user_id"], email)
        if db.scalar("SELECT status FROM tenants") != "ACTIVE":
            _mark(request, row["tenant_id"], row["user_id"], email, "auth.login_blocked", reason="organization suspended")
            raise ApiError(403, "This organization is suspended. Contact support.", "ORGANIZATION_SUSPENDED")
        _mark(request, row["tenant_id"], row["user_id"], email, "auth.login")
        if password_needs_rehash(row["password_hash"]):
            db.execute("UPDATE users SET password_hash = %s WHERE user_id = %s",
                       (hash_password(password), row["user_id"]))
        db.execute("UPDATE users SET last_login_at = now() WHERE user_id = %s", (row["user_id"],))
        result = _issue(db, request, response, row)
        db.commit()
    return result


@router.post("/login", summary="Sign in with email and password")
def login(body: LoginIn, request: Request, response: Response):
    return _login(request, response, body.email, body.password)


@router.post("/token", summary="OAuth2 password flow (used by the Swagger 'Authorize' button)",
             include_in_schema=False)
def token(request: Request, response: Response, form: OAuth2PasswordRequestForm = Depends()):
    return _login(request, response, form.username, form.password)


def _presented(request: Request, body: RefreshIn | None) -> str:
    token = (body.refresh_token if body else None) or request.cookies.get(COOKIE)
    if not token:
        raise ApiError(401, "No refresh token", "INVALID_REFRESH_TOKEN")
    return token


@router.post("/refresh", summary="Exchange a refresh token for a new token pair (rotates the refresh token)")
def refresh(request: Request, response: Response, body: RefreshIn | None = None):
    rate_limit(request, "refresh", limit=120)
    invalid = ApiError(401, "Invalid or expired refresh token", "INVALID_REFRESH_TOKEN")
    token_hash = sha256_hex(_presented(request, body))
    with session(None, None, None, request.state.request_id) as db:
        found = db.one("SELECT * FROM prov.auth_refresh_token(%s)", (token_hash,))
        if not found:
            _clear_cookie(response)
            raise invalid
        db.rollback()
        db.use(Context(found["tenant_id"], found["user_id"], None, db.ctx.request_id))
        if db.scalar("SELECT status FROM tenants") != "ACTIVE":
            db.rollback()
            _clear_cookie(response)
            raise ApiError(403, "This organization is suspended. Contact support.", "ORGANIZATION_SUSPENDED")
        # Lock the row: two concurrent refreshes of the same token must not both succeed.
        tok = db.one("SELECT token_id, family_id, expires_at, used_at, revoked_at FROM refresh_tokens "
                     "WHERE token_id = %s FOR UPDATE", (found["token_id"],))
        user = db.one(_USER_SQL, (found["user_id"],))
        now = datetime.now(UTC)
        if not tok or not user or tok["revoked_at"] is not None or tok["expires_at"] <= now or not user["is_active"]:
            db.rollback()
            _clear_cookie(response)
            raise invalid
        if tok["used_at"] is not None:
            if now - tok["used_at"] <= ROTATION_GRACE:
                db.rollback()
                raise ApiError(409, "This refresh token was just rotated; retry with the new one", "TOKEN_ROTATED")
            # A rotated token came back: it was copied. Kill every session descended from that login.
            db.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = %s AND revoked_at IS NULL",
                       (tok["family_id"],))
            _mark(request, user["tenant_id"], user["user_id"], user["email"], "auth.token_reuse",
                  family_id=str(tok["family_id"]))
            emit_event(db, "security.refresh_token_reuse", "user", user["user_id"],
                       {"user_id": user["user_id"], "email": user["email"], "family_id": str(tok["family_id"])})
            db.commit()
            _clear_cookie(response)
            raise ApiError(401, "Refresh token reuse detected; all sessions from that sign-in were revoked",
                           "TOKEN_REUSED")
        result = _issue(db, request, response, user, family_id=tok["family_id"], replaces=tok["token_id"])
        db.commit()
    return result


@router.post("/logout", status_code=204, summary="End this session (revokes its refresh tokens)")
def logout(request: Request, response: Response, body: RefreshIn | None = None):
    token = (body.refresh_token if body else None) or request.cookies.get(COOKIE)
    if token:
        with session(None, None, None, request.state.request_id) as db:
            found = db.one("SELECT * FROM prov.auth_refresh_token(%s)", (sha256_hex(token),))
            if found:
                db.rollback()
                db.use(Context(found["tenant_id"], found["user_id"], None, db.ctx.request_id))
                db.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = %s AND revoked_at IS NULL",
                           (found["family_id"],))
                email = db.scalar("SELECT email FROM users WHERE user_id = %s", (found["user_id"],))
                db.commit()
                _mark(request, found["tenant_id"], found["user_id"], email or f"user:{found['user_id']}", "auth.logout")
    _clear_cookie(response)
    response.status_code = 204


def _revoke_all(db: Db, user_id: int) -> None:
    db.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL", (user_id,))
    db.execute("UPDATE users SET token_version = token_version + 1 WHERE user_id = %s", (user_id,))


@router.post("/logout-all", status_code=204, summary="Sign out everywhere (revokes every token for this user)")
def logout_all(response: Response, ctx: Ctx = Depends(any_user)):
    assert ctx.principal.user_id is not None
    _revoke_all(ctx.db, ctx.principal.user_id)
    ctx.db.commit()
    _clear_cookie(response)
    response.status_code = 204


@router.post("/password", summary="Change your password (signs out every other session)")
def change_password(body: PasswordChangeIn, request: Request, response: Response, ctx: Ctx = Depends(any_user)):
    db, user_id = ctx.db, ctx.principal.user_id
    assert user_id is not None
    hit(f"password:{user_id}", 10, 900)
    current = db.scalar("SELECT password_hash FROM users WHERE user_id = %s FOR UPDATE", (user_id,))
    if not verify_password(body.current_password, current):
        db.rollback()
        raise ApiError(403, "Current password is incorrect", "INVALID_CREDENTIALS")
    if body.new_password == body.current_password:
        db.rollback()
        raise ApiError(422, "The new password must differ from the current one", "VALIDATION_ERROR")
    db.execute("UPDATE users SET password_hash = %s, password_changed_at = now() WHERE user_id = %s",
               (hash_password(body.new_password), user_id))
    _revoke_all(db, user_id)
    user = db.one(_USER_SQL, (user_id,))
    assert user is not None
    result = _issue(db, request, response, user)
    db.commit()
    return result


@router.get("/me", summary="Current user, organization and permissions")
def me(ctx: Ctx = Depends(any_user)):
    row = ctx.db.one(_USER_SQL, (ctx.principal.user_id,))
    assert row is not None
    return public_user(row)
