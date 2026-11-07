from __future__ import annotations

import re
import secrets

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from app.db import system_session
from app.deps import CurrentUser, get_current_user
from app.ratelimit import rate_limit
from app.schemas import LoginIn, RefreshIn, SignupIn
from app.security import create_tokens, decode_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

# Verify against a dummy hash when the email is unknown, so response time does not reveal
# which emails are registered.
_DUMMY_HASH = hash_password(secrets.token_hex(16))

_USER_SQL = """
    SELECT u.user_id, u.tenant_id, u.email, u.full_name, u.role, u.is_active, u.password_hash,
           t.name AS tenant_name, t.slug AS tenant_slug, t.plan
      FROM app_users u JOIN tenants t ON t.tenant_id = u.tenant_id
"""


def _public(row: dict) -> dict:
    return {
        "user_id": row["user_id"],
        "email": row["email"],
        "full_name": row["full_name"],
        "role": row["role"],
        "tenant": {"tenant_id": row["tenant_id"], "name": row["tenant_name"], "slug": row["tenant_slug"],
                   "plan": row["plan"]},
    }


def _slug(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "org"
    return f"{base}-{secrets.token_hex(3)}"


@router.post("/signup", status_code=status.HTTP_201_CREATED, summary="Create an organization and its first admin")
def signup(body: SignupIn, request: Request):
    rate_limit(request, "signup")
    email = body.email.lower()
    with system_session() as db:
        if db.scalar("SELECT COUNT(*) FROM app_users WHERE email = :e", {"e": email}):
            raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
        tenant_id = db.insert(
            "INSERT INTO tenants (name, slug) VALUES (:n, :s)", {"n": body.organization, "s": _slug(body.organization)},
            "tenant_id",
        )
        # Switch the session into the new tenant so the VPD-protected settings row is allowed.
        db.callproc("ctx_pkg.set_ctx", [tenant_id, None, email, request.state.request_id])
        db.execute("INSERT INTO tenant_settings (tenant_id) VALUES (:t)", {"t": tenant_id})
        db.insert(
            "INSERT INTO app_users (tenant_id, email, full_name, password_hash, role) "
            "VALUES (:t, :e, :n, :h, 'admin')",
            {"t": tenant_id, "e": email, "n": body.full_name, "h": hash_password(body.password)},
            "user_id",
        )
        db.commit()
        row = db.one(_USER_SQL + " WHERE u.email = :e", {"e": email})
    return {**create_tokens(row), "user": _public(row)}


def _login(email: str, password: str) -> dict:
    with system_session() as db:
        row = db.one(_USER_SQL + " WHERE u.email = :e", {"e": email.lower()})
        if not row:
            verify_password(password, _DUMMY_HASH)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
        if not verify_password(password, row["password_hash"]):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
        if row["is_active"] != "Y":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is deactivated")
        db.execute("UPDATE app_users SET last_login_at = SYS_EXTRACT_UTC(SYSTIMESTAMP) WHERE user_id = :id",
                   {"id": row["user_id"]})
        db.commit()
    return {**create_tokens(row), "user": _public(row)}


@router.post("/login", summary="Log in with email and password (JSON)")
def login(body: LoginIn, request: Request):
    rate_limit(request, "login")
    return _login(body.email, body.password)


@router.post("/token", summary="OAuth2 password flow (used by the Swagger 'Authorize' button)")
def token(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    rate_limit(request, "login")
    return _login(form.username, form.password)


@router.post("/refresh", summary="Exchange a refresh token for a new token pair")
def refresh(body: RefreshIn):
    try:
        payload = decode_token(body.refresh_token, "refresh")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")
    with system_session() as db:
        row = db.one(_USER_SQL + " WHERE u.user_id = :id", {"id": int(payload["sub"])})
    if not row or row["is_active"] != "Y":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User is inactive or no longer exists")
    return {**create_tokens(row), "user": _public(row)}


@router.get("/me", summary="Current user and organization")
def me(user: CurrentUser = Depends(get_current_user)):
    with system_session() as db:
        row = db.one(_USER_SQL + " WHERE u.user_id = :id", {"id": user.user_id})
    return _public(row)
