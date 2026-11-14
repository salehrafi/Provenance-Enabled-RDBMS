from __future__ import annotations

from fastapi import APIRouter, Depends

from app.auth import ALL_PERMISSIONS, ROLE_PERMISSIONS, Ctx, require, require_user
from app.errors import ApiError, not_found
from app.schemas import OrganizationUpdate, SettingsUpdate, UserCreate, UserUpdate
from app.security import hash_password

router = APIRouter(tags=["organization"])

_COLS = "user_id, email, full_name, role, is_active, created_at, last_login_at"


@router.get("/roles", summary="Roles and the permissions each one grants")
def list_roles(ctx: Ctx = Depends(require("settings:read"))):
    order = ["viewer", "auditor", "staff", "admin"]
    return {"items": [{"role": r, "permissions": sorted(ROLE_PERMISSIONS[r])} for r in order],
            "permissions": sorted(ALL_PERMISSIONS)}


@router.get("/users", summary="List users in your organization")
def list_users(ctx: Ctx = Depends(require("users:manage"))):
    return {"items": ctx.db.all(f"SELECT {_COLS} FROM users ORDER BY user_id")}


@router.post("/users", status_code=201, summary="Add a user to your organization")
def create_user(body: UserCreate, ctx: Ctx = Depends(require_user("users:manage"))):
    # A duplicate email (in any organization) violates uq_users_email -> 409 EMAIL_TAKEN.
    new_id = ctx.db.insert(
        "INSERT INTO users (email, full_name, password_hash, role) VALUES (%s, %s, %s, %s)",
        (body.email.lower(), body.full_name, hash_password(body.password), body.role), "user_id")
    ctx.db.commit()
    return ctx.db.one(f"SELECT {_COLS} FROM users WHERE user_id = %s", (new_id,))


@router.patch("/users/{user_id}", summary="Change a user's role, name or status")
def update_user(user_id: int, body: UserUpdate, ctx: Ctx = Depends(require_user("users:manage"))):
    db = ctx.db
    target = db.one(f"SELECT {_COLS} FROM users WHERE user_id = %s FOR UPDATE", (user_id,))
    if not target:
        raise not_found("User")
    if user_id == ctx.principal.user_id and (body.is_active is False or (body.role and body.role != "admin")):
        raise ApiError(400, "You cannot demote or deactivate yourself", "SELF_LOCKOUT")
    sets: list[str] = []
    params: list[object] = []
    if body.full_name is not None:
        sets.append("full_name = %s")
        params.append(body.full_name)
    if body.role is not None:
        sets.append("role = %s")
        params.append(body.role)
    if body.is_active is not None:
        sets.append("is_active = %s")
        params.append(body.is_active)
    if sets:
        db.execute(f"UPDATE users SET {', '.join(sets)} WHERE user_id = %s", (*params, user_id))
        if body.is_active is False:
            # Cut existing sessions immediately rather than waiting for token expiry.
            db.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL",
                       (user_id,))
            db.execute("UPDATE users SET token_version = token_version + 1 WHERE user_id = %s", (user_id,))
        db.commit()  # the "keep one active admin" constraint is checked here (409 LAST_ADMIN)
    return db.one(f"SELECT {_COLS} FROM users WHERE user_id = %s", (user_id,))


@router.patch("/organization", summary="Rename your organization")
def update_organization(body: OrganizationUpdate, ctx: Ctx = Depends(require_user("settings:manage"))):
    ctx.db.execute("UPDATE tenants SET name = %s WHERE tenant_id = %s", (body.name, ctx.tenant_id))
    ctx.db.commit()
    return ctx.db.one("SELECT tenant_id, name, slug, plan, created_at FROM tenants")


@router.get("/settings", summary="Organization settings (thresholds for approvals and alerts)")
def get_settings_(ctx: Ctx = Depends(require("settings:read"))):
    return ctx.db.one("SELECT * FROM tenant_settings")


@router.patch("/settings", summary="Update organization settings")
def update_settings(body: SettingsUpdate, ctx: Ctx = Depends(require_user("settings:manage"))):
    fields = body.model_dump(exclude_none=True)
    if fields:
        # Column names come from the Pydantic model's field names, never from the client.
        sets = ", ".join(f"{k} = %({k})s" for k in fields)
        ctx.db.execute(f"UPDATE tenant_settings SET {sets} WHERE tenant_id = %(_tenant)s",
                       {**fields, "_tenant": ctx.tenant_id})
        ctx.db.commit()
    return ctx.db.one("SELECT * FROM tenant_settings")
