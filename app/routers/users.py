from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.common import not_found
from app.db import Db
from app.deps import CurrentUser, admin, get_db, viewer
from app.schemas import SettingsUpdate, UserCreate, UserUpdate
from app.security import hash_password

router = APIRouter(tags=["organization"])

_COLS = "user_id, email, full_name, role, is_active, created_at, last_login_at"


@router.get("/users", summary="List users in your organization")
def list_users(user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    # app_users is not VPD-protected (login must find users across tenants), so filter here.
    return db.all(f"SELECT {_COLS} FROM app_users WHERE tenant_id = :t ORDER BY user_id", {"t": user.tenant_id})


@router.post("/users", status_code=status.HTTP_201_CREATED, summary="Invite a user")
def create_user(body: UserCreate, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    email = body.email.lower()
    if db.scalar("SELECT COUNT(*) FROM app_users WHERE email = :e", {"e": email}):
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
    new_id = db.insert(
        "INSERT INTO app_users (tenant_id, email, full_name, password_hash, role) VALUES (:t, :e, :n, :h, :r)",
        {"t": user.tenant_id, "e": email, "n": body.full_name, "h": hash_password(body.password), "r": body.role},
        "user_id",
    )
    db.commit()
    return db.one(f"SELECT {_COLS} FROM app_users WHERE user_id = :id", {"id": new_id})


@router.patch("/users/{user_id}", summary="Change a user's role, name or status")
def update_user(user_id: int, body: UserUpdate, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    target = db.one(f"SELECT {_COLS} FROM app_users WHERE user_id = :id AND tenant_id = :t",
                    {"id": user_id, "t": user.tenant_id})
    if not target:
        raise not_found("User")
    if user_id == user.user_id and (body.is_active is False or (body.role and body.role != "admin")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot demote or deactivate yourself")
    params = {"id": user_id}
    sets = []
    if body.full_name is not None:
        sets.append("full_name = :n")
        params["n"] = body.full_name
    if body.role is not None:
        sets.append("role = :r")
        params["r"] = body.role
    if body.is_active is not None:
        sets.append("is_active = :a")
        params["a"] = "Y" if body.is_active else "N"
    if sets:
        db.execute(f"UPDATE app_users SET {', '.join(sets)} WHERE user_id = :id", params)
        db.commit()
    return db.one(f"SELECT {_COLS} FROM app_users WHERE user_id = :id", {"id": user_id})


@router.get("/settings", summary="Organization settings (thresholds for approvals and alerts)")
def get_settings_(user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    return db.one("SELECT * FROM tenant_settings")


@router.patch("/settings", summary="Update organization settings")
def update_settings(body: SettingsUpdate, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    fields = body.model_dump(exclude_none=True)
    if fields:
        sets = ", ".join(f"{k} = :{k}" for k in fields)  # keys come from the Pydantic model, not the client
        db.execute(f"UPDATE tenant_settings SET {sets}", fields)
        db.commit()
    return db.one("SELECT * FROM tenant_settings")
