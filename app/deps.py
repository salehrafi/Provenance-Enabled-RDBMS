from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

from app.db import Db, system_session, tenant_session
from app.security import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)

ROLE_RANK = {"viewer": 0, "staff": 1, "admin": 2}


@dataclass(frozen=True)
class CurrentUser:
    user_id: int
    tenant_id: int
    email: str
    full_name: str
    role: str

    def has_role(self, minimum: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[minimum]


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"})


def get_current_user(token: str | None = Depends(oauth2_scheme)) -> CurrentUser:
    if not token:
        raise _unauthorized()
    try:
        payload = decode_token(token, "access")
    except jwt.ExpiredSignatureError:
        raise _unauthorized("Token expired")
    except jwt.PyJWTError:
        raise _unauthorized("Invalid token")
    # Look the user up on every request so deactivation and role changes apply immediately.
    with system_session() as db:
        row = db.one(
            "SELECT user_id, tenant_id, email, full_name, role, is_active FROM app_users WHERE user_id = :id",
            {"id": int(payload["sub"])},
        )
    if not row or row["is_active"] != "Y":
        raise _unauthorized("User is inactive or no longer exists")
    return CurrentUser(int(row["user_id"]), int(row["tenant_id"]), row["email"], row["full_name"], row["role"])


def require_role(minimum: str):
    def dependency(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not user.has_role(minimum):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires role '{minimum}' or higher")
        return user

    return dependency


def get_db(request: Request, user: CurrentUser = Depends(get_current_user)) -> Iterator[Db]:
    """Tenant-scoped connection: VPD filters rows, triggers record this user as the actor."""
    with tenant_session(user.tenant_id, user.user_id, user.email, request.state.request_id) as db:
        yield db


viewer = require_role("viewer")
staff = require_role("staff")
admin = require_role("admin")
