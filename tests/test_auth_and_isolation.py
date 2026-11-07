from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import ratelimit
from app.db import tenant_session
from tests.conftest import PASSWORD


def test_login_me_refresh(client, org):
    r = client.post("/api/v1/auth/login", json={"email": org.admin_email, "password": PASSWORD})
    assert r.status_code == 200
    tokens = r.json()
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()
    assert me["role"] == "admin" and me["tenant"]["tenant_id"] == org.tenant_id
    r = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200 and r.json()["access_token"]
    # an access token is not accepted as a refresh token
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["access_token"]}).status_code == 401


def test_wrong_password_and_missing_token(client, org):
    assert client.post("/api/v1/auth/login", json={"email": org.admin_email, "password": "nope-nope-nope"}).status_code == 401
    assert client.get("/api/v1/customers").status_code == 401
    assert client.get("/api/v1/customers", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_rbac_viewer_is_read_only(org):
    viewer = org.add_user("viewer")
    org.req("GET", "/customers", token=viewer, expect=200)
    org.req("POST", "/customers", {"name": "X", "email": "x@example.com"}, token=viewer, expect=403)
    org.req("GET", "/users", token=viewer, expect=403)


def test_deactivated_user_is_rejected_immediately(org):
    staff = org.add_user("staff")
    users = org.req("GET", "/users", expect=200).json()
    staff_id = next(u["user_id"] for u in users if u["role"] == "staff")
    org.req("PATCH", f"/users/{staff_id}", {"is_active": False}, expect=200)
    org.req("GET", "/customers", token=staff, expect=401)


def test_tenant_isolation_via_vpd(org, other_org):
    cid = org.customer()
    pid = org.product()
    # the other tenant cannot read, list, update or reference these rows
    other_org.req("GET", f"/customers/{cid}", expect=404)
    assert cid not in [c["customer_id"] for c in other_org.req("GET", "/customers", expect=200).json()["items"]]
    other_org.req("PATCH", f"/products/{pid}", {"name": "hijacked"}, expect=404)
    other_org.req("POST", "/orders", {"customer_id": cid, "items": []}, expect=422)
    assert other_org.req("GET", f"/provenance/customer/{cid}/history", expect=200).json()["history"] == []


def test_vpd_blocks_cross_tenant_insert_at_database_level(org, other_org):
    import oracledb

    with tenant_session(other_org.tenant_id, None, "test", "t") as db:
        with pytest.raises(oracledb.DatabaseError) as exc:
            db.execute("INSERT INTO customers (tenant_id, name, email) VALUES (:t, 'evil', 'e@example.com')",
                       {"t": org.tenant_id})
        assert "ORA-28115" in str(exc.value)


def test_no_context_means_no_rows(org):
    org.customer()
    with tenant_session(None, None, "test", "t") as db:
        assert db.scalar("SELECT COUNT(*) FROM customers") == 0
        assert db.scalar("SELECT COUNT(*) FROM audit_log") == 0


def test_rate_limiter():
    ratelimit.reset()
    scope = {"type": "http", "client": ("10.0.0.1", 1234), "headers": []}
    req = Request(scope)
    for _ in range(3):
        ratelimit.rate_limit(req, "unit", limit=3)
    with pytest.raises(HTTPException) as exc:
        ratelimit.rate_limit(req, "unit", limit=3)
    assert exc.value.status_code == 429
    ratelimit.reset()
