"""Authentication, sessions, RBAC and API-key scopes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app import ratelimit
from app.config import get_settings
from app.db import tenant_session
from tests.conftest import PASSWORD

LOGIN = "/api/v1/auth/login"
REFRESH = "/api/v1/auth/refresh"


def login(client, org, password=PASSWORD):
    client.cookies.clear()
    r = client.post(LOGIN, json={"email": org.admin_email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def test_login_me_and_permissions(client, org):
    tokens = login(client, org)
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()
    assert me["role"] == "admin" and me["tenant"]["tenant_id"] == org.tenant_id
    assert "users:manage" in me["permissions"] and "events:write" not in me["permissions"]


def test_wrong_password_unknown_user_and_missing_token_look_alike(client, org):
    bad = client.post(LOGIN, json={"email": org.admin_email, "password": "nope-nope-nope"})
    unknown = client.post(LOGIN, json={"email": "nobody@example.com", "password": "nope-nope-nope"})
    assert bad.status_code == unknown.status_code == 401
    assert bad.json()["code"] == unknown.json()["code"] == "INVALID_CREDENTIALS"
    assert bad.json()["detail"] == unknown.json()["detail"]
    assert client.get("/api/v1/customers").status_code == 401
    assert client.get("/api/v1/customers", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_error_body_is_problem_json_with_code_and_request_id(client):
    r = client.get("/api/v1/customers", headers={"X-Request-ID": "trace-123"})
    assert r.status_code == 401 and r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["code"] == "UNAUTHENTICATED" and body["request_id"] == "trace-123" and r.headers["x-request-id"] == "trace-123"


def test_expired_and_forged_tokens_are_rejected(client, org):
    s = get_settings()
    now = datetime.now(UTC)
    claims = {"iss": "provenance-cloud", "sub": str(org.user_id), "tid": org.tenant_id, "ver": 1, "typ": "access",
              "iat": now - timedelta(hours=2), "exp": now - timedelta(hours=1)}
    expired = jwt.encode(claims, s.jwt_secret, algorithm="HS256")
    assert client.get("/api/v1/customers", headers={"Authorization": f"Bearer {expired}"}).json()["code"] == "TOKEN_EXPIRED"
    forged = jwt.encode({**claims, "exp": now + timedelta(hours=1)}, "x" * 40, algorithm="HS256")
    assert client.get("/api/v1/customers", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    none_alg = jwt.encode({**claims, "exp": now + timedelta(hours=1)}, None, algorithm="none")
    assert client.get("/api/v1/customers", headers={"Authorization": f"Bearer {none_alg}"}).status_code == 401
    # a valid signature but another tenant id in the claim cannot reach that tenant's data
    other = jwt.encode({**claims, "exp": now + timedelta(hours=1), "tid": org.tenant_id + 9999}, s.jwt_secret, algorithm="HS256")
    assert client.get("/api/v1/customers", headers={"Authorization": f"Bearer {other}"}).status_code == 401


def test_refresh_rotates_and_cookie_flags(client, org):
    client.cookies.clear()
    r = client.post(LOGIN, json={"email": org.admin_email, "password": PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/api/v1/auth" in cookie
    first = r.json()["refresh_token"]
    r2 = client.post(REFRESH)  # cookie only, no body
    assert r2.status_code == 200 and r2.json()["refresh_token"] != first
    # an access token is not a refresh token
    client.cookies.clear()
    assert client.post(REFRESH, json={"refresh_token": r2.json()["access_token"]}).status_code in (401, 422)
    assert client.post(REFRESH, json={"refresh_token": "prt_" + "x" * 60}).json()["code"] == "INVALID_REFRESH_TOKEN"


def test_refresh_token_reuse_revokes_the_whole_family(client, org, admin_conn):
    client.cookies.clear()
    t1 = client.post(LOGIN, json={"email": org.admin_email, "password": PASSWORD}).json()["refresh_token"]
    client.cookies.clear()
    # immediate second use (two tabs racing) is told to retry, and nothing is revoked
    t2 = client.post(REFRESH, json={"refresh_token": t1}).json()["refresh_token"]
    client.cookies.clear()
    race = client.post(REFRESH, json={"refresh_token": t1})
    assert race.status_code == 409 and race.json()["code"] == "TOKEN_ROTATED"
    # outside the grace window the same replay means theft: whole family dies, including the new token
    admin_conn.execute("UPDATE prov.refresh_tokens SET used_at = used_at - interval '5 minutes' WHERE used_at IS NOT NULL")
    client.cookies.clear()
    replay = client.post(REFRESH, json={"refresh_token": t1})
    assert replay.status_code == 401 and replay.json()["code"] == "TOKEN_REUSED"
    client.cookies.clear()
    assert client.post(REFRESH, json={"refresh_token": t2}).status_code == 401
    event = admin_conn.execute("SELECT count(*) FROM prov.outbox_events WHERE tenant_id = %s "
                               "AND event_type = 'security.refresh_token_reuse'", (org.tenant_id,)).fetchone()
    assert event[0] == 1


def test_expired_refresh_token_is_rejected(client, org, admin_conn):
    t = login(client, org)["refresh_token"]
    admin_conn.execute("UPDATE prov.refresh_tokens SET expires_at = now() - interval '1 second' WHERE tenant_id = %s",
                       (org.tenant_id,))
    client.cookies.clear()
    assert client.post(REFRESH, json={"refresh_token": t}).status_code == 401


def test_logout_revokes_refresh_token(client, org):
    t = login(client, org)["refresh_token"]
    assert client.post("/api/v1/auth/logout", json={"refresh_token": t}).status_code == 204
    client.cookies.clear()
    assert client.post(REFRESH, json={"refresh_token": t}).status_code == 401


def test_password_change_revokes_old_access_and_refresh_tokens(client, org):
    old = login(client, org)
    r = client.post("/api/v1/auth/password", headers={"Authorization": f"Bearer {old['access_token']}"},
                    json={"current_password": "wrong-password-1", "new_password": "a-brand-new-password"})
    assert r.status_code == 403
    r = client.post("/api/v1/auth/password", headers={"Authorization": f"Bearer {old['access_token']}"},
                    json={"current_password": PASSWORD, "new_password": "a-brand-new-password"})
    assert r.status_code == 200
    assert client.get("/api/v1/customers", headers={"Authorization": f"Bearer {old['access_token']}"}).json()["code"] == "TOKEN_REVOKED"
    client.cookies.clear()
    assert client.post(REFRESH, json={"refresh_token": old["refresh_token"]}).status_code == 401
    assert client.get("/api/v1/customers", headers={"Authorization": f"Bearer {r.json()['access_token']}"}).status_code == 200
    assert client.post(LOGIN, json={"email": org.admin_email, "password": PASSWORD}).status_code == 401


def test_logout_all_invalidates_access_tokens(client, org):
    t = login(client, org)
    h = {"Authorization": f"Bearer {t['access_token']}"}
    assert client.post("/api/v1/auth/logout-all", headers=h).status_code == 204
    assert client.get("/api/v1/customers", headers=h).status_code == 401


def test_signup_validation_and_duplicate_email(client, org):
    weak = client.post("/api/v1/auth/signup", json={"organization": "Weak Co", "full_name": "W", "email": "w@example.com", "password": "short"})
    assert weak.status_code == 422
    dup = client.post("/api/v1/auth/signup", json={"organization": "Dup Co", "full_name": "Dup Admin",
                                                    "email": org.admin_email.upper(), "password": PASSWORD})
    assert dup.status_code == 409 and dup.json()["code"] == "EMAIL_TAKEN"
    extra = client.post("/api/v1/auth/signup", json={"organization": "X Co", "full_name": "X Admin", "email": "x@example.com",
                                                      "password": PASSWORD, "role": "admin"})
    assert extra.status_code == 422  # unknown fields are rejected


def test_rbac_matrix(org):
    viewer, auditor, staff = org.add_user("viewer"), org.add_user("auditor"), org.add_user("staff")
    for t in (viewer, auditor, staff):
        org.req("GET", "/customers", token=t, expect=200)
    org.req("POST", "/customers", {"name": "X", "email": "x@example.com"}, token=viewer, expect=403)
    org.req("POST", "/customers", {"name": "X", "email": "x@example.com"}, token=auditor, expect=403)
    org.req("POST", "/customers", {"name": "Y", "email": "y@example.com"}, token=staff, expect=201)
    org.req("GET", "/audit/export", token=viewer, expect=403)
    org.req("GET", "/audit/export", token=auditor, expect=200)
    org.req("POST", "/audit/verify", token=viewer, expect=403)
    org.req("POST", "/audit/verify", token=auditor, expect=200)
    for t in (viewer, auditor, staff):
        org.req("GET", "/users", token=t, expect=403)
        org.req("POST", "/webhooks", {"url": "https://example.com/h"}, token=t, expect=403)
        org.req("POST", "/api-keys", {"name": "k", "scopes": ["events:read"]}, token=t, expect=403)
        org.req("PATCH", "/settings", {"currency": "EUR"}, token=t, expect=403)
    org.req("DELETE", "/customers/1", token=staff, expect=403)  # delete is admin-only
    assert org.req("GET", "/roles", token=viewer, expect=200).json()["items"][0]["role"] == "viewer"


def test_deactivated_user_is_rejected_immediately_and_cannot_refresh(client, org):
    email = f"staff-{uuid.uuid4().hex[:6]}@example.com"
    org.req("POST", "/users", {"email": email, "full_name": "Temp Staff", "password": PASSWORD, "role": "staff"}, expect=201)
    client.cookies.clear()
    t = client.post(LOGIN, json={"email": email, "password": PASSWORD}).json()
    uid = next(u["user_id"] for u in org.req("GET", "/users", expect=200).json()["items"] if u["email"] == email)
    org.req("PATCH", f"/users/{uid}", {"is_active": False}, expect=200)
    assert client.get("/api/v1/customers", headers={"Authorization": f"Bearer {t['access_token']}"}).status_code == 401
    client.cookies.clear()
    assert client.post(REFRESH, json={"refresh_token": t["refresh_token"]}).status_code == 401
    assert client.post(LOGIN, json={"email": email, "password": PASSWORD}).status_code == 403


def test_admin_cannot_demote_themselves_and_db_keeps_one_admin(org):
    org.req("PATCH", f"/users/{org.user_id}", {"role": "viewer"}, expect=400)
    with tenant_session(org.tenant_id, org.user_id, org.admin_email, "t") as db:
        with pytest.raises(Exception) as exc:
            db.execute("UPDATE users SET is_active = false WHERE user_id = %s", (org.user_id,))
            db.commit()  # deferred constraint fires at commit
    assert "PV020" in str(getattr(exc.value, "sqlstate", "")) or "at least one active admin" in str(exc.value)


def test_user_creation_across_organizations_cannot_steal_an_email(org, other_org):
    r = org.req("POST", "/users", {"email": other_org.admin_email, "full_name": "Dup", "password": PASSWORD, "role": "viewer"})
    assert r.status_code == 409 and r.json()["code"] == "EMAIL_TAKEN"


def test_login_is_rate_limited_per_address_and_per_account(client, org, monkeypatch):
    ratelimit.reset()
    monkeypatch.setattr(get_settings(), "login_rate_limit_per_minute", 3)
    codes = [client.post(LOGIN, json={"email": f"u{i}@example.com", "password": "nope-nope-nope"}).status_code for i in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]
    r = client.post(LOGIN, json={"email": "x@example.com", "password": "nope-nope-nope"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1 and r.json()["code"] == "RATE_LIMITED"


def test_rate_limiter_window():
    from fastapi import HTTPException
    from starlette.requests import Request

    ratelimit.reset()
    req = Request({"type": "http", "client": ("10.0.0.1", 1234), "headers": []})
    for _ in range(3):
        ratelimit.rate_limit(req, "unit", limit=3)
    with pytest.raises(HTTPException) as exc:
        ratelimit.rate_limit(req, "unit", limit=3)
    assert exc.value.status_code == 429


def test_redis_rate_limiter_is_shared_via_fakeredis():
    import fakeredis
    from fastapi import HTTPException

    ratelimit.reset()
    ratelimit.set_redis_client(fakeredis.FakeRedis())
    try:
        for _ in range(2):
            ratelimit.hit("k", 2)
        with pytest.raises(HTTPException):
            ratelimit.hit("k", 2)
    finally:
        ratelimit.set_redis_client(None)
        ratelimit.reset()


# ---- API keys -------------------------------------------------------------------------------
def test_api_key_scopes_and_lifecycle(client, org, admin_conn):
    writer = org.api_key(("events:write",))
    h = {"Authorization": f"Bearer {writer}"}
    assert client.get("/api/v1/customers", headers=h).status_code == 403          # people-only data
    assert client.get("/api/v1/ingested-events", headers=h).status_code == 403    # lacks events:read
    assert client.get("/api/v1/users", headers=h).status_code == 403
    assert client.post("/api/v1/webhooks", headers=h, json={"url": "https://example.com/x"}).status_code == 403
    assert client.get("/api/v1/auth/me", headers=h).status_code == 403
    # secrets are never listed, and revoking works immediately
    listed = org.req("GET", "/api-keys", expect=200).json()["items"]
    assert "secret_hash" not in listed[0] and "api_key" not in listed[0]
    org.req("DELETE", f"/api-keys/{writer.split('_')[1]}", expect=204)
    assert client.get("/api/v1/ingested-events", headers=h).json()["code"] == "API_KEY_REVOKED"


def test_api_key_expiry_malformed_and_wrong_secret(client, org, admin_conn):
    key = org.req("POST", "/api-keys", {"name": "short-lived", "scopes": ["events:read"], "expires_in_days": 1}, expect=201).json()
    h = {"Authorization": f"Bearer {key['api_key']}"}
    assert client.get("/api/v1/ingested-events", headers=h).status_code == 200
    admin_conn.execute("UPDATE prov.api_keys SET expires_at = now() - interval '1 minute' WHERE key_id = %s", (key["key_id"],))
    assert client.get("/api/v1/ingested-events", headers=h).json()["code"] == "API_KEY_EXPIRED"
    wrong = f"prv_{key['key_id']}_{'A' * 43}"
    assert client.get("/api/v1/ingested-events", headers={"Authorization": f"Bearer {wrong}"}).json()["code"] == "INVALID_API_KEY"
    assert client.get("/api/v1/ingested-events", headers={"Authorization": "Bearer prv_bad"}).json()["code"] == "INVALID_API_KEY"
    # the plaintext secret is not stored anywhere
    secret = key["api_key"].split("_", 2)[2]
    stored = admin_conn.execute("SELECT secret_hash FROM prov.api_keys WHERE key_id = %s", (key["key_id"],)).fetchone()[0]
    assert secret not in stored and len(stored) == 64


def test_api_key_rate_limit_is_per_key(client, org, monkeypatch):
    ratelimit.reset()
    monkeypatch.setattr(get_settings(), "api_key_rate_limit_per_minute", 2)
    a, b = org.api_key(("events:read",)), org.api_key(("events:read",))
    ha, hb = ({"Authorization": f"Bearer {k}"} for k in (a, b))
    assert [client.get("/api/v1/ingested-events", headers=ha).status_code for _ in range(3)] == [200, 200, 429]
    assert client.get("/api/v1/ingested-events", headers=hb).status_code == 200  # other keys unaffected


def test_security_headers_and_body_limit(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    big = client.post("/api/v1/auth/login", content=b"x" * (7 * 1024 * 1024), headers={"content-type": "application/json"})
    assert big.status_code == 413 and big.json()["code"] == "PAYLOAD_TOO_LARGE"


def test_password_minimum_is_six_characters(client):
    base = {"organization": "Short Pw Co", "full_name": "Short Pw"}
    too_short = client.post("/api/v1/auth/signup", json={**base, "email": f"s5-{uuid.uuid4().hex[:6]}@example.com", "password": "12345"})
    assert too_short.status_code == 422 and "password" in too_short.text
    email = f"s6-{uuid.uuid4().hex[:6]}@example.com"
    ok = client.post("/api/v1/auth/signup", json={**base, "email": email, "password": "123456"})
    assert ok.status_code == 201
    client.cookies.clear()
    assert client.post(LOGIN, json={"email": email, "password": "123456"}).status_code == 200
