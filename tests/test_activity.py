"""Security activity log: what is recorded, who can see it, that it cannot be changed, filters and export."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from app.config import get_settings
from app.db import tenant_session
from tests.conftest import CLIENT_IP, PASSWORD

LOGIN = "/api/v1/auth/login"


def activity(org, **params):
    return org.req("GET", "/activity", expect=200, limit=500, **params).json()["items"]


def actions(org, **params):
    return [a["action"] for a in activity(org, **params)]


def test_successful_and_failed_sign_ins_are_recorded_with_ip_and_user_agent(client, org):
    client.cookies.clear()
    assert client.post(LOGIN, json={"email": org.admin_email, "password": "wrong-password"},
                       headers={"User-Agent": "pytest-agent/1.0"}).status_code == 401
    assert client.post(LOGIN, json={"email": org.admin_email, "password": PASSWORD},
                       headers={"User-Agent": "pytest-agent/1.0"}).status_code == 200
    client.cookies.clear()
    rows = activity(org, action="auth.login")
    failed = next(r for r in rows if r["action"] == "auth.login_failed")
    ok = next(r for r in rows if r["action"] == "auth.login")
    assert failed["outcome"] == "DENIED" and failed["status_code"] == 401 and failed["actor"] == org.admin_email
    assert failed["details"]["reason"] == "wrong password"
    for r in (failed, ok):
        assert r["ip_address"] == CLIENT_IP and r["user_agent"] == "pytest-agent/1.0" and r["method"] == "POST"
    assert ok["outcome"] == "SUCCESS" and ok["actor_user_id"] == org.user_id
    assert "auth.signup" in actions(org)


def test_sign_in_for_unknown_email_is_not_attributed_to_any_organization(client, org, admin_conn):
    ghost = f"ghost-{uuid.uuid4().hex[:8]}@example.com"
    client.post(LOGIN, json={"email": ghost, "password": "whatever-123"})
    n = admin_conn.execute("SELECT count(*) FROM prov.activity_log WHERE actor = %s", (ghost,)).fetchone()[0]
    assert n == 0  # it is in the structured application log instead


def test_changes_are_recorded_with_outcome_including_denied_and_failed(org):
    cid = org.customer()
    org.req("PATCH", f"/customers/{cid}", {"name": "Renamed"}, expect=200)
    viewer = org.add_user("viewer")
    org.req("POST", "/customers", {"name": "X", "email": "x@example.com"}, token=viewer, expect=403)
    p = org.product("10.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    org.req("POST", f"/orders/{oid}/status", {"status": "SHIPPED"}, expect=409)  # rolled back, still recorded
    rows = activity(org)
    by_action = {(r["action"], r["outcome"]) for r in rows}
    assert ("POST /customers", "SUCCESS") in by_action
    assert ("PATCH /customers/{customer_id}", "SUCCESS") in by_action
    assert ("POST /customers", "DENIED") in by_action
    assert ("POST /orders/{order_id}/status", "FAILURE") in by_action
    patch = next(r for r in rows if r["action"] == "PATCH /customers/{customer_id}")
    assert patch["details"]["customer_id"] == str(cid) and patch["path"] == f"/api/v1/customers/{cid}"
    assert patch["request_id"] and patch["duration_ms"] is not None
    denied = next(r for r in rows if r["outcome"] == "DENIED" and r["action"] == "POST /customers")
    assert denied["actor"].startswith("viewer-")


def test_routine_reads_are_not_recorded_unless_enabled_but_sensitive_reads_are(org, monkeypatch):
    org.req("GET", "/customers", expect=200)
    org.req("GET", "/audit/export", expect=200)
    org.req("GET", "/api-keys", expect=200)
    got = actions(org)
    assert "GET /customers" not in got and "audit.export" in got and "GET /api-keys" in got
    monkeypatch.setattr(get_settings(), "activity_log_reads", True)
    org.req("GET", "/customers", expect=200)
    assert "GET /customers" in actions(org)


def test_viewing_and_exporting_the_log_is_itself_recorded_but_helper_lookups_are_not(org):
    org.req("GET", "/activity/summary", expect=200)
    org.req("GET", "/activity/actions", expect=200)
    org.req("GET", "/activity/export", expect=200, format="csv")
    org.req("GET", "/activity", expect=200)  # a view is recorded after its own response, so look one call later
    got = actions(org)
    assert "activity.export" in got and "activity.view" in got
    assert not any(a.endswith(("/activity/summary", "/activity/actions")) for a in got)


def test_only_admins_can_see_the_log(client, org):
    for role in ("viewer", "auditor", "staff"):
        token = org.add_user(role)
        for path in ("/activity", "/activity/export", "/activity/summary"):
            org.req("GET", path, token=token, expect=403)
    key = org.api_key(("events:read", "audit:read", "audit:export"))
    assert client.get("/api/v1/activity", headers={"Authorization": f"Bearer {key}"}).status_code == 403
    assert client.get("/api/v1/activity").status_code == 401
    second_admin = org.add_user("admin")
    org.req("GET", "/activity", token=second_admin, expect=200)


def test_organizations_never_see_each_others_activity(org, other_org):
    org.customer()
    mine = {r["activity_id"] for r in activity(org)}
    theirs = {r["activity_id"] for r in activity(other_org)}
    assert mine and theirs and mine.isdisjoint(theirs)
    some_id = next(iter(mine))
    other_org.req("GET", f"/activity/{some_id}", expect=404)
    with tenant_session(other_org.tenant_id, None, "t", "t") as db:
        assert db.scalar("SELECT count(*) FROM activity_log WHERE tenant_id = %s", (org.tenant_id,)) == 0


@pytest.mark.parametrize("statement", [
    "UPDATE activity_log SET actor = 'mallory'",
    "UPDATE activity_log SET ip_address = '10.0.0.1'",
    "DELETE FROM activity_log",
    "TRUNCATE activity_log",
    "ALTER TABLE activity_log DISABLE TRIGGER ALL",
])
def test_the_application_role_cannot_change_or_delete_the_log(org, statement):
    org.customer()
    with tenant_session(org.tenant_id, org.user_id, org.admin_email, "t") as db:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute(statement)


def test_even_the_table_owner_and_superuser_are_blocked_by_the_trigger(org, admin_conn):
    org.customer()
    for stmt in ("UPDATE prov.activity_log SET actor = 'x' WHERE tenant_id = %s",
                 "DELETE FROM prov.activity_log WHERE tenant_id = %s"):
        with pytest.raises(psycopg.Error) as exc:
            admin_conn.execute(stmt, (org.tenant_id,))
        assert exc.value.sqlstate == "PV901"
    with pytest.raises(psycopg.Error):
        admin_conn.execute("TRUNCATE prov.activity_log")


def test_admin_api_has_no_way_to_modify_the_log(client, org):
    row = activity(org)[0]
    for method in ("PUT", "PATCH", "DELETE"):
        assert org.req(method, f"/activity/{row['activity_id']}", {}).status_code == 405


def test_spoofed_forwarded_header_is_not_trusted(client, org):
    org.req("POST", "/customers", {"name": "Spoof", "email": f"s-{uuid.uuid4().hex[:6]}@example.com"},
            headers={"X-Forwarded-For": "8.8.8.8"}, expect=201)
    assert activity(org, action="POST /customers")[0]["ip_address"] == CLIENT_IP


def test_token_reuse_and_sign_out_are_recorded(client, org, admin_conn):
    client.cookies.clear()
    t1 = client.post(LOGIN, json={"email": org.admin_email, "password": PASSWORD}).json()["refresh_token"]
    client.cookies.clear()
    t2 = client.post("/api/v1/auth/refresh", json={"refresh_token": t1}).json()["refresh_token"]
    admin_conn.execute("UPDATE prov.refresh_tokens SET used_at = used_at - interval '5 minutes' WHERE used_at IS NOT NULL")
    client.cookies.clear()
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": t1}).status_code == 401
    t3 = client.post(LOGIN, json={"email": org.admin_email, "password": PASSWORD}).json()["refresh_token"]
    client.cookies.clear()
    assert client.post("/api/v1/auth/logout", json={"refresh_token": t3}).status_code == 204
    got = actions(org)
    assert "auth.token_reuse" in got and "auth.logout" in got
    assert "POST /auth/refresh" not in got  # routine successful refreshes are not noise in the log
    assert t2


def test_filters_by_actor_action_ip_outcome_method_time_and_pagination(org):
    staff = org.add_user("staff")
    for i in range(3):
        org.req("POST", "/customers", {"name": f"C{i}", "email": f"c{i}-{uuid.uuid4().hex[:6]}@example.com"},
                token=staff, expect=201)
    org.req("POST", "/customers", {"name": "Bad"}, token=staff, expect=422)
    assert all(r["actor"].startswith("staff-") for r in activity(org, actor="STAFF-"))
    assert len(activity(org, actor="staff-", action="/customers", outcome="SUCCESS")) == 3
    assert [r["status_code"] for r in activity(org, actor="staff-", outcome="FAILURE")] == [422]
    assert activity(org, ip=CLIENT_IP) and activity(org, ip="203.0.113.0/24")
    assert activity(org, ip="198.51.100.0/24") == []
    assert org.req("GET", "/activity", ip="not-an-ip").status_code == 422
    by_method = org.client.get("/api/v1/activity", params={"method": "POST", "limit": 500}, headers=org.headers()).json()
    assert by_method["items"] and all(r["method"] == "POST" for r in by_method["items"])
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert activity(org, since=future) == []
    assert activity(org, until=future)
    page1 = org.req("GET", "/activity", expect=200, limit=2).json()
    page2 = org.req("GET", "/activity", expect=200, limit=2, before_id=page1["next_before_id"]).json()
    assert len(page1["items"]) == 2 and max(r["activity_id"] for r in page2["items"]) < page1["next_before_id"]
    org.req("GET", "/activity", outcome="MAYBE", expect=422)


def test_csv_and_json_export_with_filters_and_formula_injection_defence(client, org):
    client.cookies.clear()
    client.post(LOGIN, json={"email": org.admin_email, "password": "wrong-password"}, headers={"User-Agent": "=HYPERLINK(1)"})
    r = org.req("GET", "/activity/export", expect=200, format="csv", action="login_failed")
    assert r.headers["content-type"].startswith("text/csv") and "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert rows and {"ip_address", "actor", "action", "outcome", "user_agent", "occurred_at"} <= set(rows[0])
    assert all(x["action"] == "auth.login_failed" for x in rows)
    assert rows[0]["ip_address"] == CLIENT_IP and rows[0]["user_agent"].startswith("'=")
    js = json.loads(org.req("GET", "/activity/export", expect=200, format="json").text)
    assert js["tenant_id"] == org.tenant_id and js["records"]


def test_summary_counts(client, org):
    client.post(LOGIN, json={"email": org.admin_email, "password": "nope-nope-nope"})
    s = org.req("GET", "/activity/summary", expect=200).json()
    assert s["failed_logins"] >= 1 and s["total"] >= 2 and s["distinct_ips"] >= 1
