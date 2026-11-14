"""Global administration and break-glass: separation from tenants, MFA, four-eyes, read-only, expiry, audit integrity."""

from __future__ import annotations

import time
import uuid

import psycopg
import pytest

from app import security
from app.db import platform_session, session, tenant_session
from app.security import create_platform_token, totp_at
from app.services import platform as svc
from tests.conftest import PASSWORD

P = "/api/platform/v1"
OP_PASSWORD = "operator-password-123"


class FakeClock:
    """Only the TOTP clock: every code is for a fresh 30-second step, so the replay guard never trips by accident."""

    def __init__(self) -> None:
        self.t = time.time()

    def __call__(self) -> float:
        return self.t

    def code(self, secret: str) -> str:
        self.t += 30
        return totp_at(secret, int(self.t // 30))


_CLOCK = FakeClock()


@pytest.fixture(autouse=True)
def totp_clock(monkeypatch):
    monkeypatch.setattr(security, "_clock", _CLOCK)
    return _CLOCK


class Op:
    def __init__(self, client, role: str):
        self.client = client
        self.email = f"{role}-{uuid.uuid4().hex[:8]}@platform.example"
        with platform_session() as db:
            self.id = svc.create_operator(db, self.email, f"Test {role}", role, OP_PASSWORD, "test")
            db.commit()
        r = client.post(f"{P}/auth/login", json={"email": self.email, "password": OP_PASSWORD})
        assert r.status_code == 200 and r.json()["mfa_setup_required"], r.text
        self.secret = r.json()["secret"]
        r = client.post(f"{P}/auth/mfa/enroll", json={"setup_token": r.json()["setup_token"], "code": _CLOCK.code(self.secret)})
        assert r.status_code == 200, r.text
        self.token = r.json()["access_token"]

    def req(self, method, path, body=None, expect=None, token=None, **params):
        r = self.client.request(method, P + path, json=body, params=params or None,
                                headers={"Authorization": f"Bearer {token or self.token}"})
        if expect is not None:
            assert r.status_code == expect, f"{method} {path}: expected {expect}, got {r.status_code}: {r.text}"
        return r

    def stale_token(self) -> str:
        with platform_session() as db:
            ver = db.scalar("SELECT token_version FROM platform_users WHERE platform_user_id = %s", (self.id,))
        return create_platform_token(self.id, ver, int(time.time()) - 3600)[0]


@pytest.fixture
def admin_op(client):
    return Op(client, "super_admin")


@pytest.fixture
def officer(client):
    return Op(client, "security_officer")


def tenant_activity(org):
    return org.req("GET", "/activity", expect=200, limit=500).json()["items"]


def grant(requester, approver, org, scope="READ_ONLY", minutes=30, activate=True, **extra):
    body = {"tenant_id": org.tenant_id, "scope": scope, "reason": "Customer-authorised investigation of a billing dispute",
            "ticket_ref": "INC-4711", "duration_minutes": minutes, **extra}
    g = requester.req("POST", "/break-glass", body, expect=201).json()
    approver.req("POST", f"/break-glass/{g['grant_id']}/approve", {"note": "verified ticket"}, expect=200)
    if activate:
        g = requester.req("POST", f"/break-glass/{g['grant_id']}/activate", expect=200).json()
    return g


# ---- identity separation and MFA -----------------------------------------------------------------
def test_operator_sign_in_requires_mfa_and_codes_cannot_be_replayed(client, admin_op):
    r = client.post(f"{P}/auth/login", json={"email": admin_op.email, "password": OP_PASSWORD})
    assert r.status_code == 401 and r.json()["code"] == "MFA_REQUIRED"
    code = _CLOCK.code(admin_op.secret)
    ok = client.post(f"{P}/auth/login", json={"email": admin_op.email, "password": OP_PASSWORD, "totp": code})
    assert ok.status_code == 200 and ok.json()["operator"]["role"] == "super_admin"
    replay = client.post(f"{P}/auth/login", json={"email": admin_op.email, "password": OP_PASSWORD, "totp": code})
    assert replay.status_code == 401  # the same code never works twice
    bad = client.post(f"{P}/auth/login", json={"email": admin_op.email, "password": "wrong-wrong-wrong", "totp": _CLOCK.code(admin_op.secret)})
    assert bad.status_code == 401
    secret_at_rest = admin_op.req("GET", "/me", expect=200).json()
    assert "mfa_secret_enc" not in secret_at_rest and "password_hash" not in secret_at_rest


def test_platform_and_organization_tokens_are_not_interchangeable(client, org, admin_op):
    assert client.get(f"{P}/organizations", headers=org.headers()).status_code == 401
    assert client.get("/api/v1/customers", headers={"Authorization": f"Bearer {admin_op.token}"}).status_code == 401
    assert client.get(f"{P}/organizations").status_code == 401
    key = org.api_key()
    assert client.get(f"{P}/organizations", headers={"Authorization": f"Bearer {key}"}).status_code == 401


def test_organization_users_cannot_become_operators(org, client):
    org.req("POST", "/users", {"email": f"x-{uuid.uuid4().hex[:6]}@example.com", "full_name": "Escalator",
                               "password": PASSWORD, "role": "super_admin"}, expect=422)
    r = client.post(f"{P}/auth/login", json={"email": org.admin_email, "password": PASSWORD})
    assert r.status_code == 401  # organization credentials mean nothing to the platform console


# ---- database-level separation ---------------------------------------------------------------------
@pytest.mark.parametrize("table", ["customers", "orders", "users", "audit_log", "activity_log", "external_events",
                                   "tenants", "api_keys", "webhooks", "refresh_tokens"])
def test_platform_role_cannot_read_any_tenant_table(table):
    with platform_session() as db, pytest.raises(psycopg.errors.InsufficientPrivilege):
        db.all(f"SELECT * FROM {table} LIMIT 1")


@pytest.mark.parametrize("statement", [
    "SELECT * FROM platform_users", "SELECT * FROM break_glass_grants", "SELECT * FROM platform_audit_log",
    "SELECT * FROM prov.platform_org_overview()", "SELECT prov.platform_set_tenant_status(1, 'SUSPENDED', 'x', 'x', 'x')",
    "SELECT prov.platform_audit_append('x', NULL, 'x', 'SUCCESS', NULL, NULL, NULL, NULL, NULL, '{}')",
    "SELECT * FROM prov.breakglass_list_users(1, 1)",
])
def test_application_role_cannot_reach_platform_objects(org, statement):
    with tenant_session(org.tenant_id, org.user_id, org.admin_email, "t") as db, pytest.raises(psycopg.errors.InsufficientPrivilege):
        db.all(statement)


def test_no_role_bypasses_row_level_security(admin_conn):
    rows = admin_conn.execute("SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname LIKE 'prov_%'").fetchall()
    assert {r[0] for r in rows} == {"prov_owner", "prov_app", "prov_platform"}
    assert all(not r[1] and not r[2] for r in rows)


# ---- organizations and metadata -------------------------------------------------------------------
def test_overview_is_metadata_only(org, officer):
    org.customer()
    orgs = officer.req("GET", "/organizations", expect=200).json()["items"]
    mine = next(o for o in orgs if o["tenant_id"] == org.tenant_id)
    assert mine["customers"] == 1 and mine["users"] >= 1 and mine["status"] == "ACTIVE"
    allowed = {"tenant_id", "name", "slug", "plan", "status", "status_reason", "created_at", "users", "active_users",
               "customers", "orders", "external_events", "audit_records", "latest_checkpoint_at", "activity_24h",
               "failed_logins_24h", "denied_24h", "last_activity_at", "open_critical_alerts", "active_break_glass"}
    assert set(mine) == allowed  # counts and status, never names/emails/values of business records
    health = officer.req("GET", "/health", expect=200).json()
    assert health["database"] == "ok" and "organizations" in health["metrics"]
    assert officer.req("GET", "/security/signals", expect=200).json()["items"] is not None


def test_suspension_blocks_the_organization_and_is_visible_to_it(client, org, admin_op, officer):
    key = org.api_key(("events:read",))
    officer.req("POST", f"/organizations/{org.tenant_id}/suspend", {"reason": "Payment fraud investigation"}, expect=403)
    admin_op.req("POST", f"/organizations/{org.tenant_id}/suspend", {"reason": "Payment fraud investigation"},
                 token=admin_op.stale_token(), expect=403)  # needs a fresh MFA check
    assert admin_op.req("POST", f"/organizations/{org.tenant_id}/suspend", {"reason": "Payment fraud investigation"},
                        expect=200).json()["status"] == "SUSPENDED"
    assert client.get("/api/v1/customers", headers=org.headers()).json()["code"] == "ORGANIZATION_SUSPENDED"
    assert client.get("/api/v1/ingested-events", headers={"Authorization": f"Bearer {key}"}).json()["code"] == "ORGANIZATION_SUSPENDED"
    client.cookies.clear()
    assert client.post("/api/v1/auth/login", json={"email": org.admin_email, "password": PASSWORD}).json()["code"] == "ORGANIZATION_SUSPENDED"
    admin_op.req("POST", f"/organizations/{org.tenant_id}/reactivate", expect=200)
    actions = [a["action"] for a in tenant_activity(org)]
    assert "organization.suspended" in actions and "organization.active" in actions
    hist = org.req("GET", f"/provenance/organization/{org.tenant_id}/history", expect=200).json()["history"]
    assert any(h["actor"] == f"platform:{admin_op.email}" for h in hist)  # in the organization's own audit chain


# ---- break-glass -----------------------------------------------------------------------------------
def test_break_glass_full_flow_read_only_and_customer_visible(client, org, other_org, admin_op, officer):
    mine, theirs = org.customer(), other_org.customer()
    body = {"tenant_id": org.tenant_id, "reason": "Legal request: subpoena 2026-77 for order records",
            "ticket_ref": "LEGAL-77", "duration_minutes": 15}
    g = admin_op.req("POST", "/break-glass", body, expect=201).json()
    gid = g["grant_id"]
    assert g["status"] == "PENDING"
    assert admin_op.req("POST", f"/break-glass/{gid}/approve", {}).json()["code"] == "FOUR_EYES"
    admin_op.req("GET", f"/break-glass/{gid}/data/customers", expect=403)  # not active yet
    officer.req("POST", f"/break-glass/{gid}/approve", {"note": "subpoena verified"}, expect=200)
    officer.req("POST", f"/break-glass/{gid}/activate", expect=403)        # only the requester activates
    g = admin_op.req("POST", f"/break-glass/{gid}/activate", expect=200).json()
    assert g["status"] == "ACTIVE" and g["expires_at"]

    rows = admin_op.req("GET", f"/break-glass/{gid}/data/customers", expect=200).json()["items"]
    ids = {r["customer_id"] for r in rows}
    assert mine in ids and theirs not in ids  # one organization only: RLS still applies
    users = admin_op.req("GET", f"/break-glass/{gid}/data/users", expect=200).json()["items"]
    assert users and all("password_hash" not in u for u in users)
    officer.req("GET", f"/break-glass/{gid}/data/customers", expect=403)  # the approver gets no access
    admin_op.req("GET", f"/break-glass/{gid}/data/platform_users", expect=404)
    admin_op.req("POST", f"/break-glass/{gid}/users/{org.user_id}/reset-password", expect=403)  # READ_ONLY scope

    acts = [a["action"] for a in tenant_activity(org)]
    for expected in ("breakglass.pending", "breakglass.approved", "breakglass.active", "breakglass.access"):
        assert expected in acts, (expected, acts)
    assert any(e["event_type"] == "security.break_glass" for e in org.req("GET", "/events", expect=200).json()["items"])
    assert not any(a["action"].startswith("breakglass") for a in tenant_activity(other_org))

    admin_op.req("POST", f"/break-glass/{gid}/close", {"note": "done"}, expect=200)
    admin_op.req("GET", f"/break-glass/{gid}/data/customers", expect=403)


def test_break_glass_session_is_read_only_in_the_database(org, admin_op, officer):
    g = grant(admin_op, officer, org)
    with session(None, None, None, "t") as db:
        db.one("SELECT * FROM prov.breakglass_begin(%s, %s, %s)", (g["grant_id"], admin_op.id, "t"))
        assert db.scalar("SELECT count(*) FROM customers") >= 0
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            db.execute("INSERT INTO customers (name, email) VALUES ('x', 'x@example.com')")
    with session(None, None, None, "t") as db, pytest.raises(psycopg.Error) as exc:
        db.one("SELECT * FROM prov.breakglass_begin(%s, %s, %s)", (g["grant_id"], officer.id, "t"))  # not the requester
    assert exc.value.sqlstate == "PV040"


def test_access_expires_automatically_and_cannot_be_extended(org, admin_op, officer, admin_conn):
    g = grant(admin_op, officer, org, minutes=5)
    gid = g["grant_id"]
    admin_op.req("GET", f"/break-glass/{gid}/data/orders", expect=200)
    with platform_session() as db:  # the platform role cannot extend a grant
        with pytest.raises(psycopg.Error) as exc:
            db.execute("UPDATE break_glass_grants SET expires_at = now() + interval '1 day' WHERE grant_id = %s", (gid,))
        assert exc.value.sqlstate == "PV041"
    admin_conn.execute("ALTER TABLE prov.break_glass_grants DISABLE TRIGGER trg_bg_guard")
    try:  # even a superuser cannot push the expiry past the approved duration
        with pytest.raises(psycopg.errors.CheckViolation):
            admin_conn.execute("UPDATE prov.break_glass_grants SET expires_at = activated_at + interval '1 day' WHERE grant_id = %s", (gid,))
        admin_conn.execute("UPDATE prov.break_glass_grants SET activated_at = now() - interval '10 minutes', "
                           "expires_at = now() - interval '5 minutes' WHERE grant_id = %s", (gid,))  # simulate time passing
    finally:
        admin_conn.execute("ALTER TABLE prov.break_glass_grants ENABLE TRIGGER trg_bg_guard")
    assert admin_op.req("GET", f"/break-glass/{gid}/data/orders").json()["code"] == "BREAK_GLASS_NOT_ACTIVE"
    with session(None, None, None, "t") as db, pytest.raises(psycopg.Error) as exc:
        db.one("SELECT * FROM prov.breakglass_begin(%s, %s, %s)", (gid, admin_op.id, "t"))
    assert exc.value.sqlstate == "PV040"  # the database refuses even if the API were bypassed
    with platform_session() as db:
        assert gid in [r["grant_id"] for r in svc.expire_grants(db)]
    assert admin_op.req("GET", f"/break-glass/{gid}", expect=200).json()["status"] == "EXPIRED"
    assert "breakglass.expired" in [a["action"] for a in tenant_activity(org)]


def test_approval_lapses_if_not_activated_in_time(org, admin_op, officer, admin_conn):
    g = grant(admin_op, officer, org, activate=False)
    admin_conn.execute("ALTER TABLE prov.break_glass_grants DISABLE TRIGGER trg_bg_guard")
    try:
        admin_conn.execute("UPDATE prov.break_glass_grants SET approval_expires_at = now() - interval '1 minute' WHERE grant_id = %s",
                           (g["grant_id"],))
    finally:
        admin_conn.execute("ALTER TABLE prov.break_glass_grants ENABLE TRIGGER trg_bg_guard")
    assert admin_op.req("POST", f"/break-glass/{g['grant_id']}/activate").json()["code"] == "BREAK_GLASS_APPROVAL_EXPIRED"


def test_requests_need_fresh_mfa_and_cannot_be_edited(org, admin_op, officer):
    body = {"tenant_id": org.tenant_id, "reason": "Account recovery requested by the verified owner", "ticket_ref": "SUP-1"}
    assert admin_op.req("POST", "/break-glass", body, token=admin_op.stale_token()).json()["code"] == "MFA_STEP_UP_REQUIRED"
    g = admin_op.req("POST", "/break-glass", body, expect=201).json()
    assert officer.req("POST", f"/break-glass/{g['grant_id']}/approve", {}, token=officer.stale_token()).json()["code"] == "MFA_STEP_UP_REQUIRED"
    with platform_session() as db, pytest.raises(psycopg.Error) as exc:
        db.execute("UPDATE break_glass_grants SET scope = 'ACCOUNT_RECOVERY', status = 'APPROVED', decided_by = %s WHERE grant_id = %s",
                   (officer.id, g["grant_id"]))
    assert exc.value.sqlstate == "PV041"
    with platform_session() as db, pytest.raises(psycopg.Error) as exc:  # self-approval is impossible in the database
        db.execute("UPDATE break_glass_grants SET status = 'APPROVED', decided_by = requested_by WHERE grant_id = %s", (g["grant_id"],))
    assert exc.value.sqlstate in ("PV043", "23514")
    with platform_session() as db, pytest.raises(psycopg.Error):  # skipping approval is an invalid transition
        db.execute("UPDATE break_glass_grants SET status = 'ACTIVE' WHERE grant_id = %s", (g["grant_id"],))
    step = officer.req("POST", "/auth/step-up", {"totp": _CLOCK.code(officer.secret)}, expect=200).json()
    officer.token = step["access_token"]
    officer.req("POST", f"/break-glass/{g['grant_id']}/reject", {"note": "insufficient"}, expect=200)


def test_account_recovery_is_narrow_audited_and_works(client, org, admin_op, officer):
    staff_token = org.add_user("staff")
    staff = next(u for u in org.req("GET", "/users", expect=200).json()["items"] if u["role"] == "staff")
    g = grant(admin_op, officer, org, scope="ACCOUNT_RECOVERY")
    users = admin_op.req("GET", f"/break-glass/{g['grant_id']}/users", expect=200).json()["items"]
    assert {u["user_id"] for u in users} >= {staff["user_id"]} and all("password_hash" not in u for u in users)
    r = admin_op.req("POST", f"/break-glass/{g['grant_id']}/users/{staff['user_id']}/reset-password", expect=200).json()
    temp = r["temporary_password"]
    assert client.get("/api/v1/customers", headers={"Authorization": f"Bearer {staff_token}"}).status_code == 401  # old session revoked
    client.cookies.clear()
    assert client.post("/api/v1/auth/login", json={"email": staff["email"], "password": temp}).status_code == 200
    client.cookies.clear()
    hist = org.req("GET", f"/provenance/user/{staff['user_id']}/history", expect=200).json()["history"]
    assert hist[-1]["actor"].startswith(f"breakglass:{admin_op.email}#")
    assert "breakglass.recovery.reset_password" in [a["action"] for a in tenant_activity(org)]
    admin_op.req("POST", f"/break-glass/{g['grant_id']}/users/999999/reactivate", expect=422)
    officer.req("POST", f"/break-glass/{g['grant_id']}/users/{staff['user_id']}/reactivate", expect=403)


def test_legal_hold_suppresses_customer_notification_only_with_a_documented_reason(org, admin_op, officer):
    short = {"tenant_id": org.tenant_id, "reason": "Court order, no notice allowed", "ticket_ref": "LEGAL-9",
             "notify_customer": False}
    assert admin_op.req("POST", "/break-glass", short).status_code == 422
    g = grant(admin_op, officer, org, notify_customer=False,
              reason="Sealed court order 2026-CV-1234 prohibits notifying the account holder of this access")
    admin_op.req("GET", f"/break-glass/{g['grant_id']}/data/orders", expect=200)
    assert not any(a["action"].startswith("breakglass") for a in tenant_activity(org))
    entries = admin_op.req("GET", "/audit", expect=200, action="breakglass", tenant_id=org.tenant_id).json()["items"]
    assert {"breakglass.requested", "breakglass.access"} <= {e["action"] for e in entries}  # but never off the platform record


def test_access_is_refused_when_it_cannot_be_logged(org, admin_op, officer, monkeypatch):
    g = grant(admin_op, officer, org)

    def broken(*a, **k):
        raise RuntimeError("audit store down")

    monkeypatch.setattr(svc, "append", broken)
    r = admin_op.req("GET", f"/break-glass/{g['grant_id']}/data/customers")
    assert r.status_code == 503 and r.json()["code"] == "AUDIT_UNAVAILABLE" and "items" not in r.text


# ---- privilege escalation --------------------------------------------------------------------------
def test_operator_management_is_super_admin_only_and_never_self(client, admin_op, officer):
    officer.req("POST", "/operators", {"email": "new@platform.example", "full_name": "New Op", "role": "super_admin"}, expect=403)
    officer.req("PATCH", f"/operators/{officer.id}", {"role": "super_admin"}, expect=403)
    assert admin_op.req("PATCH", f"/operators/{admin_op.id}", {"role": "security_officer"}).json()["code"] == "SELF_ESCALATION"
    assert admin_op.req("PATCH", f"/operators/{admin_op.id}", {"is_active": False}).json()["code"] == "SELF_ESCALATION"
    new = admin_op.req("POST", "/operators", {"email": f"n-{uuid.uuid4().hex[:6]}@platform.example", "full_name": "New Op",
                                              "role": "security_officer"}, expect=201).json()
    assert len(new["temporary_password"]) >= 12
    admin_op.req("PATCH", f"/operators/{officer.id}", {"is_active": False}, expect=200)
    officer.req("GET", "/organizations", expect=401)  # deactivation revokes the session at once


def test_platform_keeps_one_active_super_admin(admin_op):
    with platform_session() as db:
        db.execute("UPDATE platform_users SET role = 'security_officer' WHERE role = 'super_admin'")
        with pytest.raises(psycopg.Error) as exc:
            db.commit()
    assert exc.value.sqlstate == "PV050"


def test_cli_cannot_be_used_to_add_admins_once_one_exists(admin_op):
    from types import SimpleNamespace

    from app import cli
    with pytest.raises(SystemExit) as exc:
        cli.cmd_create_platform_admin(SimpleNamespace(email="sneaky@platform.example", name="Sneaky"))
    assert "already exists" in str(exc.value)


# ---- platform audit chain ----------------------------------------------------------------------------
def test_every_request_is_recorded_with_ip(admin_op):
    admin_op.req("GET", "/organizations", expect=200)
    admin_op.client.get(f"{P}/organizations")  # anonymous attempt is recorded too
    rows = admin_op.req("GET", "/audit", expect=200, limit=50).json()["items"]
    mine = [r for r in rows if r["actor"] == admin_op.email and r["action"] == "GET /organizations"]
    assert mine and mine[0]["ip_address"] == "203.0.113.10" and mine[0]["row_hash"]
    assert any(r["actor"] == "anonymous" and r["outcome"] == "DENIED" for r in rows)
    csv_text = admin_op.req("GET", "/audit/export", expect=200).text
    assert csv_text.splitlines()[0].startswith("seq,occurred_at,actor,action")


def recompute_platform_chain(conn):
    conn.execute("ALTER TABLE prov.platform_audit_log DISABLE TRIGGER trg_platform_audit_guard")
    prev = "0" * 64
    for (audit_id,) in conn.execute("SELECT audit_id FROM prov.platform_audit_log WHERE seq IS NOT NULL ORDER BY seq").fetchall():
        prev = conn.execute("""UPDATE prov.platform_audit_log a SET prev_hash = %s,
                 row_hash = prov.audit_hash(prov.platform_audit_preimage(%s, a.seq, a.actor, a.actor_id, a.action, a.outcome,
                   a.target_tenant_id, a.target, a.ip_address, a.user_agent, a.request_id, a.occurred_at, a.details))
               WHERE audit_id = %s RETURNING row_hash""", (prev, prev, audit_id)).fetchone()[0]
    conn.execute("UPDATE prov.platform_chain_head SET last_hash = %s", (prev,))
    conn.execute("ALTER TABLE prov.platform_audit_log ENABLE TRIGGER trg_platform_audit_guard")


def test_platform_chain_detects_edits_and_anchor_detects_a_full_rewrite(admin_op, admin_conn, tmp_path, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "platform_anchor_path", str(tmp_path / "anchor" / "platform.jsonl"))
    admin_op.req("GET", "/organizations", expect=200)
    assert admin_op.req("POST", "/audit/verify", {}, expect=200).json()["ok"]
    cp = admin_op.req("POST", "/audit/checkpoints", expect=201).json()
    assert cp["ok"] and (tmp_path / "anchor" / "platform.jsonl").read_text().count("\n") == 1
    v = admin_op.req("POST", "/audit/verify", {}, expect=200).json()
    assert v["ok"] and v["checkpoints"]["anchor"] == 1 and v["checkpoints"]["stored"] >= 1

    seq = cp["seq"] - 1
    admin_conn.execute("ALTER TABLE prov.platform_audit_log DISABLE TRIGGER trg_platform_audit_guard")
    admin_conn.execute("UPDATE prov.platform_audit_log SET actor = 'nobody' WHERE seq = %s", (seq,))
    admin_conn.execute("ALTER TABLE prov.platform_audit_log ENABLE TRIGGER trg_platform_audit_guard")
    v = admin_op.req("POST", "/audit/verify", {}, expect=200).json()
    assert not v["ok"] and v["first_bad_seq"] == seq and "modified" in v["reason"]

    # A capable attacker recomputes every hash and deletes the stored checkpoints...
    recompute_platform_chain(admin_conn)
    admin_conn.execute("ALTER TABLE prov.platform_checkpoints DISABLE TRIGGER trg_platform_checkpoints_immutable")
    admin_conn.execute("DELETE FROM prov.platform_checkpoints")
    admin_conn.execute("ALTER TABLE prov.platform_checkpoints ENABLE TRIGGER trg_platform_checkpoints_immutable")
    # ...but the independent anchor still holds the signed checkpoint, so the rewrite is caught.
    v = admin_op.req("POST", "/audit/verify", {}, expect=200).json()
    assert not v["ok"] and "Anchored checkpoint" in v["reason"] and "rewritten" in v["reason"]


def test_platform_audit_is_append_only_for_everyone(admin_op, admin_conn):
    admin_op.req("GET", "/organizations", expect=200)
    with platform_session() as db, pytest.raises(psycopg.errors.InsufficientPrivilege):
        db.execute("DELETE FROM platform_audit_log")
    for stmt in ("UPDATE prov.platform_audit_log SET actor = 'x'", "DELETE FROM prov.platform_audit_log", "TRUNCATE prov.platform_audit_log"):
        with pytest.raises(psycopg.Error) as exc:
            admin_conn.execute(stmt)
        assert exc.value.sqlstate == "PV901"


def test_operators_cannot_be_created_with_an_address_that_cannot_sign_in(admin_op):
    with platform_session() as db, pytest.raises(Exception) as exc:
        svc.create_operator(db, "someone@reserved.test", "Reserved", "security_officer", OP_PASSWORD, "test")
    assert "Invalid operator email" in str(exc.value.detail)
    r = admin_op.req("POST", "/operators", {"email": "someone@reserved.test", "full_name": "Reserved", "role": "security_officer"})
    assert r.status_code == 422
