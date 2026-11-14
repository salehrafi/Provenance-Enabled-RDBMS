"""Operability: health, metrics, OpenAPI accuracy, migrations, worker, housekeeping, config guards."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import httpx

from app.config import Settings, get_settings
from app.db import system_session, tenant_session
from app.worker import Worker

ROOT = Path(__file__).resolve().parent.parent


def test_health_ready_and_metrics(client, org):
    assert client.get("/health").json()["status"] == "ok"
    r = client.get("/ready").json()
    assert r["status"] == "ready" and r["database"] == "ok"
    org.req("GET", "/customers", expect=200)
    text = client.get("/metrics").text
    assert "http_requests_total" in text and 'route="/api/v1/customers"' in text and "http_request_duration_seconds_count" in text
    assert "db_pool_pool_size" in text or "db_pool_pool_max" in text


def test_openapi_documents_every_route_with_summaries_and_security(client):
    spec = client.get("/openapi.json").json()
    assert spec["info"]["version"] == "3.0.0"
    missing = [f"{m.upper()} {p}" for p, ops in spec["paths"].items() for m, op in ops.items() if not op.get("summary")]
    assert missing == []
    paths = spec["paths"]
    for needed in ("/api/v1/events", "/api/v1/events:batch", "/api/v1/audit/verify", "/api/v1/auth/refresh",
                   "/api/v1/sources/{source_id}/records/{entity}/{external_id}/as-of"):
        assert needed in paths, needed
    # no secrets, tokens or hashes leak through example payloads
    assert "password_hash" not in str(spec)


def test_every_endpoint_requires_authentication_unless_listed_public(client):
    """Call every operation in the OpenAPI spec with no credentials and an empty body: all but the
    public ones must answer 401 (authentication runs before validation and before any lookup)."""
    public = {("POST", "/api/v1/auth/signup"), ("POST", "/api/v1/auth/login"), ("POST", "/api/v1/auth/refresh"),
              ("POST", "/api/v1/auth/logout"), ("POST", "/api/v1/auth/token"),
              ("POST", "/api/platform/v1/auth/login"), ("POST", "/api/platform/v1/auth/mfa/enroll")}
    spec = client.get("/openapi.json").json()
    checked, not_401 = 0, []
    for path, ops in spec["paths"].items():
        if not path.startswith("/api/"):
            continue
        url = re.sub(r"\{[^}]+\}", "1", path)
        for method in ops:
            if (method.upper(), path) in public:
                continue
            r = client.request(method.upper(), url, json={})
            checked += 1
            if r.status_code != 401:
                not_401.append((method.upper(), path, r.status_code))
    assert checked > 60, checked
    assert not_401 == []


def test_migrations_are_idempotent_and_downgrade_is_guarded(database):
    from app import cli

    cli.cmd_migrate(type("A", (), {"revision": "head"})())  # second run is a no-op
    env = {**os.environ, "ALLOW_DESTRUCTIVE_MIGRATION": ""}
    proc = subprocess.run([sys.executable, "-m", "alembic", "downgrade", "base"], cwd=ROOT, env=env,
                          capture_output=True, text=True)
    assert proc.returncode != 0 and "Refusing" in (proc.stderr + proc.stdout)
    with system_session() as db:
        assert db.scalar("SELECT count(*) FROM prov.worker_tenants(false)") >= 0  # schema still there


def test_unsafe_production_configuration_is_reported():
    s = Settings(environment="production", database_url="postgresql://x", jwt_secret="short", data_encryption_key="",
                 checkpoint_signing_key="", cookie_secure=False, webhook_allow_private_urls=True, cors_origins=["*"],
                 _env_file=None)
    problems = " | ".join(s.problems())
    for needle in ("JWT_SECRET", "DATA_ENCRYPTION_KEY", "CHECKPOINT_SIGNING_KEY", "COOKIE_SECURE",
                   "WEBHOOK_ALLOW_PRIVATE_URLS", "CORS_ORIGINS"):
        assert needle in problems
    assert get_settings().problems() == []  # the test configuration itself is sound


def test_worker_dispatches_checkpoints_and_raises_integrity_alerts(org, admin_conn, monkeypatch):
    from app.services import webhooks

    monkeypatch.setattr(webhooks, "resolver", lambda host, port, type=0, **_: [(2, 1, 6, "", ("93.184.216.34", port))])
    org.req("POST", "/webhooks", {"url": "https://hooks.example.com/in", "event_types": ["customer.*"]}, expect=201)
    org.customer()
    w = Worker()
    sent = []
    monkeypatch.setattr(httpx.Client, "post", lambda self, url, **kw: sent.append(url) or httpx.Response(200))
    w.run_once(rules_too=True, checkpoints_too=True, verify_too=True)
    assert sent, "worker should have delivered the webhook"
    assert org.req("GET", "/audit/checkpoints", expect=200).json()["items"]
    # Break the chain: the next worker run must refuse to sign and raise a CRITICAL alert instead.
    admin_conn.execute("ALTER TABLE prov.audit_log DISABLE TRIGGER trg_audit_guard")
    admin_conn.execute("UPDATE prov.audit_log SET actor = 'x' WHERE tenant_id = %s AND chain_seq = 2", (org.tenant_id,))
    admin_conn.execute("ALTER TABLE prov.audit_log ENABLE TRIGGER trg_audit_guard")
    org.customer()
    before = len(org.req("GET", "/audit/checkpoints", expect=200).json()["items"])
    w.run_once(rules_too=True, checkpoints_too=True, verify_too=True)
    assert len(org.req("GET", "/audit/checkpoints", expect=200).json()["items"]) == before
    assert any(a["rule_code"] == "DQ004" for a in org.req("GET", "/alerts", expect=200).json()["items"])


def test_checkpoint_anchor_file_receives_every_checkpoint(org, tmp_path, monkeypatch):
    anchor = tmp_path / "anchor" / "checkpoints.jsonl"
    monkeypatch.setattr(get_settings(), "checkpoint_anchor_path", str(anchor))
    org.product()
    org.req("POST", "/audit/checkpoints", expect=201)
    lines = anchor.read_text().strip().splitlines()
    assert len(lines) == 1 and f'"tenant_id": {org.tenant_id}' in lines[0]


def test_housekeeping_prunes_operational_data_but_never_history(org, admin_conn):
    org.customer()
    with tenant_session(org.tenant_id, None, "w", "w") as db:
        db.execute("UPDATE outbox_events SET dispatched_at = now() - interval '90 days'")
        db.commit()
    audit_before = admin_conn.execute("SELECT count(*) FROM prov.audit_log WHERE tenant_id = %s", (org.tenant_id,)).fetchone()[0]
    with system_session() as db:
        r = db.one("SELECT * FROM prov.prune_operational_data(30)")
        db.commit()
    assert r["events"] >= 1
    assert admin_conn.execute("SELECT count(*) FROM prov.audit_log WHERE tenant_id = %s", (org.tenant_id,)).fetchone()[0] == audit_before
    assert admin_conn.execute("SELECT count(*) FROM prov.outbox_events WHERE tenant_id = %s AND dispatched_at IS NOT NULL",
                              (org.tenant_id,)).fetchone()[0] == 0


def test_unexpected_database_errors_do_not_leak_details(client, org, monkeypatch):
    from app.routers import catalog

    def boom(*a, **k):
        import psycopg
        raise psycopg.errors.UndefinedTable('relation "secret_table" does not exist')

    monkeypatch.setattr(catalog, "_customer", boom)
    r = org.req("GET", "/customers/1")
    assert r.status_code == 500 and "secret_table" not in r.text and r.json()["code"] == "INTERNAL"


def test_static_ui_is_served_with_a_strict_csp(client):
    r = client.get("/")
    assert r.status_code == 200 and "script-src 'self'" in r.headers["content-security-policy"]
    assert "unsafe-eval" not in r.headers["content-security-policy"]


def test_static_assets_revalidate_so_upgrades_are_never_masked_by_a_stale_cache(client):
    for path in ("/", "/static/js/app.js", "/static/css/app.css"):
        assert client.get(path).headers["cache-control"] == "no-cache", path
    assert client.get("/api/v1/customers").headers["cache-control"] == "no-store"
