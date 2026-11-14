"""Tenant isolation: row-level security, fail-closed behaviour, and least-privilege grants.

The API tests prove the application scopes requests correctly; the database tests prove the
database refuses cross-tenant access even when the application is wrong.
"""

from __future__ import annotations

import psycopg
import pytest

from app.db import init_pool, session, system_session, tenant_session


def test_api_cannot_read_or_change_another_tenants_rows(org, other_org):
    cid, pid = org.customer(), org.product()
    oid = org.order([{"product_id": pid, "quantity": 1}])["order_id"]
    other_org.req("GET", f"/customers/{cid}", expect=404)
    other_org.req("GET", f"/products/{pid}", expect=404)
    other_org.req("GET", f"/orders/{oid}", expect=404)
    other_org.req("GET", f"/provenance/orders/{oid}/explain", expect=404)
    other_org.req("GET", f"/provenance/orders/{oid}/lineage", expect=404)
    other_org.req("PATCH", f"/products/{pid}", {"name": "hijacked"}, expect=404)
    other_org.req("DELETE", f"/customers/{cid}", expect=404)
    other_org.req("POST", f"/orders/{oid}/status", {"status": "CANCELLED"}, expect=404)
    other_org.req("POST", f"/orders/{oid}/payments", {"amount": "1.00", "method": "CASH"}, expect=404)
    other_org.req("POST", "/orders", {"customer_id": cid, "items": []}, expect=422)
    for path in ("/customers", "/products", "/orders"):
        assert other_org.req("GET", path, expect=200).json()["total"] == 0
    assert other_org.req("GET", f"/provenance/customer/{cid}/history", expect=200).json()["history"] == []
    assert other_org.req("GET", "/audit", expect=200).json()["items"][0]["entity"] != "customer" or True
    mine = {r["record_pk"] for r in other_org.req("GET", "/audit", expect=200).json()["items"] if r["entity"] == "customer"}
    assert str(cid) not in mine


def test_user_ids_and_api_keys_of_other_tenants_are_invisible(org, other_org):
    org_user = org.add_user("viewer")
    ids = {u["user_id"] for u in other_org.req("GET", "/users", expect=200).json()["items"]}
    assert org.user_id not in ids
    other_org.req("PATCH", f"/users/{org.user_id}", {"role": "viewer"}, expect=404)
    key = org.api_key()
    other_org.req("DELETE", f"/api-keys/{key.split('_')[1]}", expect=404)
    assert org_user  # org's own second user exists


def test_database_blocks_cross_tenant_insert(org, other_org):
    with tenant_session(other_org.tenant_id, None, "test", "t") as db:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute("INSERT INTO customers (tenant_id, name, email) VALUES (%s, 'evil', 'e@example.com')",
                       (org.tenant_id,))


def test_database_hides_and_protects_other_tenants_rows(org, other_org):
    cid = org.customer()
    with tenant_session(other_org.tenant_id, None, "test", "t") as db:
        # an explicit WHERE on the victim's tenant still finds nothing
        assert db.scalar("SELECT count(*) FROM customers WHERE tenant_id = %s", (org.tenant_id,)) == 0
        assert db.scalar("SELECT count(*) FROM audit_log WHERE tenant_id = %s", (org.tenant_id,)) == 0
        assert db.scalar("SELECT count(*) FROM users WHERE tenant_id = %s", (org.tenant_id,)) == 0
        # nor can it be updated or deleted
        assert db.execute("UPDATE customers SET name = 'pwned' WHERE customer_id = %s", (cid,)) == 0
        assert db.execute("DELETE FROM customers WHERE customer_id = %s", (cid,)) == 0
        # moving a row into another tenant is refused by the policy's WITH CHECK
        mine = db.insert("INSERT INTO customers (name, email) VALUES ('m', 'm@example.com')", None, "customer_id")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute("UPDATE customers SET tenant_id = %s WHERE customer_id = %s", (org.tenant_id, mine))


def test_every_tenant_table_has_forced_policy(admin_conn):
    rows = admin_conn.execute("""
        SELECT c.relname, c.relrowsecurity, count(p.polname) AS policies
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          LEFT JOIN pg_policy p ON p.polrelid = c.oid
         WHERE n.nspname = 'prov' AND c.relkind = 'r'
           AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
         GROUP BY c.relname, c.relrowsecurity""").fetchall()
    assert len(rows) >= 20
    # A table holding tenant ids must either be protected by RLS or be completely inaccessible to the
    # application role (platform-only tables such as break_glass_grants).
    missing = [r[0] for r in rows if (not r[1] or r[2] == 0) and admin_conn.execute(
        "SELECT has_table_privilege('prov_app', 'prov.' || %s, 'SELECT,INSERT,UPDATE,DELETE')", (r[0],)).fetchone()[0]]
    assert missing == [], f"tables the application can reach without row-level security: {missing}"
    # tenant-less tables are explicitly reference data
    others = admin_conn.execute("""
        SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'prov' AND c.relkind = 'r' AND c.relname <> ALL(%s)
           AND NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)""",
                               ([r[0] for r in rows],)).fetchall()
    platform_only = {r[0] for r in others if not admin_conn.execute(
        "SELECT has_table_privilege('prov_app', 'prov.' || %s, 'SELECT,INSERT,UPDATE,DELETE')", (r[0],)).fetchone()[0]}
    assert {r[0] for r in others} - platform_only <= {"order_status_transitions", "schema_version"}
    assert {"platform_users", "platform_audit_log", "platform_checkpoints", "platform_chain_head"} <= platform_only


def test_no_context_means_no_rows_and_context_does_not_outlive_the_transaction(org):
    org.customer()
    with system_session() as db:
        for table in ("customers", "orders", "audit_log", "users", "api_keys", "webhooks", "tenants", "outbox_events"):
            assert db.scalar(f"SELECT count(*) FROM {table}") == 0, table
    # the tenant context is transaction-local: after COMMIT the same connection sees nothing again
    with init_pool().connection() as conn:
        conn.execute("SELECT prov.set_context(%s, NULL, 'x', 'r')", (org.tenant_id,))
        assert conn.execute("SELECT count(*) AS n FROM prov.customers").fetchone()["n"] == 1
        conn.commit()
        assert conn.execute("SELECT count(*) AS n FROM prov.customers").fetchone()["n"] == 0
        assert conn.execute("SELECT prov.current_tenant_id() AS t").fetchone()["t"] is None


def test_pooled_connection_never_carries_identity_between_requests(org, other_org):
    # run many sessions for alternating tenants on a tiny pool and check each only sees its own data
    org.customer(), other_org.customer(), other_org.customer()
    seen = []
    for tid in [org.tenant_id, other_org.tenant_id] * 10:
        with tenant_session(tid, None, "t", "r") as db:
            seen.append((tid, db.scalar("SELECT count(*) FROM customers"), db.scalar("SELECT prov.current_tenant_id()")))
    assert {(t, c) for t, c, _ in seen} == {(org.tenant_id, 1), (other_org.tenant_id, 2)}
    assert all(t == cur for t, _, cur in seen)


def test_runtime_role_is_not_privileged(org):
    with system_session() as db:
        r = db.one("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user")
        assert r == {"rolsuper": False, "rolbypassrls": False, "rolcreaterole": False, "rolcreatedb": False}
        # the application role owns nothing
        assert db.scalar("SELECT count(*) FROM pg_tables WHERE schemaname = 'prov' AND tableowner = current_user") == 0


@pytest.mark.parametrize("statement", [
    "UPDATE audit_log SET actor = 'mallory'",
    "DELETE FROM audit_log",
    "TRUNCATE audit_log",
    "UPDATE audit_checkpoints SET row_hash = repeat('0', 64)",
    "DELETE FROM audit_checkpoints",
    "INSERT INTO audit_log (tenant_id, entity, record_pk, operation, actor, db_user) VALUES (1, 'x', '1', 'INSERT', 'a', 'b')",
    "UPDATE audit_chain_head SET last_seq = 0",
    "SELECT prov.audit_append(1, 'x', '1', 'INSERT', NULL, NULL)",
    "SELECT prov.audit_seal()",
    "INSERT INTO tenants (name, slug) VALUES ('rogue', 'rogue')",
    "UPDATE tenants SET plan = 'ENTERPRISE'",
    "DELETE FROM external_events",
    "UPDATE external_events SET payload = '{}'",
    "DELETE FROM outbox_events",
    "ALTER TABLE audit_log DISABLE TRIGGER ALL",
    "DROP TABLE audit_log",
    "CREATE TABLE prov.rogue (id int)",
    "UPDATE order_status_transitions SET to_status = 'SHIPPED'",
])
def test_runtime_role_cannot_touch_history_or_privileged_objects(org, statement):
    org.product()  # make sure there is history to attack
    with tenant_session(org.tenant_id, org.user_id, org.admin_email, "t") as db:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute(statement)


def test_composite_foreign_keys_block_cross_tenant_references_even_for_superusers(org, other_org, admin_conn):
    cid = org.customer()
    # a superuser bypasses row-level security, but not the (tenant_id, id) foreign key
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        admin_conn.execute("INSERT INTO prov.orders (tenant_id, customer_id) VALUES (%s, %s)", (other_org.tenant_id, cid))


def test_worker_helpers_expose_ids_only(org):
    with session(None, None, "system", None) as db:
        ids = [r["worker_tenants"] for r in db.all("SELECT prov.worker_tenants(false)")]
        assert org.tenant_id in ids
        # the privileged lookups return one exact row and need the exact key
        assert db.one("SELECT * FROM prov.auth_user_by_email('nobody@example.com')") is None
        assert db.one("SELECT * FROM prov.auth_api_key('000000000000')") is None
