"""The tamper-evident audit chain, signed checkpoints, and what each defence can and cannot catch.

Attacker model in these tests: someone who has a superuser connection to the database (so can
disable triggers and bypass row-level security) but does NOT hold the checkpoint signing key.
"""

from __future__ import annotations

import csv
import io
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.db import tenant_session
from app.security import checkpoint_public_key, sign_checkpoint, verify_checkpoint


def make_history(org, n=3):
    p = org.product("10.00")
    for i in range(n):
        org.req("PATCH", f"/products/{p}", {"name": f"Name {i}"}, expect=200)
    return p


def tamper(conn, org, sql: str, params=()):
    """Run SQL as a superuser with the append-only and sealing guards switched off."""
    conn.execute("ALTER TABLE prov.audit_log DISABLE TRIGGER trg_audit_guard")
    try:
        conn.execute(sql, params)
    finally:
        conn.execute("ALTER TABLE prov.audit_log ENABLE TRIGGER trg_audit_guard")


def verify(org, **body):
    return org.req("POST", "/audit/verify", body or None, expect=200).json()


def test_chain_verifies_and_links(org):
    make_history(org)
    v = verify(org)
    assert v["ok"] and v["checked"] == v["records"] == v["head_seq"] and v["first_bad_seq"] is None
    items = org.req("GET", "/audit", expect=200, limit=500).json()["items"]
    seqs = sorted(i["chain_seq"] for i in items)
    assert seqs == list(range(1, len(seqs) + 1))  # gap-free, starts at 1 per tenant
    by_seq = {i["chain_seq"]: i for i in items}
    assert by_seq[1]["prev_hash"] == "0" * 64
    assert all(by_seq[s]["prev_hash"] == by_seq[s - 1]["row_hash"] for s in seqs[1:])


def test_editing_a_record_is_detected_and_located(org, admin_conn):
    p = make_history(org)
    target = org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"][1]
    tamper(admin_conn, org, "UPDATE prov.audit_log SET actor = 'mallory' WHERE audit_id = %s", (target["audit_id"],))
    v = verify(org)
    assert not v["ok"] and v["first_bad_seq"] == target["chain_seq"] and "modified" in v["reason"]
    # failures raise a CRITICAL alert and an event
    org.req("POST", "/alerts/run", expect=200)
    assert any(a["rule_code"] == "DQ004" and a["severity"] == "CRITICAL" for a in org.req("GET", "/alerts", expect=200).json()["items"])
    assert any(e["event_type"] == "audit.integrity_failed" for e in org.req("GET", "/events", expect=200).json()["items"])


def test_editing_the_payload_is_detected(org, admin_conn):
    p = make_history(org)
    target = org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"][0]
    tamper(admin_conn, org, "UPDATE prov.audit_log SET new_values = jsonb_set(new_values, '{price}', '1') WHERE audit_id = %s",
           (target["audit_id"],))
    assert verify(org)["first_bad_seq"] == target["chain_seq"]


def test_deleting_a_record_in_the_middle_is_detected(org, admin_conn):
    p = make_history(org, 4)
    target = org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"][2]
    tamper(admin_conn, org, "DELETE FROM prov.audit_log WHERE audit_id = %s", (target["audit_id"],))
    v = verify(org)
    assert not v["ok"] and v["first_bad_seq"] == target["chain_seq"] and "missing" in v["reason"].lower()


def test_truncating_the_end_is_detected(org, admin_conn):
    make_history(org)
    head = verify(org)["head_seq"]
    tamper(admin_conn, org, "DELETE FROM prov.audit_log WHERE tenant_id = %s AND chain_seq = %s", (org.tenant_id, head))
    v = verify(org)
    assert not v["ok"] and "removed from the end" in v["reason"]


def test_reordering_records_is_detected(org, admin_conn):
    p = make_history(org)
    h = org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"]
    a, b = h[1], h[2]
    tamper(admin_conn, org, "UPDATE prov.audit_log SET chain_seq = -chain_seq WHERE audit_id IN (%s, %s)",
           (a["audit_id"], b["audit_id"]))
    tamper(admin_conn, org, "UPDATE prov.audit_log SET chain_seq = CASE audit_id WHEN %s THEN %s ELSE %s END "
                            "WHERE audit_id IN (%s, %s)", (a["audit_id"], b["chain_seq"], a["chain_seq"], a["audit_id"], b["audit_id"]))
    assert not verify(org)["ok"]


def test_unsealed_row_inserted_with_sealing_disabled_is_detected(org, admin_conn):
    make_history(org)
    admin_conn.execute("ALTER TABLE prov.audit_log DISABLE TRIGGER trg_audit_seal")
    try:
        admin_conn.execute("INSERT INTO prov.audit_log (tenant_id, entity, record_pk, operation, actor, db_user) "
                           "VALUES (%s, 'product', '1', 'INSERT', 'ghost', 'postgres')", (org.tenant_id,))
    finally:
        admin_conn.execute("ALTER TABLE prov.audit_log ENABLE TRIGGER trg_audit_seal")
    v = verify(org)
    assert not v["ok"] and "outside the chain" in v["reason"]


def recompute_chain(conn, tenant_id):
    """What a capable attacker does: rewrite history and recompute every hash so the chain is
    internally consistent again."""
    conn.execute("ALTER TABLE prov.audit_log DISABLE TRIGGER trg_audit_guard")
    rows = conn.execute("SELECT audit_id, chain_seq, changed_at FROM prov.audit_log WHERE tenant_id = %s ORDER BY chain_seq",
                        (tenant_id,)).fetchall()
    prev = "0" * 64
    for audit_id, seq, _ in rows:
        h = conn.execute("""UPDATE prov.audit_log a SET prev_hash = %s,
                 row_hash = prov.audit_hash(prov.audit_preimage(%s, a.chain_seq, a.tenant_id, a.entity, a.record_pk, a.operation,
                     a.actor, a.actor_user_id, a.request_id, a.change_request_id, a.db_user, a.changed_at, a.old_values, a.new_values))
               WHERE audit_id = %s RETURNING row_hash""", (prev, prev, audit_id)).fetchone()[0]
        prev = h
    conn.execute("UPDATE prov.audit_chain_head SET last_hash = %s WHERE tenant_id = %s", (prev, tenant_id))
    conn.execute("ALTER TABLE prov.audit_log ENABLE TRIGGER trg_audit_guard")


def test_hash_chain_alone_cannot_catch_a_full_rewrite_but_checkpoints_do(org, admin_conn):
    p = make_history(org)
    cp = org.req("POST", "/audit/checkpoints", expect=201).json()
    assert cp["ok"] and cp["chain_seq"] == verify(org)["head_seq"]
    external = {k: cp[k] for k in ("chain_seq", "row_hash", "created_at", "signature")}  # a copy kept outside the system

    target = org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"][1]
    tamper(admin_conn, org, "UPDATE prov.audit_log SET new_values = jsonb_set(new_values, '{price}', '1') WHERE audit_id = %s",
           (target["audit_id"],))
    recompute_chain(admin_conn, org.tenant_id)

    # Every link is now internally consistent...
    from app.services.integrity import verify_chain
    with tenant_session(org.tenant_id, None, "t", "t") as db:
        assert verify_chain(db)["ok"]
    # ...but the signed checkpoint, which the attacker cannot forge, no longer matches.
    v = verify(org)
    assert not v["ok"] and "rewritten" in v["reason"]

    # Even if the attacker also deletes the stored checkpoints, the customer's own copy catches it.
    admin_conn.execute("ALTER TABLE prov.audit_checkpoints DISABLE TRIGGER trg_checkpoints_immutable")
    admin_conn.execute("DELETE FROM prov.audit_checkpoints WHERE tenant_id = %s", (org.tenant_id,))
    admin_conn.execute("ALTER TABLE prov.audit_checkpoints ENABLE TRIGGER trg_checkpoints_immutable")
    assert verify(org)["ok"], "with every checkpoint deleted, only the chain itself is left to check"
    v = verify(org, checkpoints=[external])
    assert not v["ok"] and "External checkpoint" in v["reason"] and "rewritten" in v["reason"]


def test_truncation_is_caught_by_a_checkpoint_even_if_the_head_is_rewritten(org, admin_conn):
    make_history(org)
    cp = org.req("POST", "/audit/checkpoints", expect=201).json()
    admin_conn.execute("ALTER TABLE prov.audit_log DISABLE TRIGGER trg_audit_guard")
    admin_conn.execute("DELETE FROM prov.audit_log WHERE tenant_id = %s AND chain_seq > 2", (org.tenant_id,))
    last = admin_conn.execute("SELECT chain_seq, row_hash FROM prov.audit_log WHERE tenant_id = %s ORDER BY chain_seq DESC LIMIT 1",
                              (org.tenant_id,)).fetchone()
    admin_conn.execute("UPDATE prov.audit_chain_head SET last_seq = %s, last_hash = %s WHERE tenant_id = %s",
                       (last[0], last[1], org.tenant_id))
    admin_conn.execute("ALTER TABLE prov.audit_log ENABLE TRIGGER trg_audit_guard")
    v = verify(org)
    assert not v["ok"] and ("truncated" in v["reason"] or "rewritten" in v["reason"]), v
    assert cp["chain_seq"] > 2


def test_forged_and_foreign_checkpoints_are_rejected(org, other_org):
    make_history(org)
    real = org.req("POST", "/audit/checkpoints", expect=201).json()
    forged = {"chain_seq": real["chain_seq"], "row_hash": "0" * 64, "created_at": real["created_at"], "signature": real["signature"]}
    assert not verify(org, checkpoints=[forged])["ok"]
    # a signature is bound to its tenant: another organization's checkpoint cannot be replayed here
    other_org.product()
    theirs = other_org.req("POST", "/audit/checkpoints", expect=201).json()
    replay = {k: theirs[k] for k in ("chain_seq", "row_hash", "created_at", "signature")}
    v = verify(org, checkpoints=[replay])
    assert not v["ok"] and "invalid signature" in v["reason"]


def test_checkpoint_signature_is_independently_verifiable(org):
    make_history(org)
    cp = org.req("POST", "/audit/checkpoints", expect=201).json()
    listing = org.req("GET", "/audit/checkpoints", expect=200).json()
    key = listing["signing_key"]
    assert key == checkpoint_public_key() and key["algorithm"] == "Ed25519"
    from datetime import datetime
    created = datetime.fromisoformat(cp["created_at"].replace("Z", "+00:00"))
    assert verify_checkpoint(org.tenant_id, cp["chain_seq"], cp["row_hash"], created, cp["signature"], key["public_key"])
    assert not verify_checkpoint(org.tenant_id + 1, cp["chain_seq"], cp["row_hash"], created, cp["signature"], key["public_key"])
    assert sign_checkpoint(org.tenant_id, cp["chain_seq"], cp["row_hash"], created) == cp["signature"]
    # checkpoints are also published so a webhook receiver can keep its own copy
    events = org.req("GET", "/events", expect=200, event_type="audit.checkpoint").json()["items"]
    assert events and events[0]["payload"]["row_hash"] == cp["row_hash"]
    # nothing new -> nothing to sign
    assert "Nothing new" in org.req("POST", "/audit/checkpoints", expect=201).json().get("message", "")


def test_checkpoint_is_refused_for_a_broken_chain(org, admin_conn):
    p = make_history(org)
    tamper(admin_conn, org, "UPDATE prov.audit_log SET actor = 'x' WHERE audit_id = (SELECT audit_id FROM prov.audit_log "
                            "WHERE tenant_id = %s AND entity = 'product' LIMIT 1)", (org.tenant_id,))
    r = org.req("POST", "/audit/checkpoints", expect=201).json()
    assert r["ok"] is False
    assert org.req("GET", "/audit/checkpoints", expect=200).json()["items"] == []
    assert p


def test_checkpoints_cannot_be_changed_by_the_runtime_role(org):
    make_history(org)
    org.req("POST", "/audit/checkpoints", expect=201)
    import psycopg
    with tenant_session(org.tenant_id, org.user_id, org.admin_email, "t") as db:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute("DELETE FROM audit_checkpoints")


def test_append_only_trigger_blocks_even_the_table_owner(org, admin_conn):
    import psycopg
    make_history(org)
    with pytest.raises(psycopg.Error) as exc:
        admin_conn.execute("UPDATE prov.audit_log SET actor = 'x' WHERE tenant_id = %s", (org.tenant_id,))
    assert exc.value.sqlstate == "PV901"
    with pytest.raises(psycopg.Error) as exc:
        admin_conn.execute("TRUNCATE prov.audit_log")
    assert exc.value.sqlstate == "PV901"


def test_concurrent_writers_produce_a_gap_free_valid_chain(org):
    def write(i: int):
        with tenant_session(org.tenant_id, org.user_id, org.admin_email, f"req-{i}") as db:
            db.insert("INSERT INTO customers (name, email) VALUES (%s, %s)", (f"C{i}", f"c{i}@example.com"), "customer_id")
            db.commit()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(40)))
    v = verify(org)
    assert v["ok"] and v["checked"] == v["head_seq"]
    seqs = [i["chain_seq"] for i in org.req("GET", "/audit", expect=200, limit=500).json()["items"]]
    assert sorted(seqs) == list(range(1, len(seqs) + 1)) and len(seqs) >= 41  # signup rows + 40 customers


def test_rolled_back_work_leaves_no_history_and_no_events(org):
    with tenant_session(org.tenant_id, org.user_id, org.admin_email, "rolled-back") as db:
        db.insert("INSERT INTO customers (name, email) VALUES ('ghost', 'ghost@example.com')", None, "customer_id")
        db.rollback()
    assert org.req("GET", "/provenance/requests/rolled-back").status_code == 404
    assert verify(org)["ok"]
    assert not any(e["entity_id"] and e["request_id"] == "rolled-back" for e in org.req("GET", "/events", expect=200).json()["items"])


def test_failed_request_changes_nothing(org):
    p = org.product("10.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    before = verify(org)["head_seq"]
    org.req("POST", f"/orders/{oid}/status", {"status": "SHIPPED"}, expect=409)
    org.req("POST", "/orders", {"customer_id": 999999, "items": []}, expect=422)
    assert verify(org)["head_seq"] == before


def test_audit_search_filters_and_pagination(org):
    p = make_history(org, 3)
    page1 = org.req("GET", "/audit", expect=200, limit=2).json()
    assert len(page1["items"]) == 2 and page1["next_before_seq"]
    page2 = org.req("GET", "/audit", expect=200, limit=500, before_seq=page1["next_before_seq"]).json()
    assert max(i["chain_seq"] for i in page2["items"]) < page1["next_before_seq"]
    only = org.req("GET", "/audit", expect=200, entity="product", record_pk=str(p), operation="UPDATE").json()["items"]
    assert len(only) == 3 and all(i["operation"] == "UPDATE" for i in only)
    assert org.req("GET", "/audit", expect=200, actor="ADMIN-").json()["items"]  # case-insensitive substring
    org.req("GET", "/audit", operation="TRUNCATE", expect=422)


def test_export_formats_and_csv_formula_injection(org):
    org.req("POST", "/customers", {"name": "=HYPERLINK(\"http://evil\",\"x\")", "email": "f@example.com"}, expect=201)
    r = org.req("GET", "/audit/export", expect=200, format="csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:2] == ["audit_id", "chain_seq"]
    changes = next(row[10] for row in rows if row[3] == "customer")
    assert "'=HYPERLINK" in changes or not changes.startswith("=")
    assert all(not cell.startswith(("=", "+", "-", "@")) for row in rows[1:] for cell in row if cell)
    js = org.req("GET", "/audit/export", expect=200, format="json").json()
    assert js["tenant_id"] == org.tenant_id and js["records"][0]["row_hash"]
