from __future__ import annotations

import time
from datetime import datetime, timezone

import oracledb
import pytest

from app.db import tenant_session


def test_total_is_maintained_by_trigger(org):
    a, b = org.product("1099.99"), org.product("150.00")
    o = org.order([{"product_id": a, "quantity": 1}, {"product_id": b, "quantity": 2}])
    assert float(o["total_amount"]) == 1399.99
    o = org.req("PUT", f"/orders/{o['order_id']}/items/{b}", {"quantity": 3}, expect=200).json()
    assert float(o["total_amount"]) == 1549.99
    o = org.req("DELETE", f"/orders/{o['order_id']}/items/{a}", expect=200).json()
    assert float(o["total_amount"]) == 450.00


def test_state_machine_enforced_by_database(org):
    p = org.product("10.00")
    o = org.order([{"product_id": p, "quantity": 1}])
    oid = o["order_id"]
    assert o["allowed_transitions"] == ["CANCELLED", "PAID"]
    r = org.req("POST", f"/orders/{oid}/status", {"status": "SHIPPED"}, expect=409)
    assert r.json()["code"] == "ORA-20001"
    org.req("POST", f"/orders/{oid}/payments", {"amount": "10.00", "method": "CASH"}, expect=201)
    assert org.req("GET", f"/orders/{oid}", expect=200).json()["status"] == "PAID"
    # items are locked once paid (ORA-20002 from the compound trigger)
    r = org.req("PUT", f"/orders/{oid}/items/{p}", {"quantity": 5}, expect=409)
    assert r.json()["code"] == "ORA-20002"


def test_payment_cannot_exceed_balance(org):
    p = org.product("50.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    org.req("POST", f"/orders/{oid}/payments", {"amount": "60.00", "method": "CARD"}, expect=422)


def test_refund_marks_payments_refunded(org):
    p = org.product("20.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    org.req("POST", f"/orders/{oid}/payments", {"amount": "20.00", "method": "CARD"}, expect=201)
    o = org.req("POST", f"/orders/{oid}/status", {"status": "REFUNDED"}, expect=200).json()
    assert [x["status"] for x in o["payments"]] == ["REFUNDED"]


def test_explain_replays_audit_to_the_recorded_total(org):
    a, b = org.product("1099.99"), org.product("150.00")
    o = org.order([{"product_id": a, "quantity": 1}, {"product_id": b, "quantity": 2}])
    org.req("PUT", f"/orders/{o['order_id']}/items/{b}", {"quantity": 3}, expect=200)
    x = org.req("GET", f"/provenance/orders/{o['order_id']}/explain", expect=200).json()
    assert x["checks"]["total_matches_lines"] and x["checks"]["replay_matches_total"]
    assert [float(s["running_total"]) for s in x["steps"]] == [1099.99, 1399.99, 1549.99]
    assert all(s["actor"] == org.admin_email for s in x["steps"])


def test_explain_uses_price_at_order_time(org):
    p = org.product("150.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    org.req("PATCH", f"/products/{p}", {"price": "160.00"}, expect=200)  # small change, applied directly
    line = org.req("GET", f"/provenance/orders/{oid}/explain", expect=200).json()["lines"][0]
    assert float(line["list_price_at_order_time"]) == 150.0
    assert line["price_note"] == "matches catalogue price at order time"


def test_history_records_actor_and_diff(org):
    staff = org.add_user("staff")
    p = org.product("100.00")
    org.req("PATCH", f"/products/{p}", {"price": "110.00"}, token=staff, expect=200)
    hist = org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"]
    assert [h["operation"] for h in hist] == ["INSERT", "UPDATE"]
    update = hist[1]
    assert update["actor"].startswith("staff-") and update["db_user"] == "PROV_APP"
    assert update["changes"] == [{"field": "price", "old": 100, "new": 110}]


def test_request_trace_shows_trigger_cascade(org):
    p = org.product("5.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    r = org.client.put(f"/api/v1/orders/{oid}/items/{p}", json={"quantity": 4}, headers=org.headers())
    trace = org.req("GET", f"/provenance/requests/{r.headers['X-Request-ID']}", expect=200).json()
    entities = [(c["entity"], c["operation"]) for c in trace["changes"]]
    assert entities == [("order_item", "UPDATE"), ("order", "UPDATE")]  # item change + trigger-recomputed total
    assert {e["event_type"] for e in trace["events"]} == {"order_item.updated", "order.updated"}


def test_lineage_links_total_update_to_item_change(org):
    p = org.product("5.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    g = org.req("GET", f"/provenance/orders/{oid}/lineage", expect=200).json()
    types = {n["type"] for n in g["nodes"]}
    assert {"order", "customer", "order_item", "product"} <= types
    caused = [e for e in g["events"] if e["caused_by"]]
    assert caused and caused[0]["explanation"].startswith("total recalculated")


def test_time_travel_as_of_and_compare(org):
    p = org.product("100.00")
    time.sleep(1.1)
    middle = datetime.now(timezone.utc)
    time.sleep(1.1)
    org.req("PATCH", f"/products/{p}", {"price": "105.00"}, expect=200)
    then = org.req("GET", f"/provenance/product/{p}/as-of", at=middle.isoformat(), expect=200).json()
    assert then["existed"] and then["state"]["price"] == 100
    before = org.req("GET", f"/provenance/product/{p}/as-of", at="2000-01-01T00:00:00Z", expect=200).json()
    assert before["existed"] is False
    diff = org.req("GET", f"/provenance/product/{p}/compare", t1=middle.isoformat(),
                   t2=datetime.now(timezone.utc).isoformat(), expect=200).json()
    assert diff["changes"] == [{"field": "price", "old": 100, "new": 105}]


def test_oracle_flashback_query(org):
    p = org.product("100.00")
    # Oracle samples the time -> SCN mapping every few seconds, so timestamps very close to a
    # change resolve to a nearby SCN. Leave a margin and probe a couple of points in between.
    time.sleep(9)
    org.req("PATCH", f"/products/{p}", {"price": "101.00"}, expect=200)
    assert float(org.req("GET", f"/products/{p}", expect=200).json()["price"]) == 101.0
    seen = []
    for minutes_ago in (0.02, 0.04, 0.07):
        fb = org.req("GET", f"/provenance/product/{p}/flashback", minutes_ago=minutes_ago, expect=200).json()
        seen.append(float(fb["state"]["price"]) if fb["existed"] else None)
    assert 100.0 in seen, seen  # the pre-update version, read straight from Oracle undo


def test_audit_log_is_read_only_for_the_api_account(org):
    org.product()
    with tenant_session(org.tenant_id, None, "test", "t") as db:
        with pytest.raises(oracledb.DatabaseError) as exc:
            db.execute("UPDATE audit_log SET actor = 'mallory'")
        assert "ORA-01031" in str(exc.value)


def test_hash_chain_verifies(org):
    p = org.product()
    org.req("PATCH", f"/products/{p}", {"name": "Renamed"}, expect=200)
    v = org.req("POST", "/audit/verify", expect=200).json()
    assert v["ok"] and v["checked"] == v["records"] == 2


def test_audit_export_csv(org):
    org.product()
    r = org.req("GET", "/audit/export", format="csv", expect=200)
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("audit_id,chain_seq") and len(lines) == 2
