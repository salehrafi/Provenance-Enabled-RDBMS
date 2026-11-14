"""Business rules in the database, provenance capture, explainability, time travel, approvals, rules."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import psycopg
import pytest

from app.db import tenant_session


def test_total_is_maintained_by_the_database(org):
    a, b = org.product("1099.99"), org.product("150.00")
    o = org.order([{"product_id": a, "quantity": 1}, {"product_id": b, "quantity": 2}])
    assert float(o["total_amount"]) == 1399.99
    o = org.req("PUT", f"/orders/{o['order_id']}/items/{b}", {"quantity": 3}, expect=200).json()
    assert float(o["total_amount"]) == 1549.99
    o = org.req("DELETE", f"/orders/{o['order_id']}/items/{a}", expect=200).json()
    assert float(o["total_amount"]) == 450.00


def test_total_cannot_be_set_directly_even_by_the_application_role(org):
    p = org.product("10.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    with tenant_session(org.tenant_id, org.user_id, org.admin_email, "t") as db:
        with pytest.raises(psycopg.Error) as exc:
            db.execute("UPDATE orders SET total_amount = 1 WHERE order_id = %s", (oid,))
        assert exc.value.sqlstate == "PV003"
        db.rollback()
        db.execute("INSERT INTO orders (customer_id, total_amount) SELECT customer_id, 999 FROM orders WHERE order_id = %s", (oid,))
        assert db.scalar("SELECT max(total_amount) FROM orders WHERE total_amount = 999") is None  # forced to 0 on insert


def test_state_machine_and_item_locking_are_enforced_by_the_database(org):
    p = org.product("10.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    r = org.req("POST", f"/orders/{oid}/status", {"status": "SHIPPED"}, expect=409)
    assert r.json()["code"] == "ORDER_INVALID_TRANSITION"
    org.req("POST", f"/orders/{oid}/payments", {"amount": "10.00", "method": "CASH"}, expect=201)
    assert org.req("GET", f"/orders/{oid}", expect=200).json()["status"] == "PAID"
    r = org.req("PUT", f"/orders/{oid}/items/{p}", {"quantity": 5}, expect=409)
    assert r.json()["code"] == "ORDER_ITEMS_LOCKED"
    # same rules for a client that bypasses the API entirely
    with tenant_session(org.tenant_id, org.user_id, org.admin_email, "t") as db:
        with pytest.raises(psycopg.Error) as exc:
            db.execute("UPDATE order_items SET quantity = 9 WHERE order_id = %s", (oid,))
        assert exc.value.sqlstate == "PV002"


def test_payment_rules(org):
    p = org.product("50.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    assert org.req("POST", f"/orders/{oid}/payments", {"amount": "60.00", "method": "CARD"}, expect=422).json()["code"] == "PAYMENT_EXCEEDS_BALANCE"
    org.req("POST", f"/orders/{oid}/payments", {"amount": "20.00", "method": "CARD"}, expect=201)
    assert org.req("GET", f"/orders/{oid}", expect=200).json()["status"] == "CREATED"  # partially paid
    org.req("POST", f"/orders/{oid}/payments", {"amount": "30.00", "method": "CARD"}, expect=201)
    assert org.req("GET", f"/orders/{oid}", expect=200).json()["status"] == "PAID"
    org.req("POST", f"/orders/{oid}/payments", {"amount": "1.00", "method": "CARD"}, expect=409)


def test_refund_marks_payments_refunded(org):
    p = org.product("20.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    org.req("POST", f"/orders/{oid}/payments", {"amount": "20.00", "method": "CARD"}, expect=201)
    o = org.req("POST", f"/orders/{oid}/status", {"status": "REFUNDED"}, expect=200).json()
    assert [x["status"] for x in o["payments"]] == ["REFUNDED"]


def test_search_treats_wildcards_literally_and_inputs_are_not_injectable(org):
    org.req("POST", "/products", {"sku": "A-50%", "name": "Fifty percent", "price": "1.00"}, expect=201)
    org.req("POST", "/products", {"sku": "B-500", "name": "Five hundred", "price": "1.00"}, expect=201)
    hits = org.req("GET", "/products", search="50%", expect=200).json()
    assert [p["sku"] for p in hits["items"]] == ["A-50%"]
    evil = org.req("GET", "/products", search="'; DROP TABLE products; --", expect=200).json()
    assert evil["total"] == 0
    org.req("GET", "/orders", expect=200)  # tables still there
    org.req("GET", "/orders", status="CREATED' OR '1'='1", expect=422)


def test_history_records_actor_diff_and_database_user(org):
    staff = org.add_user("staff")
    p = org.product("100.00")
    org.req("PATCH", f"/products/{p}", {"price": "110.00"}, token=staff, expect=200)
    hist = org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"]
    assert [h["operation"] for h in hist] == ["INSERT", "UPDATE"]
    update = hist[1]
    assert update["actor"].startswith("staff-") and update["db_user"] == "prov_app"
    assert update["changes"] == [{"field": "price", "old": 100, "new": 110}]
    assert hist[1]["prev_hash"] == hist[0]["row_hash"]
    assert [h["chain_seq"] for h in hist] == sorted(h["chain_seq"] for h in hist)


def test_secrets_never_enter_the_audit_log(org):
    org.add_user("viewer")
    org.api_key()
    entries = org.req("GET", "/audit", expect=200, limit=500).json()["items"]
    blob = str(entries)
    assert "password_hash" not in blob and "secret_hash" not in blob and "argon2" not in blob
    users = [e for e in entries if e["entity"] == "user"]
    assert users and all("password_hash" not in (e["new_values"] or {}) for e in users)


def test_unchanged_update_writes_no_history(org):
    p = org.product("100.00")
    org.req("PATCH", f"/products/{p}", {"name": "Thing"}, expect=200)  # same name
    assert len(org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"]) == 1


def test_explain_replays_audit_to_the_recorded_total(org):
    a, b = org.product("1099.99"), org.product("150.00")
    o = org.order([{"product_id": a, "quantity": 1}, {"product_id": b, "quantity": 2}])
    org.req("PUT", f"/orders/{o['order_id']}/items/{b}", {"quantity": 3}, expect=200)
    x = org.req("GET", f"/provenance/orders/{o['order_id']}/explain", expect=200).json()
    assert x["checks"]["total_matches_lines"] and x["checks"]["replay_matches_total"]
    assert [float(s["running_total"]) for s in x["steps"]] == [1099.99, 1399.99, 1549.99]
    assert all(s["actor"] == org.admin_email for s in x["steps"])
    assert all(len(s["row_hash"]) == 64 for s in x["steps"])


def test_explain_uses_price_at_order_time(org):
    p = org.product("150.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    org.req("PATCH", f"/products/{p}", {"price": "160.00"}, expect=200)  # small change, applied directly
    line = org.req("GET", f"/provenance/orders/{oid}/explain", expect=200).json()["lines"][0]
    assert float(line["list_price_at_order_time"]) == 150.0
    assert line["price_note"] == "matches catalogue price at order time"


def test_request_trace_shows_the_trigger_cascade(org):
    p = org.product("5.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    r = org.client.put(f"/api/v1/orders/{oid}/items/{p}", json={"quantity": 4}, headers=org.headers())
    trace = org.req("GET", f"/provenance/requests/{r.headers['X-Request-ID']}", expect=200).json()
    assert [(c["entity"], c["operation"]) for c in trace["changes"]] == [("order_item", "UPDATE"), ("order", "UPDATE")]
    assert {e["event_type"] for e in trace["events"]} == {"order_item.updated", "order.updated"}


def test_lineage_links_total_update_to_item_change(org):
    p = org.product("5.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]
    org.req("POST", f"/orders/{oid}/payments", {"amount": "5.00", "method": "CASH"}, expect=201)
    g = org.req("GET", f"/provenance/orders/{oid}/lineage", expect=200).json()
    assert {"order", "customer", "order_item", "product", "payment"} <= {n["type"] for n in g["nodes"]}
    node_ids = {n["id"] for n in g["nodes"]}
    assert all(e["from"] in node_ids and e["to"] in node_ids for e in g["edges"])
    explanations = [e["explanation"] for e in g["events"] if e["caused_by"]]
    assert any(x.startswith("total recalculated") for x in explanations)
    assert any(x.startswith("status changed because the payment") for x in explanations)


def test_time_travel_as_of_compare_and_order_documents(org):
    p = org.product("100.00")
    o = org.order([{"product_id": p, "quantity": 2}])
    oid = o["order_id"]
    time.sleep(0.05)
    middle = datetime.now(UTC)
    time.sleep(0.05)
    org.req("PATCH", f"/products/{p}", {"price": "105.00"}, expect=200)
    org.req("PUT", f"/orders/{oid}/items/{p}", {"quantity": 5}, expect=200)
    org.req("POST", f"/orders/{oid}/payments", {"amount": "500.00", "method": "CASH"}, expect=201)

    then = org.req("GET", f"/provenance/product/{p}/as-of", at=middle.isoformat(), expect=200).json()
    assert then["existed"] and then["state"]["price"] == 100 and then["based_on"]["row_hash"]
    assert org.req("GET", f"/provenance/product/{p}/as-of", at="2000-01-01T00:00:00Z", expect=200).json()["existed"] is False

    # a whole order document at a past time: header, lines and payments
    past = org.req("GET", f"/provenance/order/{oid}/as-of", at=middle.isoformat(), expect=200).json()
    assert past["state"]["status"] == "CREATED" and float(past["state"]["total_amount"]) == 200
    assert [float(i["quantity"]) for i in past["items"]] == [2] and past["payments"] == []
    now = org.req("GET", f"/provenance/order/{oid}/as-of", at=datetime.now(UTC).isoformat(), expect=200).json()
    assert now["state"]["status"] == "PAID" and [float(i["quantity"]) for i in now["items"]] == [5]
    assert len(now["payments"]) == 1

    diff = org.req("GET", f"/provenance/product/{p}/compare", t1=middle.isoformat(),
                   t2=datetime.now(UTC).isoformat(), expect=200).json()
    assert diff["changes"] == [{"field": "price", "old": 100, "new": 105}]
    odiff = org.req("GET", f"/provenance/order/{oid}/compare", t1=middle.isoformat(),
                    t2=datetime.now(UTC).isoformat(), expect=200).json()
    assert {c["field"] for c in odiff["changes"]} == {"status", "total_amount"}
    assert odiff["item_changes"][0]["change"] == "changed"


def test_deleted_records_are_reconstructable_from_history(org):
    cid = org.customer()
    before = datetime.now(UTC)
    time.sleep(0.05)
    org.req("DELETE", f"/customers/{cid}", expect=204)
    gone = org.req("GET", f"/provenance/customer/{cid}/as-of", at=datetime.now(UTC).isoformat(), expect=200).json()
    assert gone["existed"] is False
    was = org.req("GET", f"/provenance/customer/{cid}/as-of", at=before.isoformat(), expect=200).json()
    assert was["existed"] is True and was["state"]["name"] == "Cust"
    assert [h["operation"] for h in org.req("GET", f"/provenance/customer/{cid}/history", expect=200).json()["history"]] == ["INSERT", "DELETE"]
    org.req("GET", "/provenance/nonsense/1/history", expect=404)


# ---- maker-checker -----------------------------------------------------------------------------
def test_large_price_change_requires_a_second_admin(org):
    p = org.product("100.00")
    r = org.req("PATCH", f"/products/{p}", {"price": "150.00", "reason": "cost"}, expect=202).json()
    cr_id = r["pending_change_request"]["change_request_id"]
    assert float(r["price"]) == 100.0

    assert org.req("POST", f"/approvals/{cr_id}/approve", {}, expect=403).json()["code"] == "FOUR_EYES"
    staff = org.add_user("staff")
    org.req("POST", f"/approvals/{cr_id}/approve", {}, token=staff, expect=403)
    second = org.add_user("admin")
    approved = org.req("POST", f"/approvals/{cr_id}/approve", {"note": "ok"}, token=second, expect=200).json()
    assert approved["status"] == "APPROVED"
    assert float(org.req("GET", f"/products/{p}", expect=200).json()["price"]) == 150.0
    last = org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"][-1]
    assert last["change_request_id"] == cr_id and last["actor"] != org.admin_email
    assert org.req("POST", f"/approvals/{cr_id}/reject", {}, token=second, expect=409).json()["code"] == "CHANGE_REQUEST_DECIDED"
    # the approval id must not leak onto unrelated later changes in the same connection
    org.req("PATCH", f"/products/{p}", {"name": "Renamed"}, expect=200)
    assert org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"][-1]["change_request_id"] is None


def test_stale_change_request_cannot_be_approved(org):
    p = org.product("100.00")
    cr = org.req("PATCH", f"/products/{p}", {"price": "150.00"}, expect=202).json()["pending_change_request"]["change_request_id"]
    org.req("PATCH", f"/products/{p}", {"price": "110.00"}, expect=200)  # small change slips in
    second = org.add_user("admin")
    assert org.req("POST", f"/approvals/{cr}/approve", {}, token=second, expect=409).json()["code"] == "STALE_REQUEST"


def test_database_refuses_self_approval_without_the_api(org):
    p = org.product("100.00")
    cr = org.req("PATCH", f"/products/{p}", {"price": "200.00"}, expect=202).json()["pending_change_request"]["change_request_id"]
    with tenant_session(org.tenant_id, org.user_id, org.admin_email, "t") as db:
        with pytest.raises(psycopg.errors.CheckViolation) as exc:
            db.execute("UPDATE change_requests SET status = 'APPROVED', reviewed_by_id = %s WHERE change_request_id = %s",
                       (org.user_id, cr))
        assert exc.value.diag.constraint_name == "ck_cr_four_eyes"


# ---- rules -------------------------------------------------------------------------------------
def test_rules_flag_deep_discount_but_not_later_price_rises(org):
    discounted, normal = org.product("100.00"), org.product("100.00")
    o = org.order([{"product_id": discounted, "quantity": 1, "unit_price": "50.00"}, {"product_id": normal, "quantity": 1}])
    org.req("PATCH", "/settings", {"approval_price_change_pct": 50}, expect=200)
    org.req("PATCH", f"/products/{normal}", {"price": "130.00"}, expect=200)  # list price rises 30% later
    result = org.req("POST", "/alerts/run", expect=200).json()
    assert result["rules"]["AN002"]["new_alerts"] == 1
    flagged = [a["entity_id"] for a in org.req("GET", "/alerts", expect=200).json()["items"] if a["rule_code"] == "AN002"]
    assert flagged == [f"{o['order_id']}:{discounted}"]
    assert org.req("POST", "/alerts/run", expect=200).json()["new_alerts"] == 0  # deduplicated


def test_out_of_band_change_by_another_database_role_is_flagged(org, admin_conn):
    p = org.product("10.00")
    admin_conn.execute("UPDATE prov.products SET price = 9 WHERE product_id = %s", (p,))
    hist = org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"]
    assert hist[-1]["actor"] == "db:postgres" and hist[-1]["db_user"] == "postgres"
    org.req("POST", "/alerts/run", expect=200)
    codes = {a["rule_code"] for a in org.req("GET", "/alerts", expect=200).json()["items"]}
    assert "AN005" in codes


def test_change_without_user_context_falls_back_to_the_database_role(org):
    p = org.product("10.00")
    with tenant_session(org.tenant_id, None, None, None) as db:
        db.execute("UPDATE products SET price = 9 WHERE product_id = %s", (p,))
        db.commit()
    assert org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"][-1]["actor"] == "db:prov_app"


def test_alert_lifecycle_and_dashboard(org):
    p = org.product("100.00")
    org.order([{"product_id": p, "quantity": 1, "unit_price": "10.00"}])
    org.req("POST", "/alerts/run", expect=200)
    alert = org.req("GET", "/alerts", status="OPEN", expect=200).json()["items"][0]
    viewer = org.add_user("viewer")
    org.req("PATCH", f"/alerts/{alert['alert_id']}", {"status": "ACKNOWLEDGED"}, token=viewer, expect=403)
    assert org.req("PATCH", f"/alerts/{alert['alert_id']}", {"status": "ACKNOWLEDGED"}, expect=200).json()["status"] == "ACKNOWLEDGED"
    d = org.req("GET", "/dashboard", expect=200).json()
    assert d["counts"]["orders"] == 1 and d["counts"]["audit_records"] >= 5 and d["recent_activity"]


def test_settings_roundtrip_and_validation(org):
    assert org.req("PATCH", "/settings", {"currency": "EUR", "large_refund_amount": "250.00"}, expect=200).json()["currency"] == "EUR"
    org.req("PATCH", "/settings", {"currency": "euro"}, expect=422)
    org.req("PATCH", "/settings", {"discount_alert_pct": 150}, expect=422)
    org.req("PATCH", "/settings", {"unknown": 1}, expect=422)


def test_sandbox_sample_data_is_audited_explainable_and_loads_once(org):
    viewer = org.add_user("viewer")
    org.req("POST", "/sandbox/sample-data", token=viewer, expect=403)
    r = org.req("POST", "/sandbox/sample-data", expect=201).json()
    assert r["orders"] == 2 and r["new_alerts"] >= 1
    assert org.req("POST", "/sandbox/sample-data", expect=409).json()["code"] == "SAMPLE_DATA_EXISTS"
    x = org.req("GET", f"/provenance/orders/{r['order_ids'][0]}/explain", expect=200).json()
    assert x["checks"]["replay_matches_total"] and len(x["steps"]) == 3
    assert org.req("POST", "/audit/verify", expect=200).json()["ok"]
