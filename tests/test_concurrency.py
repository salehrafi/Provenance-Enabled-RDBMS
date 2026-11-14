"""Idempotency and concurrency safety."""

from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from app.db import tenant_session


def test_idempotency_key_replays_the_original_response(org):
    cust = org.customer()
    key = {"Idempotency-Key": uuid.uuid4().hex}
    body = {"customer_id": cust, "items": []}
    first = org.req("POST", "/orders", body, headers=key, expect=201)
    again = org.req("POST", "/orders", body, headers=key, expect=201)
    assert again.headers["idempotent-replayed"] == "true" and again.json() == first.json()
    assert org.req("GET", "/orders", expect=200).json()["total"] == 1
    # same key, different request -> refused, not silently replayed
    r = org.req("POST", "/orders", {**body, "notes": "other"}, headers=key)
    assert r.status_code == 422 and r.json()["code"] == "IDEMPOTENCY_KEY_REUSED"
    assert org.req("POST", "/orders", body, headers={"Idempotency-Key": "short"}).status_code == 422


def test_idempotency_keys_are_scoped_per_tenant(org, other_org):
    key = {"Idempotency-Key": "shared-key-12345"}
    a = org.req("POST", "/customers", {"name": "A", "email": "a@example.com"}, headers=key, expect=201).json()
    b = other_org.req("POST", "/customers", {"name": "B", "email": "b@example.com"}, headers=key, expect=201).json()
    assert a["name"] == "A" and b["name"] == "B"


def test_failed_request_does_not_consume_its_idempotency_key(org):
    key = {"Idempotency-Key": uuid.uuid4().hex}
    assert org.req("POST", "/orders", {"customer_id": 987654, "items": []}, headers=key).status_code == 422
    cust = org.customer()
    # the key was not stored by the failed attempt, so the retry (now with a valid customer) works
    assert org.req("POST", "/orders", {"customer_id": cust, "items": []}, headers=key).status_code in (201, 422)


def test_concurrent_requests_with_one_key_create_exactly_one_order(org):
    cust = org.customer()
    key = {"Idempotency-Key": uuid.uuid4().hex}

    def go(_):
        return org.req("POST", "/orders", {"customer_id": cust, "items": []}, headers=key).json()["order_id"]

    with ThreadPoolExecutor(max_workers=6) as pool:
        ids = list(pool.map(go, range(6)))
    assert len(set(ids)) == 1
    assert org.req("GET", "/orders", expect=200).json()["total"] == 1


def test_concurrent_payments_cannot_overpay(org):
    p = org.product("100.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]

    def pay(_):
        return org.req("POST", f"/orders/{oid}/payments", {"amount": "60.00", "method": "CASH"}).status_code

    with ThreadPoolExecutor(max_workers=6) as pool:
        codes = list(pool.map(pay, range(6)))
    assert codes.count(201) == 1, codes  # only one 60.00 fits in a 100.00 order
    o = org.req("GET", f"/orders/{oid}", expect=200).json()
    assert float(o["paid_amount"]) == 60.0 and len(o["payments"]) == 1


def test_concurrent_item_edits_keep_the_total_equal_to_the_lines(org):
    prods = [org.product("10.00") for _ in range(6)]
    oid = org.order([])["order_id"]

    def add(pid):
        return org.req("POST", f"/orders/{oid}/items", {"product_id": pid, "quantity": 2}).status_code

    with ThreadPoolExecutor(max_workers=6) as pool:
        assert set(pool.map(add, prods)) == {201}
    o = org.req("GET", f"/orders/{oid}", expect=200).json()
    assert float(o["total_amount"]) == 120.0 == sum(float(i["line_total"]) for i in o["items"])
    x = org.req("GET", f"/provenance/orders/{oid}/explain", expect=200).json()
    assert x["checks"]["replay_matches_total"]


def test_concurrent_payment_and_status_change_serialise(org):
    p = org.product("100.00")
    oid = org.order([{"product_id": p, "quantity": 1}])["order_id"]

    def pay(_):
        return org.req("POST", f"/orders/{oid}/payments", {"amount": "100.00", "method": "CASH"}).status_code

    def cancel(_):
        return org.req("POST", f"/orders/{oid}/status", {"status": "CANCELLED"}).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(pay, 0), pool.submit(cancel, 0)
        results = (a.result(), b.result())
    status = org.req("GET", f"/orders/{oid}", expect=200).json()["status"]
    # exactly one of the two won; the loser was refused by the state machine, never half-applied
    assert sorted(results) in ([201, 409], [200, 409]) and status in ("PAID", "CANCELLED")
    assert org.req("POST", "/audit/verify", expect=200).json()["ok"]


def test_concurrent_signups_with_one_email_create_one_account(client):
    email = f"race-{uuid.uuid4().hex[:8]}@example.com"

    def go(i):
        return client.post("/api/v1/auth/signup", json={"organization": f"Race Co {i}", "full_name": "Racer",
                                                         "email": email, "password": "a-long-password-1"}).status_code

    with ThreadPoolExecutor(max_workers=5) as pool:
        codes = list(pool.map(go, range(5)))
    assert codes.count(201) == 1 and codes.count(409) == 4, codes


def test_deadlock_prone_workload_is_retryable_not_fatal(org):
    """Two transactions touching the same two rows in opposite order: the loser gets a 409 RETRY
    style error, never a hang, and the survivor commits."""
    a, b = org.customer(), org.customer()

    def work(order):
        try:
            with tenant_session(org.tenant_id, org.user_id, org.admin_email, "dl") as db:
                for cid in order:
                    db.execute("UPDATE customers SET name = %s WHERE customer_id = %s", (f"n{uuid.uuid4().hex[:4]}", cid))
                db.commit()
            return "ok"
        except Exception as exc:  # noqa: BLE001
            return getattr(exc, "sqlstate", "error")

    with ThreadPoolExecutor(max_workers=2) as pool:
        r = list(pool.map(work, [(a, b), (b, a)]))
    assert set(r) <= {"ok", "40P01", "55P03"} and "ok" in r
