from __future__ import annotations

import base64
import hashlib
import hmac
import json

import httpx

from app.db import tenant_session
from app.services import webhooks


def test_large_price_change_requires_second_admin(org):
    p = org.product("100.00")
    r = org.req("PATCH", f"/products/{p}", {"price": "150.00", "reason": "cost"}, expect=202).json()
    cr_id = r["pending_change_request"]["change_request_id"]
    assert float(r["price"]) == 100.0  # not applied yet

    org.req("POST", f"/approvals/{cr_id}/approve", {}, expect=403)  # requester cannot approve
    staff = org.add_user("staff")
    org.req("POST", f"/approvals/{cr_id}/approve", {}, token=staff, expect=403)  # staff cannot approve

    second_admin = org.add_user("admin")
    approved = org.req("POST", f"/approvals/{cr_id}/approve", {"note": "ok"}, token=second_admin, expect=200).json()
    assert approved["status"] == "APPROVED"
    assert float(org.req("GET", f"/products/{p}", expect=200).json()["price"]) == 150.0

    # the audit record of the price change carries the approval it came from
    last = org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"][-1]
    assert last["change_request_id"] == cr_id and last["actor"] != org.admin_email
    org.req("POST", f"/approvals/{cr_id}/reject", {}, token=second_admin, expect=409)  # already decided


def test_database_refuses_self_approval_even_without_api(org):
    import oracledb
    import pytest

    p = org.product("100.00")
    cr_id = org.req("PATCH", f"/products/{p}", {"price": "200.00"}, expect=202).json()["pending_change_request"]["change_request_id"]
    me = org.req("GET", "/users", expect=200).json()[0]["user_id"]
    with tenant_session(org.tenant_id, me, org.admin_email, "t") as db:
        with pytest.raises(oracledb.DatabaseError) as exc:
            db.execute("UPDATE change_requests SET status = 'APPROVED', reviewed_by_id = :u WHERE change_request_id = :c",
                       {"u": me, "c": cr_id})
        assert "CK_CR_FOUR_EYES" in str(exc.value)


def test_rules_flag_deep_discount_but_not_later_price_rises(org):
    discounted = org.product("100.00")
    normal = org.product("100.00")
    o = org.order([{"product_id": discounted, "quantity": 1, "unit_price": "50.00"},
                   {"product_id": normal, "quantity": 1}])
    org.req("PATCH", "/settings", {"approval_price_change_pct": 50}, expect=200)
    # A later +30% list price rise: 100 is now 23% below the *current* price, but it matched
    # the price at order time, so it must not be reported as a discount.
    org.req("PATCH", f"/products/{normal}", {"price": "130.00"}, expect=200)
    result = org.req("POST", "/alerts/run", expect=200).json()
    assert result["rules"]["AN002"]["new_alerts"] == 1
    alerts = org.req("GET", "/alerts", expect=200).json()
    flagged = [a["entity_id"] for a in alerts if a["rule_code"] == "AN002"]
    assert flagged == [f"{o['order_id']}:{discounted}"]
    # running again does not duplicate alerts
    assert org.req("POST", "/alerts/run", expect=200).json()["new_alerts"] == 0


def test_change_without_user_context_falls_back_to_db_user(org):
    p = org.product("10.00")
    with tenant_session(org.tenant_id, None, None, None) as db:
        db.execute("UPDATE products SET price = 9 WHERE product_id = :p", {"p": p})
        db.commit()
    # PROV_APP made this change but without a user in the context: the actor falls back to the DB user
    hist = org.req("GET", f"/provenance/product/{p}/history", expect=200).json()["history"]
    assert hist[-1]["actor"] == "db:PROV_APP"


def test_outbox_and_signed_webhook_delivery(org):
    secret_resp = org.req("POST", "/webhooks", {"url": "https://hooks.example.com/in", "event_types": ["product.*"]},
                          expect=201).json()
    secret = secret_resp["secret"]
    org.product("1.00")

    received = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client, \
            tenant_session(org.tenant_id, None, "system:test", "w") as db:
        fanned, delivered = webhooks.process_tenant(db, org.tenant_id, client)

    assert fanned >= 1 and delivered == 1
    req = received[0]
    assert req.headers["X-Provenance-Event"] == "product.created"
    # Standard Webhooks: v1,base64(HMAC_SHA256(base64decode(secret), "id.timestamp.body"))
    msg_id, ts = req.headers["webhook-id"], req.headers["webhook-timestamp"]
    version, sig = req.headers["webhook-signature"].split(",", 1)
    key = base64.b64decode(secret.removeprefix("whsec_"))
    expected = base64.b64encode(
        hmac.new(key, f"{msg_id}.{ts}.{req.content.decode()}".encode(), hashlib.sha256).digest()).decode()
    assert version == "v1" and hmac.compare_digest(sig, expected)
    body = json.loads(req.content)
    assert body["tenant_id"] == org.tenant_id and body["data"]["new"]["price"] == 1

    deliveries = org.req("GET", f"/webhooks/{secret_resp['webhook_id']}/deliveries", expect=200).json()
    assert [d["status"] for d in deliveries] == ["SUCCESS"]


def test_failed_delivery_is_retried_with_backoff(org):
    hook = org.req("POST", "/webhooks", {"url": "https://hooks.example.com/down", "event_types": ["*"]}, expect=201).json()
    org.customer()
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as client, \
            tenant_session(org.tenant_id, None, "system:test", "w") as db:
        webhooks.process_tenant(db, org.tenant_id, client)
    d = org.req("GET", f"/webhooks/{hook['webhook_id']}/deliveries", expect=200).json()[0]
    assert d["status"] == "FAILED" and d["attempts"] == 1 and d["response_code"] == 503


def test_event_type_matching():
    assert webhooks.matches("*", "order.created")
    assert webhooks.matches("order.*", "order.status_changed")
    assert webhooks.matches("alert.raised, order.created", "order.created")
    assert not webhooks.matches("order.*", "orders_x.created")
    assert not webhooks.matches("product.created", "product.updated")
