"""Webhook delivery: signing, retries, dead-lettering, leases, SSRF defence, secret handling."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import time

import httpx
import pytest

from app.config import get_settings
from app.db import tenant_session
from app.security import decrypt_secret
from app.services import webhooks

PUBLIC_IP = "93.184.216.34"


def fake_resolver(mapping: dict[str, list[str]]):
    def resolve(host, port, type=0, **_):
        ips = mapping.get(host)
        if ips is None:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]
    return resolve


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    monkeypatch.setattr(webhooks, "resolver", fake_resolver({
        "hooks.example.com": [PUBLIC_IP], "localhost": ["127.0.0.1"], "internal.corp": ["10.1.2.3"],
        "metadata.google.internal": ["169.254.169.254"], "v6.example.com": ["::1"], "mapped.example.com": ["::ffff:127.0.0.1"],
        "mixed.example.com": [PUBLIC_IP, "10.0.0.5"], "rebind.example.com": ["192.168.1.10"]}))


def run_dispatch(org, handler, rounds=1):
    seen = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    with httpx.Client(transport=httpx.MockTransport(wrapped)) as client:
        for _ in range(rounds):
            with tenant_session(org.tenant_id, None, "system:test", "w") as db:
                webhooks.process_tenant(db, org.tenant_id, client)
    return seen


def make_hook(org, **body):
    return org.req("POST", "/webhooks", {"url": "https://hooks.example.com/in", **body}, expect=201).json()


def deliveries(org, hook):
    return org.req("GET", f"/webhooks/{hook['webhook_id']}/deliveries", expect=200).json()["items"]


def make_due(org):
    with tenant_session(org.tenant_id, None, "t", "t") as db:
        db.execute("UPDATE webhook_deliveries SET next_attempt_at = now() - interval '1 second' WHERE status = 'FAILED'")
        db.commit()


def test_signed_delivery_follows_standard_webhooks(org):
    hook = make_hook(org, event_types=["product.*"])
    org.product("1.00")
    seen = run_dispatch(org, lambda r: httpx.Response(200, text="ok"))
    assert len(seen) == 1
    req = seen[0]
    assert req.headers["X-Provenance-Event"] == "product.created" and req.headers["host"] == "hooks.example.com"
    assert str(req.url).startswith(f"https://{PUBLIC_IP}/")  # sent to the vetted address, not re-resolved
    msg_id, ts = req.headers["webhook-id"], req.headers["webhook-timestamp"]
    version, sig = req.headers["webhook-signature"].split(",", 1)
    key = base64.b64decode(hook["secret"].removeprefix("whsec_"))
    expected = base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.{req.content.decode()}".encode(), hashlib.sha256).digest()).decode()
    assert version == "v1" and hmac.compare_digest(sig, expected)
    assert abs(int(ts) - time.time()) < 30  # fresh timestamp, so receivers can reject replays
    body = json.loads(req.content)
    assert body["tenant_id"] == org.tenant_id and body["data"]["new"]["price"] == 1 and body["type"] == "product.created"
    d = deliveries(org, hook)
    assert [x["status"] for x in d] == ["SUCCESS"] and d[0]["response_snippet"] == "ok" and d[0]["duration_ms"] is not None


def test_event_type_filtering_and_inactive_hooks(org):
    only_orders = make_hook(org, event_types=["order.*"])
    paused = make_hook(org)
    org.req("PATCH", f"/webhooks/{paused['webhook_id']}", {"is_active": False}, expect=200)
    org.product("1.00")
    assert run_dispatch(org, lambda r: httpx.Response(200)) == []
    assert deliveries(org, only_orders) == []
    assert webhooks.matches(["*"], "order.created") and webhooks.matches(["order.*"], "order.status_changed")
    assert webhooks.matches(["alert.raised", "order.created"], "order.created")
    assert not webhooks.matches(["order.*"], "orders_x.created") and not webhooks.matches(["product.created"], "product.updated")


def test_failure_retries_with_backoff_then_dead_letters_and_alerts(org):
    hook = make_hook(org, event_types=["customer.created"])
    org.customer()
    max_attempts = get_settings().webhook_max_attempts
    for attempt in range(1, max_attempts + 1):
        run_dispatch(org, lambda r: httpx.Response(503, text="down"))
        d = deliveries(org, hook)[-1]
        if attempt < max_attempts:
            assert d["status"] == "FAILED" and d["attempts"] == attempt and d["response_code"] == 503
            make_due(org)
    d = deliveries(org, hook)[-1]
    assert d["status"] == "DEAD" and d["attempts"] == max_attempts and d["last_error"] == "HTTP 503"
    # dead deliveries are not retried automatically, and raise a visible alert
    assert run_dispatch(org, lambda r: httpx.Response(200)) == []
    assert any(a["rule_code"] == "WH001" for a in org.req("GET", "/alerts", expect=200).json()["items"])
    # an admin can retry a dead delivery manually
    org.req("POST", f"/webhooks/deliveries/{d['delivery_id']}/retry", expect=200)
    run_dispatch(org, lambda r: httpx.Response(200))
    assert deliveries(org, hook)[-1]["status"] == "SUCCESS"


def test_backoff_grows_exponentially_with_jitter_and_a_cap():
    mid = [sum(webhooks.backoff_seconds(n) for _ in range(200)) / 200 for n in range(1, 6)]
    assert all(b > a for a, b in zip(mid, mid[1:]))
    assert 12 <= webhooks.backoff_seconds(1) <= 18
    assert webhooks.backoff_seconds(40) <= webhooks.MAX_BACKOFF_SECONDS * 1.2
    assert len({round(webhooks.backoff_seconds(3), 3) for _ in range(20)}) > 1  # jittered


def test_message_id_is_stable_across_retries_for_receiver_dedup(org):
    make_hook(org, event_types=["customer.created"])
    org.customer()
    seen = run_dispatch(org, lambda r: httpx.Response(500))
    make_due(org)
    seen += run_dispatch(org, lambda r: httpx.Response(200))
    assert len(seen) == 2 and seen[0].headers["webhook-id"] == seen[1].headers["webhook-id"]
    assert seen[0].headers["webhook-signature"] != "" and seen[0].content == seen[1].content


def test_network_errors_and_redirects_do_not_leak_or_follow(org):
    hook = make_hook(org, event_types=["customer.created"])
    org.customer()

    def boom(request):
        raise httpx.ConnectTimeout("timed out")

    run_dispatch(org, boom)
    assert "ConnectTimeout" in deliveries(org, hook)[-1]["last_error"]
    make_due(org)
    seen = run_dispatch(org, lambda r: httpx.Response(302, headers={"location": "http://169.254.169.254/latest"}))
    assert len(seen) == 1  # the redirect target is never requested
    assert deliveries(org, hook)[-1]["status"] == "FAILED"


def test_lease_prevents_double_delivery_by_concurrent_workers(org):
    make_hook(org)
    org.customer()
    with tenant_session(org.tenant_id, None, "w", "w") as db:
        webhooks.fan_out(db)
        first = webhooks._claim(db, 10)
        second = webhooks._claim(db, 10)  # a second worker right after: nothing is claimable
    assert len(first) >= 1 and second == []
    # a crashed worker's lease expires, and the delivery is picked up again
    with tenant_session(org.tenant_id, None, "w", "w") as db:
        db.execute("UPDATE webhook_deliveries SET locked_until = now() - interval '1 second'")
        db.commit()
        assert len(webhooks._claim(db, 10)) == len(first)


def test_fan_out_is_idempotent(org):
    hook = make_hook(org)
    org.customer()
    with tenant_session(org.tenant_id, None, "w", "w") as db:
        webhooks.fan_out(db)
        db.execute("UPDATE outbox_events SET dispatched_at = NULL")  # simulate a crash before the mark
        db.commit()
        webhooks.fan_out(db)
    ids = [d["event_id"] for d in deliveries(org, hook)]
    assert len(ids) == len(set(ids))


# ---- SSRF ----------------------------------------------------------------------------------------
@pytest.mark.parametrize("url", [
    "https://localhost/hook", "https://internal.corp/hook", "https://metadata.google.internal/computeMetadata/v1/",
    "https://v6.example.com/x", "https://mapped.example.com/x", "https://mixed.example.com/x",
    "https://rebind.example.com/x", "https://127.0.0.1/x", "https://10.0.0.1/x",
])
def test_internal_destinations_are_refused(org, url, monkeypatch):
    monkeypatch.setattr(webhooks, "resolver", fake_resolver({
        "localhost": ["127.0.0.1"], "internal.corp": ["10.1.2.3"], "metadata.google.internal": ["169.254.169.254"],
        "v6.example.com": ["::1"], "mapped.example.com": ["::ffff:127.0.0.1"], "mixed.example.com": [PUBLIC_IP, "10.0.0.5"],
        "rebind.example.com": ["192.168.1.10"], "127.0.0.1": ["127.0.0.1"], "10.0.0.1": ["10.0.0.1"]}))
    r = org.req("POST", "/webhooks", {"url": url})
    assert r.status_code == 422 and r.json()["code"] == "INVALID_WEBHOOK_URL"


@pytest.mark.parametrize("url", ["http://hooks.example.com/x", "ftp://hooks.example.com/x", "https://user:pw@hooks.example.com/x",
                                 "https://nonexistent.example.com/x", "https://hooks.example.com:99999/x", "file:///etc/passwd"])
def test_unsafe_schemes_credentials_and_unresolvable_hosts_are_refused(org, url):
    assert org.req("POST", "/webhooks", {"url": url}).status_code == 422


def test_dns_rebinding_between_creation_and_delivery_is_blocked(org, monkeypatch):
    hook = make_hook(org)
    org.customer()
    # the hostname now resolves to an internal address: delivery must fail without sending anything
    monkeypatch.setattr(webhooks, "resolver", fake_resolver({"hooks.example.com": ["169.254.169.254"]}))
    seen = run_dispatch(org, lambda r: httpx.Response(200))
    assert seen == []
    assert "private or internal" in deliveries(org, hook)[-1]["last_error"]


def test_private_urls_can_be_enabled_for_development_only(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "webhook_allow_private_urls", True)
    monkeypatch.setattr(s, "webhook_allow_http", True)
    monkeypatch.setattr(webhooks, "resolver", fake_resolver({"localhost": ["127.0.0.1"]}))
    assert webhooks.resolve_target("http://localhost:9000/hook").address == "127.0.0.1"
    monkeypatch.setattr(s, "environment", "production")
    assert any("WEBHOOK_ALLOW_PRIVATE_URLS" in p for p in s.problems())


# ---- secrets -------------------------------------------------------------------------------------
def test_signing_secret_is_encrypted_at_rest_shown_once_and_bound_to_its_tenant(org, other_org, admin_conn):
    hook = make_hook(org)
    assert hook["secret"].startswith("whsec_")
    assert "secret" not in org.req("GET", "/webhooks", expect=200).json()["items"][0]
    stored = admin_conn.execute("SELECT secret_enc FROM prov.webhooks WHERE webhook_id = %s", (hook["webhook_id"],)).fetchone()[0]
    assert hook["secret"] not in stored and hook["secret"][6:] not in stored and stored.startswith("v1.")
    assert decrypt_secret(stored, webhooks.secret_context(org.tenant_id)) == hook["secret"]
    with pytest.raises(ValueError):  # the ciphertext is useless if copied into another tenant's row
        decrypt_secret(stored, webhooks.secret_context(other_org.tenant_id))
    with pytest.raises(ValueError):
        decrypt_secret(stored[:-3] + "AAA", webhooks.secret_context(org.tenant_id))
    entries = str(org.req("GET", "/audit", expect=200, entity="webhook").json())
    assert "secret_enc" not in entries and hook["secret"] not in entries


def test_secret_rotation_changes_the_signature_key(org):
    hook = make_hook(org)
    new = org.req("POST", f"/webhooks/{hook['webhook_id']}/rotate-secret", expect=200).json()["secret"]
    assert new != hook["secret"]
    org.customer()
    req = run_dispatch(org, lambda r: httpx.Response(200))[0]
    assert req.headers["webhook-signature"] == webhooks.sign(new, req.headers["webhook-id"], int(req.headers["webhook-timestamp"]), req.content.decode())


def test_webhook_management_requires_admin_and_is_tenant_scoped(org, other_org):
    hook = make_hook(org)
    other_org.req("GET", f"/webhooks/{hook['webhook_id']}/deliveries", expect=404)
    other_org.req("PATCH", f"/webhooks/{hook['webhook_id']}", {"is_active": False}, expect=404)
    other_org.req("DELETE", f"/webhooks/{hook['webhook_id']}", expect=404)
    staff = org.add_user("staff")
    org.req("GET", "/webhooks", token=staff, expect=403)
    org.req("POST", f"/webhooks/{hook['webhook_id']}/test", expect=200)
    run_dispatch(org, lambda r: httpx.Response(200))
    assert any(d["event_type"] == "webhook.test" for d in deliveries(org, hook))
    org.req("DELETE", f"/webhooks/{hook['webhook_id']}", expect=204)
    org.req("GET", f"/webhooks/{hook['webhook_id']}/deliveries", expect=404)


def test_webhook_events_never_cross_tenants(org, other_org):
    mine, theirs = make_hook(org), make_hook(other_org)
    org.customer()
    seen = run_dispatch(org, lambda r: httpx.Response(200))
    assert seen and all(json.loads(r.content)["tenant_id"] == org.tenant_id for r in seen)
    assert deliveries(other_org, theirs) == [] and mine


def test_new_subscription_does_not_receive_the_backlog(org):
    org.product("1.00")  # event exists before the subscription does
    hook = make_hook(org, event_types=["product.*"])
    assert run_dispatch(org, lambda r: httpx.Response(200)) == [] and deliveries(org, hook) == []
    org.product("2.00")
    assert len(run_dispatch(org, lambda r: httpx.Response(200))) == 1
