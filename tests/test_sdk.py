"""The Python SDK: retry policy, error mapping, and webhook verification against the server's signer."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk" / "python"))
from provenance_cloud import ApiError, Client, WebhookVerificationError, verify_webhook  # noqa: E402

from app.security import new_webhook_secret  # noqa: E402
from app.services.webhooks import sign  # noqa: E402


def client_with(handler, **kw):
    return Client("https://pc.example.com", "prv_test", transport=httpx.MockTransport(handler), **kw)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    slept = []
    monkeypatch.setattr(time, "sleep", slept.append)
    return slept


def test_retries_503_then_succeeds_and_sends_the_same_event_each_time(no_sleep):
    calls = []

    def handler(req: httpx.Request):
        calls.append(req.content)
        return httpx.Response(503) if len(calls) < 3 else httpx.Response(201, json={"duplicate": False})

    out = client_with(handler).send_event(source="s", id="e1", type="a.b", data={}, time="2026-01-01T00:00:00Z")
    assert out == {"duplicate": False} and len(calls) == 3 and len(set(calls)) == 1  # identical body: safe to retry
    assert no_sleep == [0.5, 1.0]  # exponential backoff


def test_429_honours_retry_after(no_sleep):
    n = []

    def handler(req):
        n.append(1)
        return httpx.Response(429, headers={"Retry-After": "7"}) if len(n) == 1 else httpx.Response(200, json={"ok": True})

    client_with(handler).checkpoints()
    assert no_sleep[0] == 7


def test_client_errors_are_not_retried_and_expose_the_code():
    n = []

    def handler(req):
        n.append(1)
        return httpx.Response(422, json={"code": "SOURCE_UNKNOWN", "detail": "Unknown source: x", "request_id": "r1"})

    with pytest.raises(ApiError) as exc:
        client_with(handler).send_event(source="x", id="1", type="a.b", data={})
    assert exc.value.code == "SOURCE_UNKNOWN" and exc.value.status == 422 and exc.value.request_id == "r1" and len(n) == 1


def test_gives_up_after_max_retries_on_network_errors():
    def handler(req):
        raise httpx.ConnectError("down")

    with pytest.raises(httpx.ConnectError):
        client_with(handler, max_retries=2).send_event(source="s", id="1", type="a.b", data={})


def test_iter_events_follows_cursors():
    pages = {None: {"items": [{"id": 1}, {"id": 2}], "next_cursor": 2}, "2": {"items": [{"id": 3}], "next_cursor": None}}
    out = list(client_with(lambda r: httpx.Response(200, json=pages[r.url.params.get("cursor")])).iter_events())
    assert [e["id"] for e in out] == [1, 2, 3]


def test_webhook_verification_roundtrip_and_failures():
    secret = new_webhook_secret()
    body = b'{"id":"evt_1"}'
    ts = int(time.time())
    headers = {"Webhook-Id": "msg_1", "Webhook-Timestamp": str(ts), "Webhook-Signature": sign(secret, "msg_1", ts, body.decode())}
    verify_webhook(secret, headers, body)  # valid
    with pytest.raises(WebhookVerificationError):
        verify_webhook(secret, headers, body + b" ")  # body altered
    with pytest.raises(WebhookVerificationError):
        verify_webhook(new_webhook_secret(), headers, body)  # wrong secret
    old = ts - 3600
    stale = {**headers, "Webhook-Timestamp": str(old), "Webhook-Signature": sign(secret, "msg_1", old, body.decode())}
    with pytest.raises(WebhookVerificationError, match="tolerance"):
        verify_webhook(secret, stale, body)  # correctly signed but replayed late
    with pytest.raises(WebhookVerificationError):
        verify_webhook(secret, {}, body)
