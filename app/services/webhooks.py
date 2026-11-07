"""Outbox dispatcher: fans out outbox events to matching webhooks and delivers them.

Deliveries follow the Standard Webhooks spec (webhook-id / webhook-timestamp /
webhook-signature headers) and are retried with exponential backoff; after max attempts a
delivery is marked DEAD.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import logging
import socket
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
import oracledb

from app.common import dumps
from app.config import get_settings
from app.db import Db, parse_json

log = logging.getLogger("app.webhooks")


def matches(patterns: str, event_type: str) -> bool:
    for p in (x.strip() for x in patterns.split(",")):
        if p == "*" or p == event_type or (p.endswith(".*") and event_type.startswith(p[:-1])):
            return True
    return False


def validate_url(url: str) -> None:
    """Block webhooks to private/internal addresses (SSRF) unless explicitly allowed."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must be http(s) with a host")
    if get_settings().webhook_allow_private_urls:
        return
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve host: {parsed.hostname}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("Webhook URL resolves to a private or internal address")


def _secret_bytes(secret: str) -> bytes:
    raw = secret.removeprefix("whsec_")
    try:
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return raw.encode()  # secrets created before the Standard Webhooks format


def sign(secret: str, msg_id: str, timestamp: int, body: str) -> str:
    """Standard Webhooks: base64(HMAC_SHA256(key, "{id}.{timestamp}.{body}")), prefixed with v1."""
    mac = hmac.new(_secret_bytes(secret), f"{msg_id}.{timestamp}.{body}".encode(), hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode()


def fan_out(db: Db) -> int:
    events = db.all(
        "SELECT event_id, event_type FROM outbox_events WHERE dispatched_at IS NULL "
        "ORDER BY event_id FETCH FIRST 500 ROWS ONLY"
    )
    if not events:
        return 0
    hooks = db.all("SELECT webhook_id, event_types FROM webhooks WHERE is_active = 'Y'")
    for e in events:
        for h in hooks:
            if matches(h["event_types"], e["event_type"]):
                try:
                    db.execute("INSERT INTO webhook_deliveries (webhook_id, event_id) VALUES (:w, :e)",
                               {"w": h["webhook_id"], "e": e["event_id"]})
                except oracledb.IntegrityError:
                    pass
        db.execute("UPDATE outbox_events SET dispatched_at = SYS_EXTRACT_UTC(SYSTIMESTAMP) WHERE event_id = :e",
                   {"e": e["event_id"]})
    db.commit()
    return len(events)


def deliver_due(db: Db, tenant_id: int, client: httpx.Client) -> int:
    s = get_settings()
    due = db.all(
        """SELECT d.delivery_id, d.attempts, e.event_id, e.event_type, e.entity, e.entity_id, e.payload,
                  e.request_id, e.created_at, w.webhook_id, w.url, w.secret
             FROM webhook_deliveries d
             JOIN webhooks w ON w.webhook_id = d.webhook_id
             JOIN outbox_events e ON e.event_id = d.event_id
            WHERE d.status IN ('PENDING', 'FAILED') AND d.next_attempt_at <= SYS_EXTRACT_UTC(SYSTIMESTAMP)
              AND w.is_active = 'Y'
            ORDER BY d.delivery_id FETCH FIRST 50 ROWS ONLY"""
    )
    for d in due:
        body = dumps({
            "id": f"evt_{d['event_id']}",
            "type": d["event_type"],
            "created_at": d["created_at"],
            "tenant_id": tenant_id,
            "request_id": d["request_id"],
            "entity": d["entity"],
            "entity_id": d["entity_id"],
            "data": parse_json(d["payload"]),
        })
        ts = int(time.time())
        msg_id = f"msg_{d['delivery_id']}"  # stable across retries, so receivers can dedupe
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "ProvenanceCloud-Webhooks/2.0",
            "webhook-id": msg_id,
            "webhook-timestamp": str(ts),
            "webhook-signature": sign(d["secret"], msg_id, ts, body),
            "X-Provenance-Event": d["event_type"],
        }
        attempts = int(d["attempts"]) + 1
        code, error = None, None
        try:
            resp = client.post(d["url"], content=body, headers=headers, timeout=s.webhook_timeout_seconds)
            code = resp.status_code
            ok = 200 <= code < 300
            if not ok:
                error = f"HTTP {code}: {resp.text[:200]}"
        except httpx.HTTPError as exc:
            ok, error = False, f"{type(exc).__name__}: {exc}"[:1000]
        if ok:
            db.execute(
                "UPDATE webhook_deliveries SET status = 'SUCCESS', attempts = :a, response_code = :c, last_error = NULL, "
                "delivered_at = SYS_EXTRACT_UTC(SYSTIMESTAMP) WHERE delivery_id = :id",
                {"a": attempts, "c": code, "id": d["delivery_id"]},
            )
        else:
            dead = attempts >= s.webhook_max_attempts
            next_at = datetime.now(timezone.utc) + timedelta(seconds=5 * 2 ** attempts)
            db.execute(
                "UPDATE webhook_deliveries SET status = :st, attempts = :a, response_code = :c, last_error = :err, "
                "next_attempt_at = :n WHERE delivery_id = :id",
                {"st": "DEAD" if dead else "FAILED", "a": attempts, "c": code, "err": error, "n": next_at,
                 "id": d["delivery_id"]},
            )
        db.commit()
    return len(due)


def process_tenant(db: Db, tenant_id: int, client: httpx.Client) -> tuple[int, int]:
    return fan_out(db), deliver_due(db, tenant_id, client)
