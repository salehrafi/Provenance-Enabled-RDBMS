"""Outbox dispatcher: turns outbox events into signed webhook deliveries.

Flow, all of it safe to run from several worker processes at once:

1. fan_out     pending outbox events -> one webhook_deliveries row per matching subscription
               (rows are claimed with FOR UPDATE SKIP LOCKED; the unique index makes it idempotent).
2. claim       due deliveries get a lease (locked_until) and the lease is committed.
3. send        the HTTP call happens outside any database transaction.
4. record      SUCCESS, or FAILED with exponential backoff + jitter, or DEAD after the last attempt.

A worker that dies between 2 and 4 simply lets its lease expire and the delivery is retried, so
delivery is at-least-once. Receivers dedupe on the `webhook-id` header, which is stable across
retries.

SSRF defence: the hostname is resolved, every address is checked, and the request is then sent
to that exact address (with the original Host header and TLS server name). Checking a name and
then letting the HTTP client resolve it again would allow DNS rebinding.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import logging
import random
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.config import get_settings
from app.db import Db, dumps
from app.security import decrypt_secret, encrypt_secret
from app.services.rules import Finding, raise_alert

log = logging.getLogger("app.webhooks")

USER_AGENT = "ProvenanceCloud-Webhooks/3.0"
MAX_BACKOFF_SECONDS = 6 * 3600

# Replaceable in tests (and the single place name resolution happens).
resolver: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo


def matches(patterns: list[str], event_type: str) -> bool:
    return any(p == "*" or p == event_type or (p.endswith(".*") and event_type.startswith(p[:-1])) for p in patterns)


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    address: str   # the vetted IP the request is actually sent to
    path: str

    @property
    def pinned_url(self) -> str:
        literal = f"[{self.address}]" if ":" in self.address else self.address
        return f"{self.scheme}://{literal}:{self.port}{self.path}"

    @property
    def host_header(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_target(url: str) -> Target:
    """Validate a webhook URL and resolve it to one vetted address. Raises ValueError."""
    s = get_settings()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("URL must be http(s) with a host")
    if parts.scheme == "http" and not s.webhook_allow_http:
        raise ValueError("Webhook URLs must use https")
    if parts.username or parts.password:
        raise ValueError("Webhook URLs must not contain credentials")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Invalid port") from exc
    host = parts.hostname
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ValueError(f"Cannot resolve host: {host}") from exc
    addresses = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]
    if not addresses:
        raise ValueError(f"Cannot resolve host: {host}")
    if not s.webhook_allow_private_urls and not all(_is_public(a) for a in addresses):
        # Refuse if ANY address is internal: a name that sometimes resolves inside is not trusted.
        raise ValueError("Webhook URL resolves to a private or internal address")
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return Target(parts.scheme, host, port, str(addresses[0]), path)


def _secret_bytes(secret: str) -> bytes:
    raw = secret.removeprefix("whsec_")
    try:
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return raw.encode()


def sign(secret: str, msg_id: str, timestamp: int, body: str) -> str:
    """Standard Webhooks: base64(HMAC_SHA256(key, "{id}.{timestamp}.{body}")), prefixed with v1."""
    mac = hmac.new(_secret_bytes(secret), f"{msg_id}.{timestamp}.{body}".encode(), hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode()


def secret_context(tenant_id: int) -> str:
    return f"webhook-secret:{tenant_id}"


def seal_secret(tenant_id: int, secret: str) -> str:
    return encrypt_secret(secret, secret_context(tenant_id))


def backoff_seconds(attempts: int) -> float:
    """15 s, 30 s, 60 s ... capped at 6 h, with +/-20% jitter so retries do not synchronise.

    With the default 12 attempts the total retry window is about 8 hours."""
    base = min(MAX_BACKOFF_SECONDS, 15 * 2 ** (attempts - 1))
    return base * random.uniform(0.8, 1.2)


def fan_out(db: Db) -> int:
    events = db.all(
        "SELECT event_id, event_type, created_at FROM outbox_events WHERE dispatched_at IS NULL "
        "ORDER BY event_id LIMIT 500 FOR UPDATE SKIP LOCKED")
    if not events:
        db.rollback()
        return 0
    hooks = db.all("SELECT webhook_id, event_types, created_at FROM webhooks WHERE is_active")
    # A subscription only sees events from after it was created, never the organization's backlog.
    pairs = [(h["webhook_id"], e["event_id"]) for e in events for h in hooks
             if e["created_at"] >= h["created_at"] and matches(h["event_types"], e["event_type"])]
    if pairs:
        db.executemany("INSERT INTO webhook_deliveries (webhook_id, event_id) VALUES (%s, %s) "
                       "ON CONFLICT (webhook_id, event_id) DO NOTHING", pairs)
    db.execute("UPDATE outbox_events SET dispatched_at = now() WHERE event_id = ANY(%s)",
               ([e["event_id"] for e in events],))
    db.commit()
    return len(events)


def _claim(db: Db, limit: int) -> list[dict[str, Any]]:
    s = get_settings()
    rows = db.all(
        """WITH due AS (
             SELECT d.delivery_id FROM webhook_deliveries d
               JOIN webhooks w ON w.webhook_id = d.webhook_id AND w.is_active
              WHERE d.status IN ('PENDING', 'FAILED') AND d.next_attempt_at <= now()
                AND (d.locked_until IS NULL OR d.locked_until < now())
              ORDER BY d.next_attempt_at LIMIT %s
              FOR UPDATE OF d SKIP LOCKED)
           UPDATE webhook_deliveries d
              SET locked_until = now() + make_interval(secs => %s), attempts = d.attempts + 1
             FROM due, webhooks w, outbox_events e
            WHERE d.delivery_id = due.delivery_id AND w.webhook_id = d.webhook_id AND e.event_id = d.event_id
        RETURNING d.delivery_id, d.attempts, w.webhook_id, w.url, w.secret_enc, e.event_id, e.event_type,
                  e.entity, e.entity_id, e.payload, e.request_id, e.created_at""",
        (limit, s.webhook_lease_seconds))
    db.commit()
    return rows


def build_message(tenant_id: int, d: dict[str, Any]) -> str:
    return dumps({
        "id": f"evt_{d['event_id']}",
        "type": d["event_type"],
        "created_at": d["created_at"],
        "tenant_id": tenant_id,
        "request_id": d["request_id"],
        "entity": d["entity"],
        "entity_id": d["entity_id"],
        "data": d["payload"],
    })


def _send(client: httpx.Client, tenant_id: int, d: dict[str, Any]) -> tuple[bool, int | None, str | None, str | None, int]:
    """Return (ok, status code, error, response snippet, duration ms). Never raises."""
    s = get_settings()
    started = time.perf_counter()
    try:
        target = resolve_target(d["url"])
        secret = decrypt_secret(d["secret_enc"], secret_context(tenant_id))
    except ValueError as exc:
        return False, None, str(exc)[:1000], None, 0
    body = build_message(tenant_id, d)
    ts = int(time.time())
    msg_id = f"msg_{d['delivery_id']}"  # stable across retries, so receivers can dedupe
    headers = {
        "Host": target.host_header,
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "webhook-id": msg_id,
        "webhook-timestamp": str(ts),
        "webhook-signature": sign(secret, msg_id, ts, body),
        "X-Provenance-Event": d["event_type"],
    }
    try:
        resp = client.post(target.pinned_url, content=body, headers=headers, timeout=s.webhook_timeout_seconds,
                           follow_redirects=False, extensions={"sni_hostname": target.host})
        ms = int((time.perf_counter() - started) * 1000)
        snippet = resp.text[:500] if resp.content else None
        if 200 <= resp.status_code < 300:
            return True, resp.status_code, None, snippet, ms
        return False, resp.status_code, f"HTTP {resp.status_code}", snippet, ms
    except httpx.HTTPError as exc:
        ms = int((time.perf_counter() - started) * 1000)
        return False, None, f"{type(exc).__name__}: {exc}"[:1000], None, ms


def deliver_due(db: Db, tenant_id: int, client: httpx.Client, limit: int = 25) -> int:
    s = get_settings()
    claimed = _claim(db, limit)
    for d in claimed:
        ok, code, error, snippet, ms = _send(client, tenant_id, d)
        if ok:
            db.execute(
                "UPDATE webhook_deliveries SET status = 'SUCCESS', response_code = %s, response_snippet = %s, "
                "last_error = NULL, duration_ms = %s, delivered_at = now(), locked_until = NULL WHERE delivery_id = %s",
                (code, snippet, ms, d["delivery_id"]))
        else:
            dead = d["attempts"] >= s.webhook_max_attempts
            db.execute(
                "UPDATE webhook_deliveries SET status = %s, response_code = %s, response_snippet = %s, last_error = %s, "
                "duration_ms = %s, next_attempt_at = now() + make_interval(secs => %s), locked_until = NULL "
                "WHERE delivery_id = %s",
                ("DEAD" if dead else "FAILED", code, snippet, error, ms, backoff_seconds(d["attempts"]),
                 d["delivery_id"]))
            if dead:
                # An alert, not an outbox event: an event would be delivered to the same broken endpoint.
                raise_alert(db, Finding(
                    "WH001", "MEDIUM", "webhook", str(d["webhook_id"]),
                    f"Webhook #{d['webhook_id']} delivery of {d['event_type']} abandoned after {d['attempts']} attempts",
                    {"delivery_id": d["delivery_id"], "event_id": d["event_id"], "last_error": error},
                    f"WH001:{d['delivery_id']}"), emit=False)
        db.commit()
    return len(claimed)


def process_tenant(db: Db, tenant_id: int, client: httpx.Client) -> tuple[int, int]:
    return fan_out(db), deliver_due(db, tenant_id, client)
