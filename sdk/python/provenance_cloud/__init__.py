"""Provenance Cloud client.

    from provenance_cloud import Client
    pc = Client("https://provenance.example.com", api_key="prv_...")
    pc.send_event(source="legacy-shop", id="evt-1", type="order.updated", subject="order/10045",
                  data={"op": "u", "before": {"total": "1500.00"}, "after": {"total": "1200.00"}})

Retries are safe because events are idempotent on (source, id): the client retries network errors,
HTTP 429 (honouring Retry-After) and 502/503/504 with exponential backoff, and a retry that already
succeeded server-side returns the original event with `duplicate: true`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from typing import Any

import httpx

__all__ = ["Client", "ApiError", "verify_webhook", "WebhookVerificationError"]
__version__ = "0.1.0"


class ApiError(Exception):
    """An RFC 9457 problem response. `code` is stable and safe to branch on."""

    def __init__(self, status: int, body: dict[str, Any]):
        super().__init__(f"{status} {body.get('code', '')}: {body.get('detail', '')}")
        self.status, self.body = status, body
        self.code = body.get("code")
        self.detail = body.get("detail")
        self.request_id = body.get("request_id")


class Client:
    def __init__(self, base_url: str, api_key: str, *, timeout: float = 15.0, max_retries: int = 4,
                 transport: httpx.BaseTransport | None = None):
        self._http = httpx.Client(
            base_url=base_url.rstrip("/") + "/api/v1", timeout=timeout, transport=transport,
            headers={"Authorization": f"Bearer {api_key}", "User-Agent": f"provenance-cloud-python/{__version__}"})
        self._retries = max_retries

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _request(self, method: str, path: str, **kw: Any) -> Any:
        delay = 0.5
        for attempt in range(self._retries + 1):
            try:
                r = self._http.request(method, path, **kw)
            except httpx.TransportError:
                if attempt == self._retries:
                    raise
            else:
                if r.status_code < 400:
                    return r.json() if r.content else None
                if r.status_code not in (429, 502, 503, 504) or attempt == self._retries:
                    try:
                        body = r.json()
                    except ValueError:
                        body = {"detail": r.text[:200]}
                    raise ApiError(r.status_code, body)
                delay = max(delay, float(r.headers.get("retry-after", 0) or 0))
            time.sleep(min(delay, 30))
            delay *= 2
        raise AssertionError("unreachable")

    # ---- ingestion ---------------------------------------------------------------------
    def send_event(self, *, source: str, id: str, type: str, data: Mapping[str, Any], subject: str | None = None,
                   time: datetime | str | None = None, **extensions: Any) -> dict[str, Any]:
        """Send one CloudEvent. Returns the stored event; `duplicate` is True on a safe retry."""
        body = {"specversion": "1.0", "id": id, "source": source, "type": type, "subject": subject,
                "time": _iso(time), "data": dict(data), **extensions}
        return self._request("POST", "/events", json={k: v for k, v in body.items() if v is not None})

    def send_events(self, events: list[Mapping[str, Any]]) -> dict[str, Any]:
        """Send up to 500 CloudEvents; each succeeds or fails on its own (see `results`)."""
        return self._request("POST", "/events:batch", json=list(events))

    def iter_events(self, *, source: str | None = None, type: str | None = None, subject: str | None = None,
                    page_size: int = 100) -> Iterator[dict[str, Any]]:
        cursor = None
        while True:
            params = {"source": source, "type": type, "subject": subject, "cursor": cursor, "limit": page_size}
            page = self._request("GET", "/ingested-events", params={k: v for k, v in params.items() if v is not None})
            yield from page["items"]
            cursor = page["next_cursor"]
            if not cursor:
                return

    def reconcile(self, *, source: str, entity: str, records: list[Mapping[str, Any]], complete: bool = False,
                  as_of: datetime | str | None = None) -> dict[str, Any]:
        """Compare an upstream snapshot with the evidence held. `records`: [{"external_id", "fields"}]."""
        body: dict[str, Any] = {"source": source, "entity": entity, "complete": complete, "records": list(records)}
        if as_of:
            body["as_of"] = _iso(as_of)
        return self._request("POST", "/reconciliations", json=body)

    # ---- provenance and integrity (need the matching key scopes) --------------------------
    def verify_audit(self, checkpoints: list[Mapping[str, Any]] | None = None) -> dict[str, Any]:
        """Verify the chain and checkpoints. Pass checkpoints you stored yourself to detect a full rewrite."""
        return self._request("POST", "/audit/verify", json={"checkpoints": list(checkpoints or [])})

    def checkpoints(self, limit: int = 100) -> dict[str, Any]:
        return self._request("GET", "/audit/checkpoints", params={"limit": limit})

    def history(self, entity: str, record_pk: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/provenance/{entity}/{record_pk}/history")["history"]

    def as_of(self, entity: str, record_pk: str, at: datetime | str) -> dict[str, Any]:
        return self._request("GET", f"/provenance/{entity}/{record_pk}/as-of", params={"at": _iso(at)})


def _iso(value: datetime | str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class WebhookVerificationError(ValueError):
    pass


def verify_webhook(secret: str, headers: Mapping[str, str], body: bytes, tolerance_seconds: int = 300) -> None:
    """Verify a Standard Webhooks delivery. Raises WebhookVerificationError; returns None when valid.

    Rejects stale timestamps (replay protection). Deduplicate on the `webhook-id` header: deliveries are
    at-least-once and the id is stable across retries."""
    h = {k.lower(): v for k, v in headers.items()}
    try:
        msg_id, ts, sigs = h["webhook-id"], h["webhook-timestamp"], h["webhook-signature"]
        stamp = int(ts)
    except (KeyError, ValueError) as exc:
        raise WebhookVerificationError("missing or malformed webhook headers") from exc
    if abs(time.time() - stamp) > tolerance_seconds:
        raise WebhookVerificationError("timestamp outside the tolerance window")
    key = base64.b64decode(secret.removeprefix("whsec_"))
    expected = base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
    for candidate in sigs.split(" "):
        version, _, sig = candidate.partition(",")
        if version == "v1" and hmac.compare_digest(sig, expected):
            return
    raise WebhookVerificationError("signature mismatch")
