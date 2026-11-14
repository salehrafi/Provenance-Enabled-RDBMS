"""Recording external events: shared by the API-key endpoints and CSV imports.

An event is a single INSERT. The database does the rest, for every client:

* a BEFORE INSERT trigger checks the source is active and stamps the event with the source's
  registered capture method and trust level (the sender cannot claim its own);
* the unique index on (tenant, source, source event id) makes a retry a no-op
  (`ON CONFLICT DO NOTHING`), so duplicates are detected without a race;
* an AFTER INSERT trigger writes the event into the hash-chained audit log and the outbox.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from app.db import Db, json_default, jsonb, utc
from app.errors import ApiError
from app.schemas import CloudEventIn

MAX_PAYLOAD_BYTES = 256 * 1024
SUBJECT = re.compile(r"^([a-z][a-z0-9_]{0,29})/(.{1,100})$")

EV_COLS = ("e.event_pk, s.code AS source, e.source_event_id AS id, e.event_type AS type, e.subject, e.entity, "
           "e.external_id, e.occurred_at, e.received_at, e.capture_method, e.trust_level, e.request_id")


def canonical_sha256(payload: dict[str, Any]) -> str:
    text = json.dumps(payload, default=json_default, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


def get_source(db: Db, code: str) -> dict[str, Any]:
    src = db.one("SELECT source_id, code, name, status, capture_method, trust_level FROM sources WHERE code = %s",
                 (code,))
    if not src:
        raise ApiError(422, f"Unknown source: {code}", "SOURCE_UNKNOWN")
    return src


def _existing(db: Db, source_id: int, event_id: str) -> dict[str, Any]:
    row = db.one(f"SELECT {EV_COLS}, e.payload_sha256 FROM external_events e JOIN sources s ON s.source_id = e.source_id "
                 "WHERE e.source_id = %s AND e.source_event_id = %s", (source_id, event_id))
    assert row is not None
    return row


def ingest_one(db: Db, body: CloudEventIn, sources: dict[str, dict[str, Any]] | None = None) -> tuple[int, dict]:
    """Record one event and return (HTTP status, event). Does not commit.

    `sources` is an optional per-request cache so a batch looks each source up once."""
    entity = external_id = None
    if body.subject:
        m = SUBJECT.match(body.subject)
        if not m:
            raise ApiError(422, "subject must look like '<entity>/<external id>'", "INVALID_SUBJECT")
        entity, external_id = m.groups()
    occurred = utc(body.time)
    payload = {"specversion": body.specversion, "id": body.id, "source": body.source, "type": body.type,
               "subject": body.subject, "time": occurred.isoformat().replace("+00:00", "Z"), "data": body.data,
               **(body.model_extra or {})}
    digest = canonical_sha256(payload)
    if len(json.dumps(payload, default=json_default).encode()) > MAX_PAYLOAD_BYTES:
        raise ApiError(413, f"Event larger than {MAX_PAYLOAD_BYTES // 1024} KiB", "PAYLOAD_TOO_LARGE")

    cache = sources if sources is not None else {}
    if body.source not in cache:
        cache[body.source] = get_source(db, body.source)
    src = cache[body.source]
    if src["status"] != "ACTIVE":
        raise ApiError(409, f"Source is paused: {body.source}", "SOURCE_PAUSED")

    event_pk = db.scalar(
        "INSERT INTO external_events (source_id, source_event_id, event_type, subject, entity, external_id, "
        "occurred_at, payload, payload_sha256) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (tenant_id, source_id, source_event_id) DO NOTHING RETURNING event_pk",
        (src["source_id"], body.id, body.type, body.subject, entity, external_id, occurred, jsonb(payload), digest))
    row = _existing(db, src["source_id"], body.id)
    stored_digest = row.pop("payload_sha256")
    if event_pk is None:
        # Same source + id seen before. `identical` tells the sender whether it re-sent the same
        # content or reused an id for something different (which is a bug on their side).
        return 200, {**row, "duplicate": True, "identical": stored_digest == digest}
    return 201, {**row, "duplicate": False, "identical": True}
