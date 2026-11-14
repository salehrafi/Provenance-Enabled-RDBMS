"""Reconstructing external records from their event stream.

An ingested event describes a change to one record in an upstream system:
`subject` = "<entity>/<external id>", `data.op` = c|u|d (Debezium style) and `data.after` = the
complete record after the change. The state of a record at time T is therefore the `after` of
its latest event at or before T, or "did not exist" if that event was a delete (or there is none).

Two clocks are available (bitemporal queries):
  occurred_at  when the change happened in the source system  -> `at`
  received_at  when this service learned about it              -> `known_at`
"What did the record look like on the 1st, as we understood it on the 3rd?" is `at=1st&known_at=3rd`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.common import diff_values
from app.db import Db, utc
from app.errors import not_found
from app.services.ingestion import get_source

DELETED = object()
_DELETE_OPS = ("d", "delete", "deleted")


def state_of(payload: Any) -> Any:
    """Record state described by an event payload: a dict, or DELETED."""
    data = (payload or {}).get("data") or {}
    if str(data.get("op", "")).lower() in _DELETE_OPS:
        return DELETED
    after = data.get("after")
    # Events without before/after are treated as carrying the record directly in `data`.
    return after if isinstance(after, dict) else {k: v for k, v in data.items() if k not in ("op", "before", "after")}


def is_deleted(state: Any) -> bool:
    return state is DELETED


def latest_states(db: Db, source_id: int, entity: str, as_of: datetime,
                  known_at: datetime | None = None) -> dict[str, tuple[Any, dict]]:
    """external_id -> (state from the latest event up to as_of, the event row)."""
    rows = db.all(
        """SELECT DISTINCT ON (e.external_id) e.external_id, e.payload, e.occurred_at, e.received_at, e.event_pk,
                  e.event_type
             FROM external_events e
            WHERE e.source_id = %(s)s AND e.entity = %(e)s AND e.external_id IS NOT NULL
              AND e.occurred_at <= %(at)s AND (%(k)s::timestamptz IS NULL OR e.received_at <= %(k)s)
            ORDER BY e.external_id, e.occurred_at DESC, e.event_pk DESC""",
        {"s": source_id, "e": entity, "at": utc(as_of), "k": utc(known_at) if known_at else None})
    return {r["external_id"]: (state_of(r["payload"]), r) for r in rows}


def list_entities(db: Db, source_code: str) -> list[dict[str, Any]]:
    src = get_source(db, source_code)
    return db.all(
        "SELECT entity, count(DISTINCT external_id) AS records, count(*) AS events, max(occurred_at) AS last_change "
        "FROM external_events WHERE source_id = %s AND entity IS NOT NULL GROUP BY entity ORDER BY entity",
        (src["source_id"],))


def list_records(db: Db, source_code: str, entity: str, at: datetime | None, search: str | None,
                 cursor: str | None, limit: int) -> dict[str, Any]:
    src = get_source(db, source_code)
    pattern = None
    if search:
        pattern = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = db.all(
        """SELECT * FROM (
             SELECT DISTINCT ON (e.external_id) e.external_id, e.payload, e.occurred_at, e.event_pk, e.event_type,
                    count(*) OVER (PARTITION BY e.external_id) AS event_count
               FROM external_events e
              WHERE e.source_id = %(s)s AND e.entity = %(e)s AND e.external_id IS NOT NULL
                AND e.occurred_at <= %(at)s
                AND (%(c)s::text IS NULL OR e.external_id > %(c)s)
                AND (%(q)s::text IS NULL OR e.external_id ILIKE %(q)s)
              ORDER BY e.external_id, e.occurred_at DESC, e.event_pk DESC) x
            ORDER BY external_id LIMIT %(l)s""",
        {"s": src["source_id"], "e": entity, "at": utc(at or datetime.now(UTC)), "c": cursor,
         "q": pattern, "l": limit})
    items = []
    for r in rows:
        state = state_of(r["payload"])
        items.append({"external_id": r["external_id"], "deleted": is_deleted(state),
                      "state": None if is_deleted(state) else state, "last_event_pk": r["event_pk"],
                      "last_event_type": r["event_type"], "last_change": r["occurred_at"],
                      "event_count": r["event_count"]})
    return {"source": src["code"], "entity": entity, "trust_level": src["trust_level"],
            "capture_method": src["capture_method"], "items": items,
            "next_cursor": items[-1]["external_id"] if len(items) == limit else None}


_EVENT_SQL = """
    SELECT e.event_pk, e.source_event_id AS id, e.event_type AS type, e.occurred_at, e.received_at, e.trust_level,
           e.capture_method, e.payload, a.audit_id, a.chain_seq, a.row_hash, a.actor
      FROM external_events e
      LEFT JOIN audit_log a ON a.entity = 'external_event' AND a.record_pk = e.event_pk::text
     WHERE e.source_id = %(s)s AND e.entity = %(e)s AND e.external_id = %(x)s
"""


def _evidence(row: dict[str, Any]) -> dict[str, Any]:
    return {k: row[k] for k in ("event_pk", "id", "type", "occurred_at", "received_at", "trust_level",
                                "capture_method", "audit_id", "chain_seq", "row_hash", "actor")}


def history(db: Db, source_code: str, entity: str, external_id: str) -> dict[str, Any]:
    src = get_source(db, source_code)
    rows = db.all(_EVENT_SQL + " ORDER BY e.occurred_at, e.event_pk",
                  {"s": src["source_id"], "e": entity, "x": external_id})
    if not rows:
        raise not_found("Record")
    versions = []
    prev: dict | None = None
    for r in rows:
        state = state_of(r["payload"])
        now = None if is_deleted(state) else state
        versions.append({**_evidence(r), "deleted": is_deleted(state), "state": now,
                         "changes": diff_values(prev, now), "op": (r["payload"].get("data") or {}).get("op")})
        prev = now
    return {"source": src["code"], "entity": entity, "external_id": external_id, "current": prev,
            "exists": prev is not None, "trust_level": src["trust_level"], "capture_method": src["capture_method"],
            "versions": versions}


def as_of(db: Db, source_code: str, entity: str, external_id: str, at: datetime,
          known_at: datetime | None = None) -> dict[str, Any]:
    src = get_source(db, source_code)
    row = db.one(
        _EVENT_SQL + " AND e.occurred_at <= %(at)s AND (%(k)s::timestamptz IS NULL OR e.received_at <= %(k)s) "
        "ORDER BY e.occurred_at DESC, e.event_pk DESC LIMIT 1",
        {"s": src["source_id"], "e": entity, "x": external_id, "at": utc(at),
         "k": utc(known_at) if known_at else None})
    state = state_of(row["payload"]) if row else DELETED
    return {"source": src["code"], "entity": entity, "external_id": external_id, "as_of": utc(at),
            "known_at": utc(known_at) if known_at else None,
            "existed": row is not None and not is_deleted(state),
            "state": None if is_deleted(state) else state,
            "method": "latest event at or before the requested time",
            "based_on": _evidence(row) if row else None}


def compare(db: Db, source_code: str, entity: str, external_id: str, t1: datetime, t2: datetime) -> dict[str, Any]:
    if utc(t1) > utc(t2):
        t1, t2 = t2, t1
    a = as_of(db, source_code, entity, external_id, t1)
    b = as_of(db, source_code, entity, external_id, t2)
    src = get_source(db, source_code)
    between = db.all(
        _EVENT_SQL + " AND e.occurred_at > %(t1)s AND e.occurred_at <= %(t2)s ORDER BY e.occurred_at, e.event_pk",
        {"s": src["source_id"], "e": entity, "x": external_id, "t1": utc(t1), "t2": utc(t2)})
    return {"source": src["code"], "entity": entity, "external_id": external_id, "from": utc(t1), "to": utc(t2),
            "existed_from": a["existed"], "existed_to": b["existed"], "state_from": a["state"], "state_to": b["state"],
            "changes": diff_values(a["state"], b["state"]), "events_between": [_evidence(r) for r in between]}
