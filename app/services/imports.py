"""CSV snapshots: for systems whose only integration point is a file export.

A snapshot CSV has one row per record: an `external_id` column plus any fields. Importing
compares every row with the latest state we hold and records only the differences as events:

  created    new external_id (or one we had recorded as deleted)
  updated    at least one field differs; the event carries before/after
  deleted    (complete snapshots only) a record we hold is absent from the file
  unchanged  nothing to record

Event ids derive from the record, its previous event and its new content, so uploading the same
file twice records nothing new, while a genuine A -> B -> A -> B history is kept.
`dry_run` previews without writing.
"""

from __future__ import annotations

import csv
import hashlib
import io
from datetime import UTC, datetime
from typing import Any

from app.db import Db, dumps
from app.errors import ApiError
from app.schemas import CloudEventIn
from app.services.ingestion import get_source, ingest_one
from app.services.reconcile import same
from app.services.records import is_deleted, latest_states

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ROWS = 5000


def parse_snapshot(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_FILE_BYTES:
        raise ApiError(413, f"File larger than {MAX_FILE_BYTES // (1024 * 1024)} MB", "PAYLOAD_TOO_LARGE")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ApiError(422, "File must be UTF-8 encoded CSV", "INVALID_CSV") from None
    reader = csv.DictReader(io.StringIO(text))
    headers = [h.strip() for h in (reader.fieldnames or []) if h]
    if "external_id" not in headers:
        raise ApiError(422, "CSV needs a header row with an 'external_id' column", "INVALID_CSV")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line, r in enumerate(reader, start=2):
        if len(rows) >= MAX_ROWS:
            raise ApiError(413, f"At most {MAX_ROWS} rows per file", "PAYLOAD_TOO_LARGE")
        if None in r:
            raise ApiError(422, f"Line {line}: more values than header columns", "INVALID_CSV")
        clean = {k.strip(): (v.strip() if isinstance(v, str) and v.strip() != "" else None) for k, v in r.items() if k}
        ext = clean.pop("external_id", None)
        if not ext:
            raise ApiError(422, f"Line {line}: external_id is empty", "INVALID_CSV")
        if len(ext) > 100:
            raise ApiError(422, f"Line {line}: external_id longer than 100 characters", "INVALID_CSV")
        if ext in seen:
            raise ApiError(422, f"Line {line}: duplicate external_id '{ext}'", "INVALID_CSV")
        seen.add(ext)
        rows.append({"external_id": ext, "fields": clean})
    if not rows:
        raise ApiError(422, "CSV has no data rows", "INVALID_CSV")
    return rows


def _event_id(entity: str, ext: str, prev_pk: Any, op: str, after: Any) -> str:
    digest = hashlib.sha256(f"{entity}|{ext}|{prev_pk or 0}|{op}|{dumps(after)}".encode()).hexdigest()
    return f"csv-{digest[:40]}"


def import_snapshot(db: Db, source: str, entity: str, rows: list[dict], complete: bool, dry_run: bool) -> dict:
    src = get_source(db, source)
    if src["status"] != "ACTIVE" and not dry_run:
        raise ApiError(409, f"Source is paused: {source}", "SOURCE_PAUSED")
    now = datetime.now(UTC)
    ours = latest_states(db, src["source_id"], entity, now)

    changes: list[dict] = []
    unchanged = 0
    for row in rows:
        ext, fields = row["external_id"], row["fields"]
        state: Any
        prev: Any
        state, prev = ours.get(ext, (None, None))
        if prev is None or is_deleted(state):
            changes.append({"external_id": ext, "op": "c", "before": None, "after": fields, "prev": prev})
            continue
        diffs = [k for k, v in fields.items() if not same(v, state.get(k))]
        if diffs:
            changes.append({"external_id": ext, "op": "u", "before": state, "after": {**state, **fields},
                            "changed": diffs, "prev": prev})
        else:
            unchanged += 1
    if complete:
        listed = {r["external_id"] for r in rows}
        for ext, (state, prev) in ours.items():
            if ext not in listed and not is_deleted(state):
                changes.append({"external_id": ext, "op": "d", "before": state, "after": None, "prev": prev})

    verbs = {"c": "created", "u": "updated", "d": "deleted"}
    results = []
    cache: dict[str, dict[str, Any]] = {source: src}
    for ch in changes:
        out = {"external_id": ch["external_id"], "change": verbs[ch["op"]], "before": ch["before"], "after": ch["after"]}
        if "changed" in ch:
            out["changed_fields"] = ch["changed"]
        if not dry_run:
            prev_pk = ch["prev"]["event_pk"] if ch["prev"] else None
            ev = CloudEventIn(
                specversion="1.0", source=source, type=f"{entity}.{verbs[ch['op']]}",
                id=_event_id(entity, ch["external_id"], prev_pk, ch["op"], ch["after"]),
                subject=f"{entity}/{ch['external_id']}", time=now,
                data={"op": ch["op"], "before": ch["before"], "after": ch["after"]})
            code, res = ingest_one(db, ev, cache)
            out["event_pk"] = res["event_pk"]
            out["duplicate"] = code == 200
        results.append(out)
    if not dry_run:
        db.commit()
    else:
        db.rollback()

    def count(v: str) -> int:
        return sum(1 for c in results if c["change"] == v)

    return {"source": source, "entity": entity, "dry_run": dry_run, "complete": complete, "rows": len(rows),
            "created": count("created"), "updated": count("updated"), "deleted": count("deleted"),
            "unchanged": unchanged, "trust_level": src["trust_level"], "capture_method": src["capture_method"],
            "changes": results[:500], "changes_truncated": len(results) > 500}
