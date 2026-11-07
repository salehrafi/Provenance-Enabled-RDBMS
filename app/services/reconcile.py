"""Reconciliation: does the evidence we hold match what the upstream system says now?

The upstream system sends a snapshot of records (external id + the fields it wants checked).
For each record we take the latest ingested event for that entity/external id (up to `as_of`)
and compare its `data.after` state:

  MATCHED     fields agree
  MISMATCH    a field differs, or we recorded a delete
  MISSING     upstream has the record, but we never received an event for it
  UNEXPECTED  (complete snapshots only) we hold a live record upstream no longer lists

Discrepancies raise a RC001 alert and every run emits a `reconciliation.completed` event.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

import oracledb
from fastapi import HTTPException, status

from app.common import dumps, emit_event
from app.db import Db, parse_json, to_db_time

_DELETED = object()


def _same(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is None and b is None
    try:
        return Decimal(str(a)) == Decimal(str(b))  # "1200.00" == 1200 == 1200.0
    except (InvalidOperation, ValueError):
        return str(a) == str(b)


def _state(payload: Any) -> Any:
    data = (parse_json(payload) or {}).get("data") or {}
    if str(data.get("op", "")).lower() in ("d", "delete", "deleted"):
        return _DELETED
    after = data.get("after")
    return after if isinstance(after, dict) else {k: v for k, v in data.items() if k not in ("op", "before")}


def get_source(db: Db, code: str) -> dict:
    src = db.one("SELECT source_id, code, status, capture_method, trust_level FROM sources WHERE code = :c", {"c": code})
    if not src:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown source: {code}")
    return src


def latest_states(db: Db, source_id: int, entity: str, as_of: datetime) -> dict[str, tuple[Any, dict]]:
    """external_id -> (state from the latest event up to as_of, or _DELETED; the event row)."""
    latest = db.all(
        """SELECT external_id, payload, occurred_at, event_pk FROM (
             SELECT e.external_id, e.payload, e.occurred_at, e.event_pk,
                    ROW_NUMBER() OVER (PARTITION BY e.external_id ORDER BY e.occurred_at DESC, e.event_pk DESC) rn
               FROM external_events e
              WHERE e.source_id = :s AND e.entity = :ent AND e.occurred_at <= :asof)
           WHERE rn = 1""",
        {"s": source_id, "ent": entity, "asof": to_db_time(as_of)},
    )
    return {r["external_id"]: (_state(r["payload"]), r) for r in latest}


def is_deleted(state: Any) -> bool:
    return state is _DELETED


def reconcile(db: Db, tenant_id: int, actor: str, source: str, entity: str, as_of: datetime | None,
              complete: bool, records: list[dict]) -> dict[str, Any]:
    src = get_source(db, source)
    as_of = to_db_time(as_of or datetime.now(timezone.utc))
    ours = latest_states(db, src["source_id"], entity, as_of)

    issues: list[dict] = []
    matched = 0
    seen: set[str] = set()
    for rec in records:
        ext = str(rec["external_id"])
        seen.add(ext)
        if ext not in ours:
            issues.append({"external_id": ext, "outcome": "MISSING",
                           "details": {"reason": "No event was ever received for this record", "upstream": rec["fields"]}})
            continue
        state, row = ours[ext]
        evidence = {"event_pk": row["event_pk"], "occurred_at": row["occurred_at"]}
        if state is _DELETED:
            issues.append({"external_id": ext, "outcome": "MISMATCH",
                           "details": {"reason": "Upstream still has the record, but we recorded a delete", **evidence}})
            continue
        diffs = [{"field": k, "upstream": v, "recorded": state.get(k)}
                 for k, v in rec["fields"].items() if not _same(v, state.get(k))]
        if diffs:
            issues.append({"external_id": ext, "outcome": "MISMATCH", "details": {"differences": diffs, **evidence}})
        else:
            matched += 1
    if complete:
        for ext, (state, row) in ours.items():
            if ext not in seen and state is not _DELETED:
                issues.append({"external_id": ext, "outcome": "UNEXPECTED",
                               "details": {"reason": "We hold a live record the upstream snapshot does not contain",
                                           "event_pk": row["event_pk"], "recorded": state}})

    counts = {o: sum(1 for i in issues if i["outcome"] == o) for o in ("MISMATCH", "MISSING", "UNEXPECTED")}
    recon_id = db.insert(
        "INSERT INTO reconciliations (source_id, entity, as_of, complete, total_records, matched, mismatched, missing, "
        "unexpected, created_by) VALUES (:s, :e, :a, :c, :t, :m, :mm, :mi, :u, :creator)",
        {"s": src["source_id"], "e": entity, "a": as_of, "c": "Y" if complete else "N", "t": len(records),
         "m": matched, "mm": counts["MISMATCH"], "mi": counts["MISSING"], "u": counts["UNEXPECTED"], "creator": actor},
        "recon_id",
    )
    if issues:
        with db.cursor() as cur:
            cur.executemany(
                "INSERT INTO reconciliation_items (recon_id, external_id, outcome, details) VALUES (:1, :2, :3, :4)",
                [(recon_id, i["external_id"], i["outcome"], dumps(i["details"])) for i in issues],
            )
    summary = {"recon_id": recon_id, "source": source, "entity": entity, "as_of": as_of.replace(tzinfo=timezone.utc),
               "complete": complete, "total_records": len(records), "matched": matched,
               "mismatched": counts["MISMATCH"], "missing": counts["MISSING"], "unexpected": counts["UNEXPECTED"]}
    if issues:
        try:
            alert_id = db.insert(
                "INSERT INTO alerts (rule_code, severity, entity, entity_id, title, details, fingerprint) "
                "VALUES ('RC001', 'HIGH', 'reconciliation', :id, :t, :d, :f)",
                {"id": str(recon_id), "d": dumps(summary), "f": f"RC001:{recon_id}",
                 "t": f"Reconciliation #{recon_id} of {source}/{entity}: {counts['MISMATCH']} mismatched, "
                      f"{counts['MISSING']} missing, {counts['UNEXPECTED']} unexpected"},
                "alert_id",
            )
            emit_event(db, tenant_id, "alert.raised", "alert", alert_id, {"alert_id": alert_id, "rule_code": "RC001", **summary})
        except oracledb.IntegrityError:
            pass
    emit_event(db, tenant_id, "reconciliation.completed", "reconciliation", recon_id, summary)
    db.commit()
    return {**summary, "issues": issues[:500], "issues_truncated": len(issues) > 500}
