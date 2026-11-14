"""Reconciliation: does the evidence we hold match what the upstream system says now?

The upstream system sends a snapshot of records (external id + the fields to check). For each
record we take the latest ingested event for that entity/external id (up to `as_of`) and compare:

  MATCHED     fields agree
  MISMATCH    a field differs, or we recorded a delete
  MISSING     upstream has the record, but we never received an event for it
  UNEXPECTED  (complete snapshots only) we hold a live record upstream no longer lists

Discrepancies raise an RC001 alert; every run emits `reconciliation.completed`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from app.common import emit_event
from app.db import Db, jsonb, utc
from app.services.ingestion import get_source
from app.services.records import is_deleted, latest_states
from app.services.rules import Finding, raise_alert


def same(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is None and b is None
    try:
        return Decimal(str(a)) == Decimal(str(b))  # "1200.00" == 1200 == 1200.0
    except (InvalidOperation, ValueError):
        return str(a) == str(b)


def reconcile(db: Db, tenant_id: int, actor: str, source: str, entity: str, as_of: datetime | None,
              complete: bool, records: list[dict]) -> dict[str, Any]:
    src = get_source(db, source)
    at = utc(as_of or datetime.now(UTC))
    ours = latest_states(db, src["source_id"], entity, at)

    issues: list[dict] = []
    matched = 0
    seen: set[str] = set()
    for rec in records:
        ext = str(rec["external_id"])
        seen.add(ext)
        if ext not in ours:
            issues.append({"external_id": ext, "outcome": "MISSING",
                           "details": {"reason": "No event was ever received for this record",
                                       "upstream": rec["fields"]}})
            continue
        state, row = ours[ext]
        evidence = {"event_pk": row["event_pk"], "occurred_at": row["occurred_at"]}
        if is_deleted(state):
            issues.append({"external_id": ext, "outcome": "MISMATCH",
                           "details": {"reason": "Upstream still has the record, but we recorded a delete", **evidence}})
            continue
        diffs = [{"field": k, "upstream": v, "recorded": state.get(k)}
                 for k, v in rec["fields"].items() if not same(v, state.get(k))]
        if diffs:
            issues.append({"external_id": ext, "outcome": "MISMATCH", "details": {"differences": diffs, **evidence}})
        else:
            matched += 1
    if complete:
        for ext, (state, row) in ours.items():
            if ext not in seen and not is_deleted(state):
                issues.append({"external_id": ext, "outcome": "UNEXPECTED",
                               "details": {"reason": "We hold a live record the upstream snapshot does not contain",
                                           "event_pk": row["event_pk"], "recorded": state}})

    counts = {o: sum(1 for i in issues if i["outcome"] == o) for o in ("MISMATCH", "MISSING", "UNEXPECTED")}
    recon_id = db.insert(
        "INSERT INTO reconciliations (source_id, entity, as_of, complete, total_records, matched, mismatched, "
        "missing, unexpected, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (src["source_id"], entity, at, complete, len(records), matched, counts["MISMATCH"], counts["MISSING"],
         counts["UNEXPECTED"], actor), "recon_id")
    if issues:
        db.executemany(
            "INSERT INTO reconciliation_items (recon_id, external_id, outcome, details) VALUES (%s, %s, %s, %s)",
            [(recon_id, i["external_id"], i["outcome"], jsonb(i["details"])) for i in issues])
    summary = {"recon_id": recon_id, "source": source, "entity": entity, "as_of": at, "complete": complete,
               "total_records": len(records), "matched": matched, "mismatched": counts["MISMATCH"],
               "missing": counts["MISSING"], "unexpected": counts["UNEXPECTED"]}
    if issues:
        raise_alert(db, Finding(
            "RC001", "HIGH", "reconciliation", str(recon_id),
            f"Reconciliation #{recon_id} of {source}/{entity}: {counts['MISMATCH']} mismatched, "
            f"{counts['MISSING']} missing, {counts['UNEXPECTED']} unexpected", summary, f"RC001:{recon_id}"))
    emit_event(db, "reconciliation.completed", "reconciliation", recon_id, summary)
    db.commit()
    return {**summary, "issues": issues[:500], "issues_truncated": len(issues) > 500}
