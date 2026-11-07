from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from app.common import AUDIT_COLS, audit_entry, dumps, emit_event, not_found
from app.db import Db
from app.deps import CurrentUser, get_db, staff, viewer
from app.services import provenance as prov
from app.services.rules import verify_chain

router = APIRouter(tags=["audit & provenance"])


def _filters(entity, record_pk, operation, actor, request_id, since, until, before_id) -> tuple[str, dict]:
    conds, params = [], {}
    if entity:
        conds.append("entity = :entity")
        params["entity"] = entity
    if record_pk:
        conds.append("record_pk = :pk")
        params["pk"] = record_pk
    if operation:
        conds.append("operation = :op")
        params["op"] = operation.upper()
    if actor:
        conds.append("LOWER(actor) LIKE :actor")
        params["actor"] = f"%{actor.lower()}%"
    if request_id:
        conds.append("request_id = :req")
        params["req"] = request_id
    if since:
        conds.append("changed_at >= :since")
        params["since"] = since
    if until:
        conds.append("changed_at <= :until")
        params["until"] = until
    if before_id:
        conds.append("audit_id < :before")
        params["before"] = before_id
    return (" WHERE " + " AND ".join(conds)) if conds else "", params


@router.get("/audit", summary="Search the audit log (keyset pagination with before_id)")
def list_audit(
    entity: str | None = None,
    record_pk: str | None = None,
    operation: Literal["INSERT", "UPDATE", "DELETE"] | None = None,
    actor: str | None = None,
    request_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    before_id: int | None = None,
    limit: int = Query(50, ge=1, le=500),
    user: CurrentUser = Depends(viewer),
    db: Db = Depends(get_db),
):
    where, params = _filters(entity, record_pk, operation, actor, request_id, since, until, before_id)
    rows = db.all(f"SELECT {AUDIT_COLS} FROM audit_log{where} ORDER BY audit_id DESC FETCH FIRST :lim ROWS ONLY",
                  {**params, "lim": limit})
    items = [audit_entry(r) for r in rows]
    return {"items": items, "next_before_id": items[-1]["audit_id"] if len(items) == limit else None}


@router.get("/audit/export", summary="Export the audit log as CSV or JSON")
def export_audit(
    format: Literal["csv", "json"] = "csv",
    entity: str | None = None,
    record_pk: str | None = None,
    operation: Literal["INSERT", "UPDATE", "DELETE"] | None = None,
    actor: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    user: CurrentUser = Depends(staff),
    db: Db = Depends(get_db),
):
    where, params = _filters(entity, record_pk, operation, actor, None, since, until, None)
    # Fetch inside the request (the DB session closes before streaming ends); capped at 50k rows.
    rows = [audit_entry(r) for r in db.all(
        f"SELECT {AUDIT_COLS} FROM audit_log{where} ORDER BY chain_seq FETCH FIRST 50000 ROWS ONLY", params)]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if format == "json":
        return StreamingResponse(
            iter([dumps(rows)]), media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.json"'},
        )

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["audit_id", "chain_seq", "changed_at", "entity", "record_pk", "operation", "actor",
                         "db_user", "request_id", "change_request_id", "changes", "row_hash", "prev_hash"])
        for r in rows:
            changes = "; ".join(f"{c['field']}: {c['old']} -> {c['new']}" for c in r["changes"])
            writer.writerow([r["audit_id"], r["chain_seq"], r["changed_at"].isoformat(), r["entity"], r["record_pk"],
                             r["operation"], r["actor"], r["db_user"], r["request_id"], r["change_request_id"],
                             changes, r["row_hash"], r["prev_hash"]])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    return StreamingResponse(generate(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.csv"'})


@router.post("/audit/verify", summary="Verify the tamper-evident hash chain",
             description="Recomputes the SHA-256 hash of every audit record in the database and checks each "
             "record links to the previous one. Any edit, deletion or reordering is detected.")
def verify(user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    result = verify_chain(db)
    if not result["ok"]:
        emit_event(db, user.tenant_id, "audit.integrity_failed", "audit_log", result["first_bad_seq"], result)
        db.commit()
    return {**result, "verified_at": datetime.now(timezone.utc), "algorithm": "SHA-256 hash chain"}


@router.get("/audit/{audit_id}", summary="Get one audit record")
def get_audit(audit_id: int, user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    row = db.one(f"SELECT {AUDIT_COLS} FROM audit_log WHERE audit_id = :id", {"id": audit_id})
    if not row:
        raise not_found("Audit record")
    return audit_entry(row)


# ---- provenance -----------------------------------------------------------------------
@router.get("/provenance/orders/{order_id}/explain", summary="Why-provenance: explain an order's total")
def explain_order(order_id: int, user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    return prov.explain_order(db, order_id)


@router.get("/provenance/orders/{order_id}/lineage", summary="Lineage graph of everything that shaped an order")
def order_lineage(order_id: int, user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    return prov.order_lineage(db, order_id)


@router.get("/provenance/requests/{request_id}", summary="How-provenance: every change one API request caused")
def request_trace(request_id: str, user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    return prov.request_trace(db, request_id)


@router.get("/provenance/{entity}/{record_pk}/history", summary="Where-provenance: full change history of a record")
def record_history(entity: str, record_pk: str, user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    prov.check_entity(entity)
    return {"entity": entity, "record_pk": record_pk, "history": prov.history(db, entity, record_pk)}


@router.get("/provenance/{entity}/{record_pk}/as-of", summary="Time travel: the record as it was at a point in time")
def record_as_of(entity: str, record_pk: str, at: datetime, user: CurrentUser = Depends(viewer),
                 db: Db = Depends(get_db)):
    prov.check_entity(entity)
    return prov.as_of(db, entity, record_pk, at)


@router.get("/provenance/{entity}/{record_pk}/compare", summary="Diff a record between two points in time")
def record_compare(entity: str, record_pk: str, t1: datetime, t2: datetime, user: CurrentUser = Depends(viewer),
                   db: Db = Depends(get_db)):
    prov.check_entity(entity)
    return prov.compare(db, entity, record_pk, t1, t2)


@router.get("/provenance/{entity}/{record_pk}/flashback",
            summary="Oracle Flashback Query: read the live table as it was N minutes ago",
            description="Uses `SELECT ... AS OF TIMESTAMP`. Only works within the database undo retention window; "
            "use /as-of for older history.")
def record_flashback(entity: str, record_pk: str, minutes_ago: float = Query(..., gt=0, le=1440),
                     user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    prov.check_entity(entity)
    return prov.flashback(db, entity, record_pk, minutes_ago)
