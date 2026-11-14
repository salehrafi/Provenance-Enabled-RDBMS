from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, StreamingResponse

from app.auth import Ctx, require
from app.common import AUDIT_COLS, audit_entry, dumps, emit_event
from app.errors import not_found
from app.schemas import VerifyIn
from app.security import checkpoint_public_key
from app.services import integrity
from app.services import provenance as prov

router = APIRouter(tags=["audit & provenance"])

Op = Literal["INSERT", "UPDATE", "DELETE"]


def _filters(entity, record_pk, operation, actor, request_id, since, until, before_seq) -> tuple[str, dict[str, Any]]:
    conds, params = [], {}
    for col, val, key in (("entity", entity, "entity"), ("record_pk", record_pk, "pk"), ("operation", operation, "op"),
                          ("request_id", request_id, "req")):
        if val:
            conds.append(f"{col} = %({key})s")
            params[key] = val
    if actor:
        conds.append("actor ILIKE %(actor)s")
        params["actor"] = "%" + actor.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    if since:
        conds.append("changed_at >= %(since)s")
        params["since"] = since
    if until:
        conds.append("changed_at <= %(until)s")
        params["until"] = until
    if before_seq:
        conds.append("chain_seq < %(before)s")
        params["before"] = before_seq
    return (" WHERE " + " AND ".join(conds)) if conds else "", params


@router.get("/audit", summary="Search the audit log (keyset pagination)")
def list_audit(
    entity: str | None = None, record_pk: str | None = None, operation: Op | None = None,
    actor: str | None = Query(None, max_length=100), request_id: str | None = None,
    since: datetime | None = None, until: datetime | None = None, before_seq: int | None = None,
    limit: int = Query(50, ge=1, le=500), ctx: Ctx = Depends(require("audit:read")),
):
    where, params = _filters(entity, record_pk, operation, actor, request_id, since, until, before_seq)
    rows = ctx.db.all(f"SELECT {AUDIT_COLS} FROM audit_log{where} ORDER BY chain_seq DESC LIMIT %(lim)s",
                      {**params, "lim": limit})
    items = [audit_entry(r) for r in rows]
    return {"items": items, "next_before_seq": items[-1]["chain_seq"] if len(items) == limit else None}


@router.get("/audit/export", summary="Export audit evidence as CSV or JSON (up to 50,000 records)")
def export_audit(
    format: Literal["csv", "json"] = "csv", entity: str | None = None, record_pk: str | None = None,
    operation: Op | None = None, actor: str | None = None, since: datetime | None = None,
    until: datetime | None = None, ctx: Ctx = Depends(require("audit:export")),
):
    where, params = _filters(entity, record_pk, operation, actor, None, since, until, None)
    rows = [audit_entry(r) for r in ctx.db.all(
        f"SELECT {AUDIT_COLS} FROM audit_log{where} ORDER BY chain_seq LIMIT 50000", params)]
    ctx.db.rollback()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    if format == "json":
        body = dumps({"exported_at": datetime.now(UTC), "tenant_id": ctx.tenant_id, "records": rows})
        return Response(body, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.json"'})

    def safe(v: Any) -> Any:
        # Spreadsheet formula injection: a cell starting with = + - @ is executed by Excel.
        return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

    def generate():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["audit_id", "chain_seq", "changed_at", "entity", "record_pk", "operation", "actor", "db_user",
                    "request_id", "change_request_id", "changes", "prev_hash", "row_hash"])
        for r in rows:
            changes = "; ".join(f"{c['field']}: {c['old']} -> {c['new']}" for c in r["changes"])
            w.writerow([safe(x) for x in (r["audit_id"], r["chain_seq"], r["changed_at"].isoformat(), r["entity"],
                                          r["record_pk"], r["operation"], r["actor"], r["db_user"], r["request_id"],
                                          r["change_request_id"], changes, r["prev_hash"], r["row_hash"])])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    return StreamingResponse(generate(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.csv"'})


@router.post("/audit/verify", summary="Verify the audit chain and its signed checkpoints",
             description="Recomputes the SHA-256 of every record, checks each links to the previous one, and checks "
             "every signed checkpoint. Optionally pass checkpoints you kept outside this system (for example from "
             "`audit.checkpoint` webhooks) in the body: those prove the history was not rewritten wholesale.")
def verify(body: VerifyIn | None = None, ctx: Ctx = Depends(require("audit:verify"))):
    external = [c.model_dump() for c in body.checkpoints] if body else []
    result = integrity.verify_tenant(ctx.db, ctx.tenant_id, external)
    if not result["ok"]:
        emit_event(ctx.db, "audit.integrity_failed", "audit_log", result["first_bad_seq"],
                   {k: result[k] for k in ("first_bad_seq", "reason", "checked")})
        ctx.db.commit()
    else:
        ctx.db.rollback()
    return result


@router.get("/audit/checkpoints", summary="Signed integrity checkpoints (newest first)")
def checkpoints(limit: int = Query(100, ge=1, le=1000), before_seq: int | None = None,
                ctx: Ctx = Depends(require("audit:verify"))):
    return {"items": integrity.list_checkpoints(ctx.db, limit, before_seq), "signing_key": checkpoint_public_key()}


@router.post("/audit/checkpoints", status_code=201, summary="Create a checkpoint now")
def create_checkpoint(ctx: Ctx = Depends(require("audit:verify"))):
    result = integrity.create_checkpoint(ctx.db, ctx.tenant_id)
    return result or {"ok": True, "message": "Nothing new since the last checkpoint"}


@router.get("/audit/{audit_id}", summary="Get one audit record")
def get_audit(audit_id: int, ctx: Ctx = Depends(require("audit:read"))):
    row = ctx.db.one(f"SELECT {AUDIT_COLS} FROM audit_log WHERE audit_id = %s", (audit_id,))
    if not row:
        raise not_found("Audit record")
    return audit_entry(row)


# ---- provenance -----------------------------------------------------------------------
@router.get("/provenance/entities", summary="Entities that have history")
def entities(ctx: Ctx = Depends(require("audit:read"))):
    return {"items": [{"entity": k, "label": v} for k, v in prov.ENTITIES.items()]}


@router.get("/provenance/orders/{order_id}/explain", summary="Why-provenance: explain an order's total")
def explain_order(order_id: int, ctx: Ctx = Depends(require("audit:read"))):
    return prov.explain_order(ctx.db, order_id)


@router.get("/provenance/orders/{order_id}/lineage", summary="Lineage graph of everything that shaped an order")
def order_lineage(order_id: int, ctx: Ctx = Depends(require("audit:read"))):
    return prov.order_lineage(ctx.db, order_id)


@router.get("/provenance/requests/{request_id}", summary="How-provenance: every change one API request caused")
def request_trace(request_id: str, ctx: Ctx = Depends(require("audit:read"))):
    return prov.request_trace(ctx.db, request_id)


@router.get("/provenance/{entity}/{record_pk}/history", summary="Where-provenance: full change history of a record")
def record_history(entity: str, record_pk: str, ctx: Ctx = Depends(require("audit:read"))):
    prov.check_entity(entity)
    return {"entity": entity, "record_pk": record_pk, "history": prov.history(ctx.db, entity, record_pk)}


@router.get("/provenance/{entity}/{record_pk}/as-of", summary="Time travel: the record as it was at a point in time")
def record_as_of(entity: str, record_pk: str, at: datetime, ctx: Ctx = Depends(require("audit:read"))):
    prov.check_entity(entity)
    return prov.as_of(ctx.db, entity, record_pk, at)


@router.get("/provenance/{entity}/{record_pk}/compare", summary="Diff a record between two points in time")
def record_compare(entity: str, record_pk: str, t1: datetime, t2: datetime,
                   ctx: Ctx = Depends(require("audit:read"))):
    prov.check_entity(entity)
    return prov.compare(ctx.db, entity, record_pk, t1, t2)
