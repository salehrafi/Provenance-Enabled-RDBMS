"""Event ingestion and record reconstruction for upstream systems (API keys or signed-in users).

The body is a CloudEvents 1.0 structured-mode event (or an array of them for the batch endpoint).
`source` + `id` identify an event, so re-sending is safe: the first call returns 201, repeats
return 200 with `duplicate: true`. Trust level and capture method come from the registered
source, never from the sender.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import psycopg
from fastapi import APIRouter, Body, Depends, Query, Response
from pydantic import ValidationError

from app.auth import Ctx, require
from app.db import Db
from app.errors import ApiError, translate_db_error
from app.schemas import CloudEventIn, ReconIn
from app.services.ingestion import EV_COLS, ingest_one
from app.services.reconcile import reconcile

router = APIRouter(tags=["ingestion"])

MAX_BATCH = 500


@router.post("/events", status_code=201, summary="Ingest one CloudEvent from an upstream system",
             description="Requires `events:write`. Idempotent on (`source`, `id`): a repeat returns 200 with "
             "`duplicate: true`.")
def ingest_event(body: CloudEventIn, response: Response, ctx: Ctx = Depends(require("events:write"))):
    code, result = ingest_one(ctx.db, body)
    ctx.db.commit()
    response.status_code = code
    return result


@router.post("/events:batch", summary="Ingest up to 500 CloudEvents in one call",
             description="Body is a JSON array. Each event succeeds or fails on its own; the response lists the "
             "outcome per index: `created`, `duplicate`, `invalid` or `rejected`.")
def ingest_batch(events: list[Any] = Body(...), ctx: Ctx = Depends(require("events:write"))):
    db: Db = ctx.db
    if not events:
        raise ApiError(422, "Batch is empty", "VALIDATION_ERROR")
    if len(events) > MAX_BATCH:
        raise ApiError(413, f"At most {MAX_BATCH} events per batch", "PAYLOAD_TOO_LARGE")
    results: list[dict[str, Any]] = []
    cache: dict[str, dict[str, Any]] = {}
    for i, raw in enumerate(events):
        entry: dict[str, Any] = {"index": i, "id": raw.get("id") if isinstance(raw, dict) else None}
        try:
            ev = CloudEventIn.model_validate(raw)
        except ValidationError as exc:
            entry.update(status="invalid", error="; ".join(
                f"{'.'.join(str(p) for p in e['loc']) or 'event'}: {e['msg']}" for e in exc.errors()[:3]))
            results.append(entry)
            continue
        try:
            # A savepoint per event: a rejected event must not abort the others.
            with db.savepoint():
                code, res = ingest_one(db, ev, cache)
            entry.update(status="created" if code == 201 else "duplicate", event_pk=res["event_pk"])
        except ApiError as exc:
            entry.update(status="rejected", error=exc.detail, code=exc.code)
        except psycopg.Error as exc:
            http_status, err_code, message = translate_db_error(exc)
            if http_status >= 500:
                raise
            entry.update(status="rejected", error=message, code=err_code)
        results.append(entry)
    db.commit()

    def count(s: str) -> int:
        return sum(1 for r in results if r["status"] == s)

    return {"created": count("created"), "duplicates": count("duplicate"),
            "failed": count("invalid") + count("rejected"), "results": results}


@router.get("/ingested-events", summary="List ingested events (cursor pagination)",
            description="Requires `events:read`. Pass `next_cursor` from the previous page as `cursor`.")
def list_ingested(source: str | None = None, type: str | None = None, subject: str | None = None,
                  since: datetime | None = None, cursor: int | None = None,
                  limit: int = Query(50, ge=1, le=500), ctx: Ctx = Depends(require("events:read"))):
    conds: list[str] = []
    params: dict[str, Any] = {"lim": limit}
    for col, val, key in (("s.code", source, "s"), ("e.event_type", type, "t"), ("e.subject", subject, "sub")):
        if val:
            conds.append(f"{col} = %({key})s")
            params[key] = val
    if since:
        conds.append("e.received_at >= %(since)s")
        params["since"] = since
    if cursor:
        conds.append("e.event_pk < %(cur)s")
        params["cur"] = cursor
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    rows = ctx.db.all(f"SELECT {EV_COLS}, e.payload FROM external_events e JOIN sources s ON s.source_id = e.source_id"
                      f"{where} ORDER BY e.event_pk DESC LIMIT %(lim)s", params)
    return {"items": rows, "next_cursor": rows[-1]["event_pk"] if len(rows) == limit else None}


@router.post("/reconciliations", status_code=201, summary="Reconcile an upstream snapshot against recorded evidence",
             description="Requires `events:write`. Send the upstream system's current records for one entity; the "
             "response lists every MISMATCH, MISSING and (with `complete: true`) UNEXPECTED record. Discrepancies "
             "raise an RC001 alert. People can do the same with a CSV file: `POST /reconciliations/upload`.")
def create_reconciliation(body: ReconIn, ctx: Ctx = Depends(require("events:write"))):
    return reconcile(ctx.db, ctx.tenant_id, ctx.actor, body.source, body.entity, body.as_of, body.complete,
                     [r.model_dump() for r in body.records])
