"""Event ingestion and reconciliation for upstream systems (authenticated with API keys).

The body is a CloudEvents 1.0 structured-mode event (or an array of them for the batch
endpoint). `id` + `source` identify an event, so re-sending it is safe: the first call returns
201, repeats return 200 with `duplicate: true` and the original event. Trust level and capture
method come from the registered source, not from the sender.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterator

import oracledb
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.apiauth import ApiPrincipal, api_db, require_scope
from app.db import Db, parse_json
from app.errors import _MAP, _db_message
from app.services.ingestion import ENTITY_PATTERN, EV_COLS, CloudEventIn, ingest_one
from app.services.reconcile import reconcile

router = APIRouter(tags=["ingestion"])

MAX_BATCH = 500


class ReconRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    external_id: str = Field(min_length=1, max_length=100)
    fields: dict[str, Any] = Field(default_factory=dict, description="Fields to compare, e.g. {status, total}")


class ReconIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(min_length=1, max_length=60)
    entity: str = Field(pattern=ENTITY_PATTERN)
    as_of: datetime | None = Field(default=None, description="Compare against evidence up to this time (default now)")
    complete: bool = Field(default=False, description="True if `records` is the full set; enables UNEXPECTED detection")
    records: list[ReconRecord] = Field(max_length=5000)


def _writer(request: Request, p: ApiPrincipal = Depends(require_scope("events:write"))) -> Iterator[tuple[ApiPrincipal, Db]]:
    for db in api_db(request, p):
        yield p, db


def _reader(request: Request, p: ApiPrincipal = Depends(require_scope("events:read"))) -> Iterator[tuple[ApiPrincipal, Db]]:
    for db in api_db(request, p):
        yield p, db


@router.post("/events", status_code=status.HTTP_201_CREATED,
             summary="Ingest one CloudEvent from an upstream system",
             description="Requires an API key with `events:write`. Idempotent on (`source`, `id`).")
def ingest_event(body: CloudEventIn, response: Response, ctx: tuple[ApiPrincipal, Db] = Depends(_writer)):
    _, db = ctx
    code, result = ingest_one(db, body)
    db.commit()
    response.status_code = code
    return result


@router.post("/events:batch", summary="Ingest up to 500 CloudEvents in one call",
             description="Body is a JSON array (CloudEvents batched mode). Each event succeeds or fails on its own; "
             "the response lists the outcome per index: `created`, `duplicate`, `invalid` or `rejected`.")
def ingest_batch(events: list[Any] = Body(...), ctx: tuple[ApiPrincipal, Db] = Depends(_writer)):
    _, db = ctx
    if not events:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Batch is empty")
    if len(events) > MAX_BATCH:
        raise HTTPException(413, f"At most {MAX_BATCH} events per batch")
    results = []
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
            code, res = ingest_one(db, ev)
            entry.update(status="created" if code == 201 else "duplicate", event_pk=res["event_pk"])
        except HTTPException as exc:
            entry.update(status="rejected", error=exc.detail)
        except oracledb.DatabaseError as exc:
            err = exc.args[0]
            if getattr(err, "code", 0) not in _MAP:
                raise
            entry.update(status="rejected", error=_db_message(err), code=f"ORA-{err.code:05d}")
        results.append(entry)
    db.commit()
    count = lambda s: sum(1 for r in results if r["status"] == s)  # noqa: E731
    return {"created": count("created"), "duplicates": count("duplicate"),
            "failed": count("invalid") + count("rejected"), "results": results}


@router.get("/ingested-events", summary="List ingested events (cursor pagination)",
            description="Requires `events:read`. Pass `next_cursor` from the previous page as `cursor`.")
def list_ingested(
    source: str | None = None,
    type: str | None = None,
    subject: str | None = None,
    cursor: int | None = None,
    limit: int = Query(50, ge=1, le=500),
    ctx: tuple[ApiPrincipal, Db] = Depends(_reader),
):
    _, db = ctx
    conds, params = [], {"lim": limit}
    for col, val, key in (("s.code", source, "s"), ("e.event_type", type, "t"), ("e.subject", subject, "sub")):
        if val:
            conds.append(f"{col} = :{key}")
            params[key] = val
    if cursor:
        conds.append("e.event_pk < :cur")
        params["cur"] = cursor
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    rows = db.all(f"SELECT {EV_COLS}, e.payload FROM external_events e JOIN sources s ON s.source_id = e.source_id"
                  f"{where} ORDER BY e.event_pk DESC FETCH FIRST :lim ROWS ONLY", params)
    for r in rows:
        r["payload"] = parse_json(r["payload"])
    return {"items": rows, "next_cursor": rows[-1]["event_pk"] if len(rows) == limit else None}


@router.post("/reconciliations", status_code=status.HTTP_201_CREATED,
             summary="Reconcile an upstream snapshot against recorded evidence",
             description="Requires `events:write`. Send the upstream system's current records for one entity; the "
             "response lists every MISMATCH, MISSING and (with `complete: true`) UNEXPECTED record. Discrepancies "
             "raise an RC001 alert. People can do the same with a CSV file: `POST /reconciliations/upload`.")
def create_reconciliation(body: ReconIn, ctx: tuple[ApiPrincipal, Db] = Depends(_writer)):
    principal, db = ctx
    return reconcile(db, principal.tenant_id, principal.actor, body.source, body.entity, body.as_of, body.complete,
                     [r.model_dump() for r in body.records])
