"""Integration management: register upstream sources, issue API keys, CSV imports, reconciliation history."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Query, Response, UploadFile

from app.auth import API_KEY_SCOPES, Ctx, require, require_user
from app.db import Db
from app.errors import not_found
from app.schemas import ENTITY_PATTERN, ApiKeyIn, SourceIn, SourceUpdate
from app.security import new_api_key, sha256_hex
from app.services import records
from app.services.imports import MAX_FILE_BYTES, import_snapshot, parse_snapshot
from app.services.reconcile import reconcile

router = APIRouter(tags=["integration"])

_SRC = ("SELECT source_id, code, name, capture_method, trust_level, status, created_at, last_event_at, "
        "(SELECT count(*) FROM external_events e WHERE e.source_id = s.source_id) AS event_count FROM sources s")


def _source(db: Db, source_id: int) -> dict[str, Any]:
    row = db.one(_SRC + " WHERE source_id = %s", (source_id,))
    if not row:
        raise not_found("Source")
    return row


@router.get("/sources", summary="List registered upstream systems")
def list_sources(ctx: Ctx = Depends(require("sources:read"))):
    return {"items": ctx.db.all(_SRC + " ORDER BY source_id")}


@router.post("/sources", status_code=201, summary="Register an upstream system")
def create_source(body: SourceIn, ctx: Ctx = Depends(require_user("sources:manage"))):
    new_id = ctx.db.insert(
        "INSERT INTO sources (code, name, capture_method, trust_level) VALUES (%s, %s, %s, %s)",
        (body.code, body.name, body.capture_method, body.trust_level), "source_id")  # duplicate code -> 409
    ctx.db.commit()
    return _source(ctx.db, new_id)


@router.get("/sources/{source_id}", summary="Get a source and its ingestion health")
def get_source(source_id: int, ctx: Ctx = Depends(require("sources:read"))):
    return _source(ctx.db, source_id)


@router.patch("/sources/{source_id}", summary="Pause/resume a source or change its trust level")
def update_source(source_id: int, body: SourceUpdate, ctx: Ctx = Depends(require_user("sources:manage"))):
    _source(ctx.db, source_id)
    fields = body.model_dump(exclude_none=True)
    if fields:
        sets = ", ".join(f"{k} = %({k})s" for k in fields)  # keys come from the model, not the client
        ctx.db.execute(f"UPDATE sources SET {sets} WHERE source_id = %(id)s", {**fields, "id": source_id})
        ctx.db.commit()
    return _source(ctx.db, source_id)


@router.get("/sources/{source_id}/events", summary="Recent events received from a source")
def source_events(source_id: int, limit: int = Query(50, ge=1, le=500), before_pk: int | None = None,
                  ctx: Ctx = Depends(require("sources:read"))):
    _source(ctx.db, source_id)
    rows = ctx.db.all(
        "SELECT event_pk, source_event_id AS id, event_type AS type, subject, occurred_at, received_at, trust_level, "
        "payload FROM external_events WHERE source_id = %s AND (%s::bigint IS NULL OR event_pk < %s) "
        "ORDER BY event_pk DESC LIMIT %s", (source_id, before_pk, before_pk, limit))
    return {"items": rows, "next_before_pk": rows[-1]["event_pk"] if len(rows) == limit else None}


# ---- reconstruction of external records -----------------------------------------------
@router.get("/sources/{source_id}/entities", summary="Entity types seen from a source")
def source_entities(source_id: int, ctx: Ctx = Depends(require("events:read"))):
    src = _source(ctx.db, source_id)
    return {"items": records.list_entities(ctx.db, src["code"])}


@router.get("/sources/{source_id}/records/{entity}", summary="Records of an entity as of a point in time")
def source_records(source_id: int, entity: str, at: datetime | None = None,
                   search: str | None = Query(None, max_length=100), cursor: str | None = None,
                   limit: int = Query(50, ge=1, le=200), ctx: Ctx = Depends(require("events:read"))):
    src = _source(ctx.db, source_id)
    return records.list_records(ctx.db, src["code"], entity, at, search, cursor, limit)


@router.get("/sources/{source_id}/records/{entity}/{external_id}/history", summary="Every version of one external record")
def record_history(source_id: int, entity: str, external_id: str, ctx: Ctx = Depends(require("events:read"))):
    src = _source(ctx.db, source_id)
    return records.history(ctx.db, src["code"], entity, external_id)


@router.get("/sources/{source_id}/records/{entity}/{external_id}/as-of",
            summary="One external record as it was at a time (optionally as we knew it at `known_at`)")
def record_as_of(source_id: int, entity: str, external_id: str, at: datetime, known_at: datetime | None = None,
                 ctx: Ctx = Depends(require("events:read"))):
    src = _source(ctx.db, source_id)
    return records.as_of(ctx.db, src["code"], entity, external_id, at, known_at)


@router.get("/sources/{source_id}/records/{entity}/{external_id}/compare",
            summary="Diff one external record between two times")
def record_compare(source_id: int, entity: str, external_id: str, t1: datetime, t2: datetime,
                   ctx: Ctx = Depends(require("events:read"))):
    src = _source(ctx.db, source_id)
    return records.compare(ctx.db, src["code"], entity, external_id, t1, t2)


# ---- reconciliation history -----------------------------------------------------------
_RECON_SQL = ("SELECT r.recon_id, s.code AS source, r.entity, r.as_of, r.complete, r.total_records, r.matched, "
              "r.mismatched, r.missing, r.unexpected, r.created_by, r.created_at "
              "FROM reconciliations r JOIN sources s ON s.source_id = r.source_id")


@router.get("/reconciliations", summary="Past reconciliation runs")
def list_reconciliations(limit: int = Query(50, ge=1, le=500), ctx: Ctx = Depends(require("sources:read"))):
    return {"items": ctx.db.all(_RECON_SQL + " ORDER BY r.recon_id DESC LIMIT %s", (limit,))}


@router.get("/reconciliations/{recon_id}", summary="A reconciliation run with its discrepancies")
def get_reconciliation(recon_id: int, ctx: Ctx = Depends(require("sources:read"))):
    row = ctx.db.one(_RECON_SQL + " WHERE r.recon_id = %s", (recon_id,))
    if not row:
        raise not_found("Reconciliation")
    items = ctx.db.all("SELECT external_id, outcome, details FROM reconciliation_items WHERE recon_id = %s "
                       "ORDER BY outcome, external_id LIMIT 1000", (recon_id,))
    return {**row, "issues": items}


def _read_upload(file: UploadFile) -> bytes:
    return file.file.read(MAX_FILE_BYTES + 1)


@router.post("/imports", summary="Import a CSV snapshot: record only what changed",
             description="For systems that can only export files. Multipart form: `file` (CSV with an `external_id` "
             "column), `source`, `entity`, `complete` (absent rows become deletes), `dry_run` (preview only).")
def import_csv(file: UploadFile = File(...), source: str = Form(..., max_length=60),
               entity: str = Form(..., pattern=ENTITY_PATTERN), complete: bool = Form(False),
               dry_run: bool = Form(False), ctx: Ctx = Depends(require_user("imports:write"))):
    return import_snapshot(ctx.db, source, entity, parse_snapshot(_read_upload(file)), complete, dry_run)


@router.post("/reconciliations/upload", status_code=201, summary="Reconcile a CSV snapshot against recorded evidence")
def reconcile_csv(file: UploadFile = File(...), source: str = Form(..., max_length=60),
                  entity: str = Form(..., pattern=ENTITY_PATTERN), complete: bool = Form(False),
                  as_of: datetime | None = Form(None), ctx: Ctx = Depends(require_user("imports:write"))):
    return reconcile(ctx.db, ctx.tenant_id, ctx.actor, source, entity, as_of, complete,
                     parse_snapshot(_read_upload(file)))


# ---- API keys -------------------------------------------------------------------------
_KEY_COLS = "key_id, name, scopes, created_by, created_at, last_used_at, expires_at, revoked_at"


@router.get("/api-keys", summary="List API keys (secrets are never returned)")
def list_keys(ctx: Ctx = Depends(require("apikeys:manage"))):
    return {"items": ctx.db.all(f"SELECT {_KEY_COLS} FROM api_keys ORDER BY created_at DESC"),
            "scopes": API_KEY_SCOPES}


@router.post("/api-keys", status_code=201, summary="Create an API key for a machine client (shown once)")
def create_key(body: ApiKeyIn, ctx: Ctx = Depends(require_user("apikeys:manage"))):
    key_id, secret, token = new_api_key()
    scopes = sorted(set(body.scopes))
    expires = datetime.now(UTC) + timedelta(days=body.expires_in_days) if body.expires_in_days else None
    ctx.db.execute(
        "INSERT INTO api_keys (key_id, name, secret_hash, scopes, created_by, expires_at) VALUES (%s, %s, %s, %s, %s, %s)",
        (key_id, body.name, sha256_hex(secret), scopes, ctx.actor, expires))
    ctx.db.commit()
    return {"key_id": key_id, "name": body.name, "scopes": scopes, "expires_at": expires, "api_key": token,
            "note": "Store this key now. It cannot be shown again."}


@router.delete("/api-keys/{key_id}", status_code=204, summary="Revoke an API key")
def revoke_key(key_id: str, ctx: Ctx = Depends(require_user("apikeys:manage"))):
    if not ctx.db.execute("UPDATE api_keys SET revoked_at = now() WHERE key_id = %s AND revoked_at IS NULL", (key_id,)):
        raise not_found("Active API key")
    ctx.db.commit()
    return Response(status_code=204)
