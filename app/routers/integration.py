"""Integration management (human admins): register upstream sources and issue API keys."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

import oracledb
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field

from app.apiauth import SCOPES
from app.common import not_found
from app.db import Db, parse_json
from app.deps import CurrentUser, admin, get_db, staff, viewer
from app.security import hash_api_secret, new_api_key
from app.services.imports import MAX_FILE_BYTES, import_snapshot, parse_snapshot
from app.services.ingestion import ENTITY_PATTERN
from app.services.reconcile import reconcile

router = APIRouter(tags=["integration"])

CaptureMethod = Literal["CDC", "TRIGGER", "API", "CSV_IMPORT", "POLLING", "MANUAL"]
TrustLevel = Literal["HIGH", "MEDIUM", "LOW"]


class SourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    code: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,59}$", description="Used as the CloudEvents `source`")
    name: str = Field(min_length=1, max_length=120)
    capture_method: CaptureMethod
    trust_level: TrustLevel


class SourceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["ACTIVE", "PAUSED"] | None = None
    trust_level: TrustLevel | None = None


class ApiKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=100)
    scopes: list[Literal["events:write", "events:read"]] = Field(min_length=1)


_SRC = ("SELECT source_id, code, name, capture_method, trust_level, status, created_at, last_event_at, "
        "(SELECT COUNT(*) FROM external_events e WHERE e.source_id = s.source_id) AS event_count FROM sources s")


def _source(db: Db, source_id: int) -> dict:
    row = db.one(_SRC + " WHERE source_id = :id", {"id": source_id})
    if not row:
        raise not_found("Source")
    return row


@router.get("/sources", summary="List registered upstream systems")
def list_sources(user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    return db.all(_SRC + " ORDER BY source_id")


@router.post("/sources", status_code=status.HTTP_201_CREATED, summary="Register an upstream system")
def create_source(body: SourceIn, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    try:
        new_id = db.insert(
            "INSERT INTO sources (code, name, capture_method, trust_level) VALUES (:c, :n, :m, :t)",
            {"c": body.code, "n": body.name, "m": body.capture_method, "t": body.trust_level}, "source_id")
    except oracledb.IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Source code '{body.code}' already exists")
    db.commit()
    return _source(db, new_id)


@router.get("/sources/{source_id}", summary="Get a source and its ingestion health")
def get_source(source_id: int, user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    return _source(db, source_id)


@router.patch("/sources/{source_id}", summary="Pause/resume a source or change its trust level")
def update_source(source_id: int, body: SourceUpdate, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    _source(db, source_id)
    fields = body.model_dump(exclude_none=True)
    if fields:
        sets = ", ".join(f"{k} = :{k}" for k in fields)  # keys come from the model
        db.execute(f"UPDATE sources SET {sets} WHERE source_id = :id", {**fields, "id": source_id})
        db.commit()
    return _source(db, source_id)


@router.get("/sources/{source_id}/events", summary="Recent events received from a source")
def source_events(source_id: int, limit: int = Query(50, ge=1, le=500), user: CurrentUser = Depends(viewer),
                  db: Db = Depends(get_db)):
    _source(db, source_id)
    rows = db.all(
        "SELECT event_pk, source_event_id AS id, event_type AS type, subject, occurred_at, received_at, trust_level, "
        "payload FROM external_events WHERE source_id = :s ORDER BY event_pk DESC FETCH FIRST :lim ROWS ONLY",
        {"s": source_id, "lim": limit})
    for r in rows:
        r["payload"] = parse_json(r["payload"])
    return rows


_RECON_SQL = ("SELECT r.recon_id, s.code AS source, r.entity, r.as_of, r.complete, r.total_records, r.matched, "
              "r.mismatched, r.missing, r.unexpected, r.created_by, r.created_at "
              "FROM reconciliations r JOIN sources s ON s.source_id = r.source_id")


@router.get("/reconciliations", summary="Past reconciliation runs")
def list_reconciliations(limit: int = Query(50, ge=1, le=500), user: CurrentUser = Depends(viewer),
                         db: Db = Depends(get_db)):
    return db.all(_RECON_SQL + " ORDER BY r.recon_id DESC FETCH FIRST :lim ROWS ONLY", {"lim": limit})


@router.get("/reconciliations/{recon_id}", summary="A reconciliation run with its discrepancies")
def get_reconciliation(recon_id: int, user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    row = db.one(_RECON_SQL + " WHERE r.recon_id = :id", {"id": recon_id})
    if not row:
        raise not_found("Reconciliation")
    items = db.all("SELECT external_id, outcome, details FROM reconciliation_items WHERE recon_id = :id "
                   "ORDER BY outcome, external_id", {"id": recon_id})
    for i in items:
        i["details"] = parse_json(i["details"])
    return {**row, "issues": items}


def _read_upload(file: UploadFile) -> bytes:
    return file.file.read(MAX_FILE_BYTES + 1)


@router.post("/imports", summary="Import a CSV snapshot: record only what changed",
             description="For systems that can only export files. Multipart form with `file` (CSV with an "
             "`external_id` column), `source`, `entity`, `complete` (absent rows become deletes) and `dry_run` "
             "(preview only). Each change becomes a hash-chained external event attributed to you.")
def import_csv(
    file: UploadFile = File(...),
    source: str = Form(..., max_length=60),
    entity: str = Form(..., pattern=ENTITY_PATTERN),
    complete: bool = Form(False),
    dry_run: bool = Form(False),
    user: CurrentUser = Depends(staff),
    db: Db = Depends(get_db),
):
    rows = parse_snapshot(_read_upload(file))
    return import_snapshot(db, source, entity, rows, complete, dry_run)


@router.post("/reconciliations/upload", status_code=status.HTTP_201_CREATED,
             summary="Reconcile a CSV snapshot against recorded evidence",
             description="Same comparison as POST /reconciliations, from a CSV file (`external_id` column plus the "
             "fields to compare). Nothing is recorded as an event; discrepancies raise an RC001 alert.")
def reconcile_csv(
    file: UploadFile = File(...),
    source: str = Form(..., max_length=60),
    entity: str = Form(..., pattern=ENTITY_PATTERN),
    complete: bool = Form(False),
    as_of: datetime | None = Form(None),
    user: CurrentUser = Depends(staff),
    db: Db = Depends(get_db),
):
    rows = parse_snapshot(_read_upload(file))
    return reconcile(db, user.tenant_id, user.email, source, entity, as_of, complete, rows)


_KEY_COLS = "key_id, name, scopes, created_by, created_at, last_used_at, revoked_at"


@router.get("/api-keys", summary="List API keys (secrets are never returned)")
def list_keys(user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    rows = db.all(f"SELECT {_KEY_COLS} FROM api_keys WHERE tenant_id = :t ORDER BY created_at DESC",
                  {"t": user.tenant_id})
    for r in rows:
        r["scopes"] = r["scopes"].split(",")
    return rows


@router.post("/api-keys", status_code=status.HTTP_201_CREATED,
             summary="Create an API key for a machine client (shown only once)")
def create_key(body: ApiKeyIn, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    key_id, secret, token = new_api_key()
    scopes = sorted(set(body.scopes) & set(SCOPES))
    db.execute(
        "INSERT INTO api_keys (key_id, tenant_id, name, secret_hash, scopes, created_by) VALUES (:k, :t, :n, :h, :s, :u)",
        {"k": key_id, "t": user.tenant_id, "n": body.name, "h": hash_api_secret(secret), "s": ",".join(scopes),
         "u": user.email})
    db.commit()
    return {"key_id": key_id, "name": body.name, "scopes": scopes, "api_key": token,
            "note": "Store this key now. It cannot be shown again."}


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke an API key")
def revoke_key(key_id: str, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    n = db.execute("UPDATE api_keys SET revoked_at = SYS_EXTRACT_UTC(SYSTIMESTAMP) "
                   "WHERE key_id = :k AND tenant_id = :t AND revoked_at IS NULL", {"k": key_id, "t": user.tenant_id})
    if not n:
        raise not_found("Active API key")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
