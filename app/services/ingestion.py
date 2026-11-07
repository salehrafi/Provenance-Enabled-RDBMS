"""Recording external events: shared by the API-key endpoints and CSV imports.

Every event goes through the Oracle procedure ingest_pkg.record_external, which checks the
source, stores the event (unique per source + id, so retries are safe) and writes it to the
hash-chained audit log.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

import oracledb
from fastapi import HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from app.common import dumps
from app.db import Db, to_db_time

MAX_PAYLOAD_BYTES = 32_000
SUBJECT = re.compile(r"^([a-z][a-z0-9_]{0,29})/(.{1,100})$")
ENTITY_PATTERN = r"^[a-z][a-z0-9_]{0,29}$"


class CloudEventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    specversion: Literal["1.0"]
    id: str = Field(min_length=1, max_length=200, description="Unique per source; used for idempotency")
    source: str = Field(min_length=1, max_length=60, description="Code of a registered source")
    type: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$", max_length=120, examples=["order.updated"])
    subject: str | None = Field(default=None, max_length=200, examples=["order/10045"],
                                description="`<entity>/<external id>`")
    time: datetime = Field(description="When the change happened in the source system")
    datacontenttype: Literal["application/json"] | None = None
    data: dict[str, Any] = Field(description="Debezium-style: {op, before, after} recommended")


EV_COLS = ("e.event_pk, s.code AS source, e.source_event_id AS id, e.event_type AS type, e.subject, e.entity, "
           "e.external_id, e.occurred_at, e.received_at, e.capture_method, e.trust_level, e.request_id")


def existing_event(db: Db, source: str, event_id: str) -> dict | None:
    return db.one(f"SELECT {EV_COLS} FROM external_events e JOIN sources s ON s.source_id = e.source_id "
                  "WHERE s.code = :s AND e.source_event_id = :i", {"s": source, "i": event_id})


def ingest_one(db: Db, body: CloudEventIn) -> tuple[int, dict]:
    """Record one event and return (HTTP status, event). Does not commit.

    A failed call rolls back only its own statement, so batches can continue after an error.
    """
    entity = external_id = None
    if body.subject:
        m = SUBJECT.match(body.subject)
        if not m:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "subject must look like '<entity>/<external id>'")
        entity, external_id = m.groups()
    occurred = to_db_time(body.time)
    payload = dumps({"specversion": body.specversion, "id": body.id, "source": body.source, "type": body.type,
                     "subject": body.subject, "time": occurred.isoformat() + "Z", "data": body.data})
    if len(payload.encode()) > MAX_PAYLOAD_BYTES:
        raise HTTPException(413, f"Event larger than {MAX_PAYLOAD_BYTES} bytes")
    with db.cursor() as cur:
        pk, trust, capture = cur.var(oracledb.DB_TYPE_NUMBER), cur.var(str), cur.var(str)
        try:
            cur.callproc("ingest_pkg.record_external",
                         [body.source, body.id, body.type, body.subject, entity, external_id,
                          occurred.strftime("%Y-%m-%dT%H:%M:%S.%f"), payload, pk, trust, capture])
        except oracledb.IntegrityError:
            existing = existing_event(db, body.source, body.id)
            if not existing:
                raise
            return status.HTTP_200_OK, {**existing, "duplicate": True}
    return status.HTTP_201_CREATED, {**existing_event(db, body.source, body.id), "duplicate": False}
