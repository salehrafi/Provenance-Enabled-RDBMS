"""Idempotency-Key support for unsafe requests.

A client that is unsure whether a POST succeeded (timeout, dropped connection) repeats it with
the same `Idempotency-Key` header and gets the original response instead of a second order or a
second payment.

The key row is inserted in the SAME transaction as the work. PostgreSQL's unique index does the
coordination: a concurrent duplicate blocks on the insert until the first request commits, then
sees the conflict, discards its own work and replays the stored response.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from typing import Any

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from app.auth import Ctx
from app.db import dumps, jsonb
from app.errors import ApiError

_KEY = re.compile(r"^[\x21-\x7e]{8,200}$")


def _replay(row: dict[str, Any]) -> JSONResponse:
    return JSONResponse(jsonable_encoder(row["response"]), status_code=row["status_code"], headers={"Idempotent-Replayed": "true"})


def run(ctx: Ctx, request: Request, body: Any, status_code: int, work: Callable[[], Any]) -> Any:
    """Run `work()` and commit, at most once per Idempotency-Key. `work` must not commit."""
    db = ctx.db
    key = request.headers.get("idempotency-key")
    if key is None:
        result = work()
        db.commit()
        return result
    if not _KEY.match(key):
        raise ApiError(422, "Idempotency-Key must be 8-200 printable ASCII characters", "VALIDATION_ERROR")

    endpoint = f"{request.method} {request.url.path}"
    request_hash = hashlib.sha256(f"{endpoint}\n{dumps(jsonable_encoder(body))}".encode()).hexdigest()

    def stored() -> dict[str, Any] | None:
        row = db.one("SELECT endpoint, request_hash, status_code, response FROM idempotency_keys WHERE idem_key = %s",
                     (key,))
        if row and (row["endpoint"] != endpoint or row["request_hash"] != request_hash):
            raise ApiError(422, "This Idempotency-Key was already used with a different request",
                           "IDEMPOTENCY_KEY_REUSED")
        return row

    if (row := stored()) is not None:
        db.rollback()
        return _replay(row)

    result = jsonable_encoder(work())
    inserted = db.execute(
        "INSERT INTO idempotency_keys (idem_key, endpoint, request_hash, status_code, response) "
        "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (tenant_id, idem_key) DO NOTHING",
        (key, endpoint, request_hash, status_code, jsonb(result)))
    if not inserted:
        # Someone else finished the same request first. Undo ours and return theirs.
        db.rollback()
        row = stored()
        assert row is not None
        return _replay(row)
    db.commit()
    return JSONResponse(result, status_code=status_code)
