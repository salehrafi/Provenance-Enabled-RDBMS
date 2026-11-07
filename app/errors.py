"""Error responses in RFC 9457 "Problem Details" format (application/problem+json).

Every error has `type`, `title`, `status`, `detail` and `instance`. Extensions: `code` (a stable
error code, e.g. ORA-20001 for database business rules) and `errors` (field-level validation).

Business rules live in the database (state machine, item locking, four-eyes check), so the
API surfaces those errors directly instead of duplicating every rule in Python.
"""

from __future__ import annotations

import logging
import re
from http import HTTPStatus
from typing import Any

import oracledb
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("app.errors")

# ORA code -> (HTTP status, public message or None to use the DB message)
_MAP: dict[int, tuple[int, str | None]] = {
    20001: (409, None),  # invalid order status transition
    20002: (409, None),  # order items locked
    20010: (422, None),  # unknown ingestion source
    20011: (409, None),  # ingestion source paused
    20901: (403, None),  # audit log append-only
    1: (409, "A record with the same unique value already exists"),
    2290: (422, "A value violates a data rule (check constraint)"),
    2291: (422, "A referenced record does not exist"),
    2292: (409, "The record is still referenced by other records"),
    1400: (422, "A required value is missing"),
    28115: (403, "Row is outside your tenant (policy check failed)"),
    1555: (422, "Requested time is older than the database undo retention"),
    8180: (422, "No snapshot is available for the requested time"),
    1031: (403, "Database privilege denied"),
}

_ORA_PREFIX = re.compile(r"^ORA-\d+:\s*")


def problem(request: Request, status: int, detail: str, *, code: str | None = None,
            headers: dict | None = None, **extra: Any) -> JSONResponse:
    try:
        title = HTTPStatus(status).phrase
    except ValueError:
        title = "Error"
    body: dict[str, Any] = {"type": "about:blank", "title": title, "status": status, "detail": detail,
                            "instance": request.url.path}
    if code:
        body["code"] = code
    body.update(extra)
    return JSONResponse(status_code=status, content=body, headers=headers, media_type="application/problem+json")


def _db_message(error: Any) -> str:
    first_line = (error.message or "").splitlines()[0] if error.message else ""
    return _ORA_PREFIX.sub("", first_line).strip()


async def oracle_error_handler(request: Request, exc: oracledb.DatabaseError) -> JSONResponse:
    (error,) = exc.args
    code = getattr(error, "code", 0) or 0
    status, message = _MAP.get(code, (500, None))
    if status == 500:
        log.exception("unhandled database error", exc_info=exc)
        message = "Internal database error"
    return problem(request, status, message or _db_message(error), code=f"ORA-{code:05d}")


async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return problem(request, exc.status_code, detail, headers=getattr(exc, "headers", None))


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [{"field": ".".join(str(p) for p in e.get("loc", [])[1:]) or "body", "message": e.get("msg", "")}
              for e in exc.errors()]
    summary = "; ".join(f"{e['field']}: {e['message']}" for e in errors[:5])
    return problem(request, 422, f"Request validation failed: {summary}", code="VALIDATION_ERROR", errors=errors)
