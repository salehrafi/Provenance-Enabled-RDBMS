"""Error responses in RFC 9457 "Problem Details" format (application/problem+json).

Every error body has `type`, `title`, `status`, `detail`, `instance`, plus two extensions:
`code` (a stable, machine-readable identifier that clients can branch on) and `request_id`.
Validation errors add `errors` (one entry per field).

Business rules live in the database (state machine, item locking, four-eyes check), so database
errors are translated here once instead of every rule being duplicated in Python.
"""

from __future__ import annotations

import logging
from http import HTTPStatus
from typing import Any

import psycopg
from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from psycopg_pool import PoolTimeout
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("app.errors")

# SQLSTATE -> (HTTP status, code, public message or None to use the database's message).
# PVxxx are raised by this application's own triggers; the rest are PostgreSQL's.
SQLSTATE: dict[str, tuple[int, str, str | None]] = {
    "PV001": (409, "ORDER_INVALID_TRANSITION", None),
    "PV002": (409, "ORDER_ITEMS_LOCKED", None),
    "PV003": (422, "ORDER_TOTAL_DERIVED", None),
    "PV010": (422, "SOURCE_UNKNOWN", None),
    "PV011": (409, "SOURCE_PAUSED", None),
    "PV020": (409, "LAST_ADMIN", None),
    "PV030": (409, "CHANGE_REQUEST_DECIDED", None),
    "PV901": (403, "APPEND_ONLY", None),
    "PV040": (403, "BREAK_GLASS_NOT_ACTIVE", None),
    "PV041": (409, "BREAK_GLASS_IMMUTABLE", None),
    "PV042": (409, "BREAK_GLASS_INVALID_TRANSITION", None),
    "PV043": (403, "FOUR_EYES", None),
    "PV044": (409, "BREAK_GLASS_APPROVAL_EXPIRED", None),
    "PV045": (422, "RECOVERY_INVALID", None),
    "PV046": (422, "VALIDATION_ERROR", None),
    "PV050": (409, "LAST_SUPER_ADMIN", None),
    "25006": (403, "READ_ONLY", "This access is read-only"),
    "23505": (409, "CONFLICT", "A record with the same unique value already exists"),
    "23514": (422, "CHECK_VIOLATION", "A value violates a data rule"),
    "23503": (409, "REFERENCE_VIOLATION", "A referenced record does not exist, or this record is still referenced"),
    "23502": (422, "REQUIRED_VALUE_MISSING", "A required value is missing"),
    "22001": (422, "VALUE_TOO_LONG", "A value is longer than allowed"),
    "22003": (422, "NUMBER_OUT_OF_RANGE", "A number is out of range"),
    "22P02": (422, "INVALID_VALUE", "A value has the wrong format"),
    "42501": (403, "FORBIDDEN_BY_DATABASE", "The database refused this operation (privilege or tenant policy)"),
    "40P01": (409, "RETRY", "The operation conflicted with a concurrent one; retry it"),
    "40001": (409, "RETRY", "The operation conflicted with a concurrent one; retry it"),
    "55P03": (409, "RETRY", "The record is locked by another operation; retry shortly"),
    "57014": (504, "TIMEOUT", "The operation took too long and was cancelled"),
}

# Named check constraints get a precise message instead of the generic one.
CONSTRAINTS: dict[str, tuple[int, str, str]] = {
    "ck_cr_four_eyes": (403, "FOUR_EYES", "Four-eyes rule: a change request cannot be reviewed by its requester"),
    "uq_users_email": (409, "EMAIL_TAKEN", "An account with this email already exists"),
    "uq_platform_users_email": (409, "EMAIL_TAKEN", "An operator with this email already exists"),
    "ck_bg_four_eyes": (403, "FOUR_EYES", "Four-eyes rule: a different operator must decide this request"),
    "ck_bg_legal_hold": (422, "VALIDATION_ERROR", "Suppressing customer notification needs a documented reason of at least 40 characters"),
    "fk_bg_tenant": (404, "NOT_FOUND", "Organization not found"),
    "uq_customers_email": (409, "CONFLICT", "A customer with this email already exists"),
    "uq_products_sku": (409, "CONFLICT", "A product with this SKU already exists"),
    "uq_sources_code": (409, "CONFLICT", "A source with this code already exists"),
}


class ApiError(HTTPException):
    """An HTTP error with a stable machine-readable code."""

    def __init__(self, status_code: int, detail: str, code: str, headers: dict[str, str] | None = None,
                 **extra: Any):
        super().__init__(status_code, detail, headers)
        self.code = code
        self.extra = extra


def not_found(what: str) -> ApiError:
    return ApiError(404, f"{what} not found", "NOT_FOUND")


def _default_code(status: int) -> str:
    return {400: "BAD_REQUEST", 401: "UNAUTHENTICATED", 403: "FORBIDDEN", 404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED", 409: "CONFLICT", 413: "PAYLOAD_TOO_LARGE", 415: "UNSUPPORTED_MEDIA_TYPE",
            422: "UNPROCESSABLE", 429: "RATE_LIMITED"}.get(status, "ERROR" if status < 500 else "INTERNAL")


def problem(request: Request, status: int, detail: str, *, code: str | None = None,
            headers: dict[str, str] | None = None, **extra: Any) -> JSONResponse:
    try:
        title = HTTPStatus(status).phrase
    except ValueError:
        title = "Error"
    body: dict[str, Any] = {
        "type": "about:blank", "title": title, "status": status, "detail": detail,
        "instance": request.url.path, "code": code or _default_code(status),
        "request_id": getattr(request.state, "request_id", None),
    }
    body.update(extra)
    return JSONResponse(status_code=status, content=body, headers=headers, media_type="application/problem+json")


def translate_db_error(exc: psycopg.Error) -> tuple[int, str, str]:
    """Map a database error to (status, code, message). Unknown errors become a generic 500."""
    constraint = getattr(exc.diag, "constraint_name", None)
    if constraint in CONSTRAINTS:
        return CONSTRAINTS[constraint]
    state = exc.sqlstate or ""
    if state in SQLSTATE:
        status, code, message = SQLSTATE[state]
        return status, code, message or (exc.diag.message_primary or "Database rule violated")
    return 500, "INTERNAL", "Internal error"


async def db_error_handler(request: Request, exc: psycopg.Error) -> JSONResponse:
    status, code, message = translate_db_error(exc)
    if status >= 500:
        log.error("unhandled database error sqlstate=%s", exc.sqlstate, exc_info=exc)
    headers = {"Retry-After": "1"} if code == "RETRY" else None
    return problem(request, status, message, code=code, headers=headers)


async def pool_timeout_handler(request: Request, exc: PoolTimeout) -> JSONResponse:
    log.error("database pool exhausted")
    return problem(request, 503, "The service is busy; retry shortly", code="UNAVAILABLE",
                   headers={"Retry-After": "2"})


async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return problem(request, exc.status_code, detail, code=getattr(exc, "code", None),
                   headers=getattr(exc, "headers", None), **getattr(exc, "extra", {}))


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [{"field": ".".join(str(p) for p in e.get("loc", [])[1:]) or "body", "message": e.get("msg", "")}
              for e in exc.errors()]
    summary = "; ".join(f"{e['field']}: {e['message']}" for e in errors[:5])
    return problem(request, 422, f"Request validation failed: {summary}", code="VALIDATION_ERROR", errors=errors)


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled error", exc_info=exc)
    return problem(request, 500, "Internal error", code="INTERNAL")
