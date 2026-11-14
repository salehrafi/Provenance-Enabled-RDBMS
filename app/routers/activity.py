"""Security activity log: admin-only, read-only, filterable, exportable."""

from __future__ import annotations

import csv
import io
import ipaddress
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, StreamingResponse

from app.auth import Ctx, require_user
from app.db import dumps
from app.errors import ApiError, not_found

router = APIRouter(prefix="/activity", tags=["activity log"])

COLS = ("activity_id, occurred_at, actor, actor_user_id, api_key_id, action, method, route, path, status_code, "
        "outcome, host(ip_address) AS ip_address, user_agent, request_id, duration_ms, details")
Outcome = Literal["SUCCESS", "DENIED", "FAILURE"]
Method = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]


def _like(term: str) -> str:
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _filters(actor: str | None, action: str | None, ip: str | None, outcome: str | None, method: str | None,
             status_code: int | None, request_id: str | None, since: datetime | None, until: datetime | None,
             before_id: int | None) -> tuple[str, dict[str, Any]]:
    conds: list[str] = []
    params: dict[str, Any] = {}
    if actor:
        conds.append("actor ILIKE %(actor)s")
        params["actor"] = _like(actor)
    if action:
        conds.append("action ILIKE %(action)s")
        params["action"] = _like(action)
    if ip:
        try:
            # A single address matches exactly; a CIDR block (203.0.113.0/24) matches every address inside it.
            net = ipaddress.ip_network(ip.strip(), strict=False)
        except ValueError:
            raise ApiError(422, "ip must be an IP address or a CIDR block such as 203.0.113.0/24",
                           "VALIDATION_ERROR") from None
        conds.append("ip_address <<= %(ip)s::inet")
        params["ip"] = str(net)
    for col, val in (("outcome", outcome), ("method", method), ("status_code", status_code), ("request_id", request_id)):
        if val:
            conds.append(f"{col} = %({col})s")
            params[col] = val
    if since:
        conds.append("occurred_at >= %(since)s")
        params["since"] = since
    if until:
        conds.append("occurred_at <= %(until)s")
        params["until"] = until
    if before_id:
        conds.append("activity_id < %(before)s")
        params["before"] = before_id
    return (" WHERE " + " AND ".join(conds)) if conds else "", params


def _filter_args(
    actor: str | None = Query(None, max_length=254, description="Substring of the email or API-key name"),
    action: str | None = Query(None, max_length=120, description="Substring, e.g. login_failed or /orders"),
    ip: str | None = Query(None, max_length=50, description="Exact address or CIDR block"),
    outcome: Outcome | None = None,
    method: Method | None = None,
    status_code: int | None = Query(None, ge=100, le=599),
    request_id: str | None = Query(None, max_length=64),
    since: datetime | None = None,
    until: datetime | None = None,
) -> dict[str, Any]:
    return {"actor": actor, "action": action, "ip": ip, "outcome": outcome, "method": method,
            "status_code": status_code, "request_id": request_id, "since": since, "until": until}


@router.get("", summary="Search the activity log (admins only; keyset pagination with before_id)")
def list_activity(f: dict = Depends(_filter_args), before_id: int | None = None,
                  limit: int = Query(50, ge=1, le=500), ctx: Ctx = Depends(require_user("activity:read"))):
    where, params = _filters(**f, before_id=before_id)
    rows = ctx.db.all(f"SELECT {COLS} FROM activity_log{where} ORDER BY activity_id DESC LIMIT %(lim)s",
                      {**params, "lim": limit})
    return {"items": rows, "next_before_id": rows[-1]["activity_id"] if len(rows) == limit else None}


@router.get("/summary", summary="Counts for the activity dashboard (last 24 hours)")
def summary(ctx: Ctx = Depends(require_user("activity:read"))):
    return ctx.db.one(
        """SELECT count(*) AS total,
                  count(*) FILTER (WHERE action = 'auth.login') AS logins,
                  count(*) FILTER (WHERE action IN ('auth.login_failed', 'auth.login_blocked')) AS failed_logins,
                  count(*) FILTER (WHERE outcome = 'DENIED') AS denied,
                  count(DISTINCT ip_address) AS distinct_ips
             FROM activity_log WHERE occurred_at >= now() - interval '24 hours'""")


@router.get("/actions", summary="Distinct actions recorded (for filter pickers)")
def actions(ctx: Ctx = Depends(require_user("activity:read"))):
    return {"items": [r["action"] for r in ctx.db.all(
        "SELECT action FROM activity_log GROUP BY action ORDER BY count(*) DESC LIMIT 200")]}


@router.get("/export", summary="Export the activity log as CSV or JSON (filters apply; up to 100,000 rows)")
def export(f: dict = Depends(_filter_args), format: Literal["csv", "json"] = "csv",
           ctx: Ctx = Depends(require_user("activity:read"))):
    where, params = _filters(**f, before_id=None)
    rows = ctx.db.all(f"SELECT {COLS} FROM activity_log{where} ORDER BY activity_id LIMIT 100000", params)
    ctx.db.rollback()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    if format == "json":
        body = dumps({"exported_at": datetime.now(UTC), "tenant_id": ctx.tenant_id, "filters": f, "records": rows})
        return Response(body, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="activity-{stamp}.json"'})

    def safe(v: Any) -> Any:
        # Spreadsheet formula injection: an attacker controls user agents and attempted emails.
        return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

    header = ["activity_id", "occurred_at", "actor", "actor_user_id", "api_key_id", "action", "method", "route", "path",
              "status_code", "outcome", "ip_address", "user_agent", "request_id", "duration_ms", "details"]

    def generate():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(header)
        for r in rows:
            w.writerow([safe(x) for x in (r["activity_id"], r["occurred_at"].isoformat(), r["actor"], r["actor_user_id"],
                                          r["api_key_id"], r["action"], r["method"], r["route"], r["path"],
                                          r["status_code"], r["outcome"], r["ip_address"], r["user_agent"],
                                          r["request_id"], r["duration_ms"], dumps(r["details"]))])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    return StreamingResponse(generate(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="activity-{stamp}.csv"'})


@router.get("/{activity_id}", summary="One activity record")
def get_one(activity_id: int, ctx: Ctx = Depends(require_user("activity:read"))):
    row = ctx.db.one(f"SELECT {COLS} FROM activity_log WHERE activity_id = %s", (activity_id,))
    if not row:
        raise not_found("Activity record")
    return row
