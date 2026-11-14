"""Security activity log: one append-only row per significant request.

What is recorded (for requests whose organization is known):
  * every change: POST, PUT, PATCH, DELETE, whatever the outcome (success, denied, failed);
  * sign-in events: success, wrong password, deactivated account, sign-up, sign-out, refresh-token reuse;
  * sensitive reads: exports, the activity log itself, API keys, the user list, checkpoints;
  * every other read too when ACTIVITY_LOG_READS=true.

Not recorded: requests that never identify an organization (a sign-in attempt for an email that does not
exist, a malformed token). Those still appear in the structured application log with their IP address.

Writing happens after the response is known, in its own short transaction, so a failed request is
recorded even though its own transaction rolled back. A failure to write is logged loudly but never
turns a successful request into an error.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from starlette.requests import Request

from app.config import get_settings
from app.db import jsonb, session
from app.ratelimit import client_ip

log = logging.getLogger("app.activity")

API_PREFIX = "/api/v1"
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Reads that reveal or take out data in bulk, or touch credentials.
SENSITIVE_READS = ("/api/v1/audit/export", "/api/v1/api-keys", "/api/v1/users", "/api/v1/audit/checkpoints")
# Looking at or exporting the activity log is itself recorded (its helper lookups are not).
ACTIVITY_READS = {"/api/v1/activity", "/api/v1/activity/export", "/api/v1/activity/{activity_id}"}
# Routes whose success is routine and recorded only when something is wrong.
QUIET_ON_SUCCESS = {"/api/v1/auth/refresh"}

ACTION_NAMES = {
    ("POST", "/api/v1/auth/logout-all"): "auth.logout_all",
    ("POST", "/api/v1/auth/password"): "auth.password_changed",
    ("POST", "/api/v1/audit/verify"): "audit.verify",
    ("GET", "/api/v1/audit/export"): "audit.export",
    ("GET", "/api/v1/activity/export"): "activity.export",
    ("GET", "/api/v1/activity"): "activity.view",
}


def outcome(status: int) -> str:
    if status < 400:
        return "SUCCESS"
    if status in (401, 403, 429):
        return "DENIED"
    return "FAILURE"


def route_template(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None) or request.url.path
    if not path.startswith(API_PREFIX) and path.startswith("/"):
        path = API_PREFIX + path  # included routers report their path without the prefix
    return path


def default_action(method: str, route: str) -> str:
    return ACTION_NAMES.get((method, route)) or f"{method} {route.removeprefix(API_PREFIX)}"


def ip_of(request: Request) -> str | None:
    host = client_ip(request)
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def should_record(request: Request, route: str, status: int) -> bool:
    state = request.state
    if getattr(state, "tenant_id", None) is None or not request.url.path.startswith("/api/"):
        return False
    if getattr(state, "activity_action", None):
        return True  # explicitly flagged events (sign-in, token reuse ...) are always recorded
    if route in QUIET_ON_SUCCESS and status < 400:
        return False
    if request.method in WRITE_METHODS:
        return True
    return request.method == "GET" and (route.startswith(SENSITIVE_READS) or route in ACTIVITY_READS
                                        or get_settings().activity_log_reads)


def build_entry(request: Request, status: int, duration_ms: float) -> dict[str, Any]:
    state = request.state
    route = route_template(request)
    details = {k: str(v) for k, v in (request.scope.get("path_params") or {}).items()}
    details.update(getattr(state, "activity_details", None) or {})
    if request.url.query and request.method == "GET":
        details["query"] = request.url.query[:300]
    return {
        "tenant_id": state.tenant_id,
        "actor": (getattr(state, "actor", None) or "unknown")[:254],
        "actor_user_id": getattr(state, "user_id", None),
        "api_key_id": getattr(state, "key_id", None),
        "action": (getattr(state, "activity_action", None) or default_action(request.method, route))[:120],
        "method": request.method,
        "route": route[:300],
        "path": request.url.path[:500],
        "status_code": status,
        "outcome": outcome(status),
        "ip_address": ip_of(request),
        "user_agent": (request.headers.get("user-agent") or "")[:300] or None,
        "request_id": getattr(state, "request_id", None),
        "duration_ms": int(duration_ms),
        "details": details,
    }


def write(entry: dict[str, Any]) -> None:
    try:
        with session(entry["tenant_id"], entry["actor_user_id"], entry["actor"], entry["request_id"]) as db:
            db.execute(
                "INSERT INTO activity_log (actor, actor_user_id, api_key_id, action, method, route, path, status_code, "
                "outcome, ip_address, user_agent, request_id, duration_ms, details) "
                "VALUES (%(actor)s, %(actor_user_id)s, %(api_key_id)s, %(action)s, %(method)s, %(route)s, %(path)s, "
                "%(status_code)s, %(outcome)s, %(ip_address)s::inet, %(user_agent)s, %(request_id)s, %(duration_ms)s, %(d)s)",
                {**entry, "d": jsonb(entry["details"])})
            db.commit()
    except Exception:
        log.exception("could not write activity log entry", extra={"request_id": entry.get("request_id"),
                                                                  "tenant_id": entry.get("tenant_id")})


def record(request: Request, status: int, duration_ms: float) -> None:
    route = route_template(request)
    if should_record(request, route, status):
        write(build_entry(request, status, duration_ms))
