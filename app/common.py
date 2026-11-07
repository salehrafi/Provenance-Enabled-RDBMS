from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from fastapi import HTTPException, status

from app.db import Db, parse_json

AUDIT_COLS = (
    "audit_id, chain_seq, entity, record_pk, operation, old_values, new_values, actor, actor_user_id, "
    "request_id, change_request_id, db_user, changed_at, prev_hash, row_hash"
)


def not_found(what: str) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f"{what} not found")


def paginate(rows: list[dict[str, Any]], limit: int, offset: int) -> dict[str, Any]:
    """Rows must include a COUNT(*) OVER () AS total_count column."""
    total = int(rows[0]["total_count"]) if rows else 0
    for r in rows:
        r.pop("total_count", None)
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def json_default(o: Any) -> Any:
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    raise TypeError(f"not JSON serialisable: {type(o)}")


def dumps(value: Any) -> str:
    return json.dumps(value, default=json_default, separators=(",", ":"))


def diff_values(old: dict | None, new: dict | None) -> list[dict[str, Any]]:
    old, new = old or {}, new or {}
    keys = list(dict.fromkeys([*old.keys(), *new.keys()]))
    return [{"field": k, "old": old.get(k), "new": new.get(k)} for k in keys if old.get(k) != new.get(k)]


def audit_entry(row: dict[str, Any]) -> dict[str, Any]:
    old = parse_json(row.pop("old_values", None))
    new = parse_json(row.pop("new_values", None))
    return {**row, "old_values": old, "new_values": new, "changes": diff_values(old, new)}


def emit_event(db: Db, tenant_id: int, event_type: str, entity: str, entity_id: Any, payload: dict) -> None:
    """Write to the transactional outbox; published only if the surrounding transaction commits."""
    db.callproc("outbox_pkg.emit", [tenant_id, event_type, entity, str(entity_id), dumps(payload)])


def update_set(fields: dict[str, Any], allowed: dict[str, str]) -> tuple[str, dict[str, Any]]:
    """Build a safe SET clause from whitelisted fields. allowed maps field -> column."""
    parts, params = [], {}
    for key, value in fields.items():
        if key in allowed:
            parts.append(f"{allowed[key]} = :{key}")
            params[key] = value
    return ", ".join(parts), params
