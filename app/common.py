"""Small helpers shared by routers and services."""

from __future__ import annotations

from typing import Any

from app.db import Db, Row, dumps, json_default, jsonb

__all__ = ["AUDIT_COLS", "audit_entry", "diff_values", "dumps", "emit_event", "json_default", "page", "update_set"]

AUDIT_COLS = (
    "audit_id, chain_seq, entity, record_pk, operation, old_values, new_values, actor, actor_user_id, "
    "request_id, change_request_id, db_user, changed_at, prev_hash, row_hash"
)


def page(rows: list[Row], limit: int, offset: int) -> dict[str, Any]:
    """Offset page. Rows must carry a `count(*) OVER () AS total_count` column."""
    total = int(rows[0]["total_count"]) if rows else 0
    for r in rows:
        r.pop("total_count", None)
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def diff_values(old: dict | None, new: dict | None) -> list[dict[str, Any]]:
    old, new = old or {}, new or {}
    keys = list(dict.fromkeys([*old.keys(), *new.keys()]))
    return [{"field": k, "old": old.get(k), "new": new.get(k)} for k in keys if old.get(k) != new.get(k)]


def audit_entry(row: Row) -> Row:
    return {**row, "changes": diff_values(row.get("old_values"), row.get("new_values"))}


def emit_event(db: Db, event_type: str, entity: str, entity_id: Any, payload: dict) -> None:
    """Write to the transactional outbox; published only if the surrounding transaction commits."""
    db.execute(
        "INSERT INTO outbox_events (event_type, entity, entity_id, payload, request_id) VALUES (%s, %s, %s, %s, %s)",
        (event_type, entity, str(entity_id), jsonb(payload), db.ctx.request_id),
    )


def update_set(fields: dict[str, Any], allowed: dict[str, str]) -> tuple[str, dict[str, Any]]:
    """Build a SET clause from allow-listed fields only. `allowed` maps field name -> column name."""
    parts, params = [], {}
    for key, value in fields.items():
        if key in allowed:
            parts.append(f"{allowed[key]} = %({key})s")
            params[key] = value
    return ", ".join(parts), params
