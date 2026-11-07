"""Provenance queries: why / where / how a value came to be.

The audit log is one hash chain per tenant, so chain_seq is a total order of every change
in the organization. "State as of" questions use chain_seq where possible, which is exact
even when two changes share a timestamp.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from fastapi import HTTPException, status

from app.common import AUDIT_COLS, audit_entry, diff_values, not_found
from app.db import Db, parse_json

ENTITIES: dict[str, tuple[str, str] | None] = {
    "external_event": None,  # events ingested from upstream systems (record_pk = event_pk)
    "customer": ("customers", "customer_id"),
    "product": ("products", "product_id"),
    "order": ("orders", "order_id"),
    "payment": ("payments", "payment_id"),
    "order_item": None,  # composite key "order_id:product_id"; no flashback
}


def check_entity(entity: str) -> None:
    if entity not in ENTITIES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown entity '{entity}'. Use one of {sorted(ENTITIES)}")


def history(db: Db, entity: str, record_pk: str) -> list[dict[str, Any]]:
    rows = db.all(
        f"SELECT {AUDIT_COLS} FROM audit_log WHERE entity = :e AND record_pk = :pk ORDER BY chain_seq",
        {"e": entity, "pk": record_pk},
    )
    return [audit_entry(r) for r in rows]


def _state_from_row(row: dict | None) -> dict | None:
    if not row or row["operation"] == "DELETE":
        return None
    return parse_json(row["new_values"])


def state_at_time(db: Db, entity: str, record_pk: str, at: datetime) -> tuple[dict | None, dict | None]:
    row = db.one(
        "SELECT audit_id, chain_seq, operation, new_values, changed_at, actor FROM audit_log "
        "WHERE entity = :e AND record_pk = :pk AND changed_at <= :at "
        "ORDER BY chain_seq DESC FETCH FIRST 1 ROWS ONLY",
        {"e": entity, "pk": record_pk, "at": at},
    )
    return _state_from_row(row), row


def state_at_seq(db: Db, entity: str, record_pk: str, seq: int) -> dict | None:
    row = db.one(
        "SELECT operation, new_values FROM audit_log WHERE entity = :e AND record_pk = :pk AND chain_seq <= :s "
        "ORDER BY chain_seq DESC FETCH FIRST 1 ROWS ONLY",
        {"e": entity, "pk": record_pk, "s": seq},
    )
    return _state_from_row(row)


def _items_at_time(db: Db, order_id: str, at: datetime) -> list[dict]:
    rows = db.all(
        """SELECT operation, new_values FROM (
             SELECT operation, new_values,
                    ROW_NUMBER() OVER (PARTITION BY record_pk ORDER BY chain_seq DESC) rn
               FROM audit_log
              WHERE entity = 'order_item' AND record_pk LIKE :pfx AND changed_at <= :at)
           WHERE rn = 1 AND operation <> 'DELETE'""",
        {"pfx": f"{order_id}:%", "at": at},
    )
    return [parse_json(r["new_values"]) for r in rows]


def as_of(db: Db, entity: str, record_pk: str, at: datetime) -> dict[str, Any]:
    state, row = state_at_time(db, entity, record_pk, at)
    result: dict[str, Any] = {
        "entity": entity,
        "record_pk": record_pk,
        "as_of": at,
        "existed": state is not None,
        "state": state,
        "source": "audit_log replay",
        "based_on": None if not row else {
            "audit_id": row["audit_id"], "chain_seq": row["chain_seq"], "operation": row["operation"],
            "changed_at": row["changed_at"], "actor": row["actor"],
        },
    }
    if entity == "order" and state is not None:
        result["items"] = _items_at_time(db, record_pk, at)
    return result


def compare(db: Db, entity: str, record_pk: str, t1: datetime, t2: datetime) -> dict[str, Any]:
    s1, _ = state_at_time(db, entity, record_pk, t1)
    s2, _ = state_at_time(db, entity, record_pk, t2)
    between = db.all(
        f"SELECT {AUDIT_COLS} FROM audit_log WHERE entity = :e AND record_pk = :pk "
        "AND changed_at > :t1 AND changed_at <= :t2 ORDER BY chain_seq",
        {"e": entity, "pk": record_pk, "t1": t1, "t2": t2},
    )
    return {
        "entity": entity, "record_pk": record_pk, "from": t1, "to": t2,
        "state_from": s1, "state_to": s2,
        "changes": diff_values(s1, s2),
        "events_between": [audit_entry(r) for r in between],
    }


def flashback(db: Db, entity: str, record_pk: str, minutes_ago: float) -> dict[str, Any]:
    """Oracle Flashback Query: read the live table as it was N minutes ago (limited by undo retention)."""
    spec = ENTITIES.get(entity)
    if spec is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Flashback is not available for this entity")
    table, pk_col = spec
    undo_seconds = None
    try:
        undo_seconds = db.scalar("SELECT value FROM v$parameter WHERE name = 'undo_retention'")
    except Exception:  # PROV_APP may not see v$parameter; that's fine
        pass
    seconds = max(int(minutes_ago * 60), 1)
    # table/pk_col come from the ENTITIES allowlist above, never from the request.
    # Oracle samples its time -> SCN map every few seconds, so a timestamp within a few
    # seconds of a change can resolve to an SCN on either side of it. Use as_of() for exact
    # answers; flashback reads the physical table state straight from undo.
    row = db.one(
        f"SELECT * FROM {table} AS OF TIMESTAMP "
        f"(CAST(SYSTIMESTAMP AS TIMESTAMP) - NUMTODSINTERVAL(:secs, 'SECOND')) WHERE {pk_col} = :id",
        {"secs": seconds, "id": int(record_pk)},
    )
    if row:
        row.pop("tenant_id", None)
    return {
        "entity": entity, "record_pk": record_pk, "minutes_ago": minutes_ago,
        "existed": row is not None, "state": row, "source": "Oracle Flashback Query (AS OF TIMESTAMP)",
        "undo_retention_seconds": undo_seconds,
    }


def _num(v: Any) -> Decimal:
    return Decimal(str(v)) if v is not None else Decimal(0)


def explain_order(db: Db, order_id: int) -> dict[str, Any]:
    """Why-provenance: exactly which changes, by whom, produced this order's total."""
    order = db.one(
        "SELECT o.order_id, o.status, o.total_amount, o.currency, o.created_at, c.name AS customer_name "
        "FROM orders o JOIN customers c ON c.customer_id = o.customer_id WHERE o.order_id = :id",
        {"id": order_id},
    )
    if not order:
        raise not_found("Order")
    names = {r["product_id"]: r for r in db.all(
        "SELECT p.product_id, p.name, p.sku, p.price FROM products p WHERE p.product_id IN "
        "(SELECT TO_NUMBER(SUBSTR(record_pk, INSTR(record_pk, ':') + 1)) FROM audit_log "
        " WHERE entity = 'order_item' AND record_pk LIKE :pfx)", {"pfx": f"{order_id}:%"})}

    lines = db.all(
        "SELECT i.product_id, p.sku, p.name, i.quantity, i.unit_price, i.line_total, p.price AS current_list_price "
        "FROM order_items i JOIN products p ON p.product_id = i.product_id WHERE i.order_id = :id ORDER BY p.name",
        {"id": order_id},
    )
    events = db.all(
        f"SELECT {AUDIT_COLS} FROM audit_log WHERE entity = 'order_item' AND record_pk LIKE :pfx ORDER BY chain_seq",
        {"pfx": f"{order_id}:%"},
    )

    running = Decimal(0)
    steps = []
    first_insert_seq: dict[int, int] = {}
    for ev in events:
        old, new = parse_json(ev["old_values"]), parse_json(ev["new_values"])
        pid = int(ev["record_pk"].split(":")[1])
        name = names.get(pid, {}).get("name", f"product {pid}")
        delta = _num((new or {}).get("line_total")) - _num((old or {}).get("line_total"))
        running += delta
        if ev["operation"] == "INSERT":
            first_insert_seq.setdefault(pid, int(ev["chain_seq"]))
            text = f"added {new['quantity']} x {name} at {new['unit_price']}"
        elif ev["operation"] == "DELETE":
            text = f"removed {old['quantity']} x {name}"
        else:
            parts = []
            if old["quantity"] != new["quantity"]:
                parts.append(f"quantity {old['quantity']} -> {new['quantity']}")
            if old["unit_price"] != new["unit_price"]:
                parts.append(f"unit price {old['unit_price']} -> {new['unit_price']}")
            text = f"changed {name}: " + ", ".join(parts)
        steps.append({
            "audit_id": ev["audit_id"], "chain_seq": ev["chain_seq"], "changed_at": ev["changed_at"],
            "actor": ev["actor"], "operation": ev["operation"], "product_id": pid, "description": text,
            "delta": delta, "running_total": running,
        })

    # Compare each line's price with the catalogue price at the moment it was added.
    for line in lines:
        pid = int(line["product_id"])
        seq = first_insert_seq.get(pid)
        state = state_at_seq(db, "product", str(pid), seq) if seq else None
        list_then = _num(state.get("price")) if state else None
        line["list_price_at_order_time"] = list_then
        if list_then:
            discount = (list_then - line["unit_price"]) / list_then * 100
            line["discount_pct"] = round(discount, 2)
            line["price_note"] = (
                "matches catalogue price at order time" if line["unit_price"] == list_then
                else f"{abs(round(discount, 1))}% {'below' if discount > 0 else 'above'} catalogue price at order time"
            )

    payments = db.all(
        "SELECT payment_id, amount, method, status, created_at FROM payments WHERE order_id = :id ORDER BY payment_id",
        {"id": order_id},
    )
    lines_sum = sum((l["line_total"] for l in lines), Decimal(0))
    captured = sum((p["amount"] for p in payments if p["status"] == "CAPTURED"), Decimal(0))
    checks = {
        "sum_of_lines": lines_sum,
        "recorded_total": order["total_amount"],
        "total_matches_lines": lines_sum == order["total_amount"],
        "replayed_total_from_audit": running,
        "replay_matches_total": running == order["total_amount"],
        "captured_payments": captured,
        "balance_due": order["total_amount"] - captured,
    }
    summary = (
        f"Order {order_id} total is {order['total_amount']} {order['currency']} because it has "
        f"{len(lines)} line(s) summing to {lines_sum}. Replaying {len(steps)} recorded change(s) "
        f"{'reproduces' if checks['replay_matches_total'] else 'does NOT reproduce'} that total."
    )
    return {"order": order, "summary": summary, "lines": lines, "steps": steps, "payments": payments, "checks": checks}


def order_lineage(db: Db, order_id: int) -> dict[str, Any]:
    """Graph of everything that contributed to an order, plus the causal chain of changes."""
    order = db.one(
        "SELECT o.order_id, o.status, o.total_amount, o.customer_id, c.name AS customer_name "
        "FROM orders o JOIN customers c ON c.customer_id = o.customer_id WHERE o.order_id = :id",
        {"id": order_id},
    )
    if not order:
        raise not_found("Order")
    nodes: list[dict] = []
    edges: list[dict] = []
    oid = f"order:{order_id}"
    nodes.append({"id": oid, "type": "order", "label": f"Order #{order_id}",
                  "detail": f"{order['status']} - {order['total_amount']}"})
    cid = f"customer:{order['customer_id']}"
    nodes.append({"id": cid, "type": "customer", "label": order["customer_name"], "detail": f"customer #{order['customer_id']}"})
    edges.append({"from": oid, "to": cid, "label": "placed by"})

    items = db.all(
        "SELECT i.product_id, i.quantity, i.unit_price, i.line_total, p.name, p.sku, p.price "
        "FROM order_items i JOIN products p ON p.product_id = i.product_id WHERE i.order_id = :id",
        {"id": order_id},
    )
    product_ids = []
    for it in items:
        iid = f"order_item:{order_id}:{it['product_id']}"
        pid = f"product:{it['product_id']}"
        product_ids.append(str(it["product_id"]))
        nodes.append({"id": iid, "type": "order_item", "label": f"{it['quantity']} x {it['name']}",
                      "detail": f"@ {it['unit_price']} = {it['line_total']}"})
        nodes.append({"id": pid, "type": "product", "label": it["name"], "detail": f"{it['sku']} - list {it['price']}"})
        edges.append({"from": iid, "to": oid, "label": "contributes to total"})
        edges.append({"from": iid, "to": pid, "label": "priced from"})

    payments = db.all("SELECT payment_id, amount, method, status FROM payments WHERE order_id = :id", {"id": order_id})
    for p in payments:
        pay = f"payment:{p['payment_id']}"
        nodes.append({"id": pay, "type": "payment", "label": f"{p['method']} {p['amount']}", "detail": p["status"]})
        edges.append({"from": pay, "to": oid, "label": "pays"})

    if product_ids:
        binds = {f"p{i}": v for i, v in enumerate(product_ids)}
        in_list = ", ".join(f":{k}" for k in binds)
        for cr in db.all(
            f"SELECT change_request_id, entity_id, status, requested_by, reviewed_by FROM change_requests "
            f"WHERE entity = 'product' AND entity_id IN ({in_list})", binds,
        ):
            crn = f"change_request:{cr['change_request_id']}"
            nodes.append({"id": crn, "type": "change_request", "label": f"Price change #{cr['change_request_id']}",
                          "detail": f"{cr['status']} - by {cr['requested_by']}"
                                    + (f", reviewed by {cr['reviewed_by']}" if cr["reviewed_by"] else "")})
            edges.append({"from": crn, "to": f"product:{cr['entity_id']}", "label": "changed price of"})

    for a in db.all(
        "SELECT alert_id, rule_code, severity, title FROM alerts WHERE (entity = 'order' AND entity_id = :o) "
        "OR (entity = 'order_item' AND entity_id LIKE :pfx)", {"o": str(order_id), "pfx": f"{order_id}:%"},
    ):
        an = f"alert:{a['alert_id']}"
        nodes.append({"id": an, "type": "alert", "label": f"{a['rule_code']} ({a['severity']})", "detail": a["title"]})
        edges.append({"from": an, "to": oid, "label": "flags"})

    # Causal chain: changes that happened inside the same API request as an item/payment change
    # (e.g. the trigger-driven total recalculation) are linked back to their cause.
    pay_ids = [str(p["payment_id"]) for p in payments]
    pay_binds = {f"y{i}": v for i, v in enumerate(pay_ids)}
    pay_clause = (" OR (entity = 'payment' AND record_pk IN (" + ", ".join(f":{k}" for k in pay_binds) + "))") if pay_ids else ""
    events = [audit_entry(r) for r in db.all(
        f"SELECT {AUDIT_COLS} FROM audit_log WHERE (entity = 'order' AND record_pk = :o) "
        f"OR (entity = 'order_item' AND record_pk LIKE :pfx){pay_clause} ORDER BY chain_seq",
        {"o": str(order_id), "pfx": f"{order_id}:%", **pay_binds},
    )]
    last_cause: dict[str, dict] = {}
    for ev in events:
        req = ev["request_id"]
        ev["caused_by"] = None
        if ev["entity"] in ("order_item", "payment"):
            last_cause[req] = ev
        elif ev["entity"] == "order" and ev["operation"] == "UPDATE" and req in last_cause:
            fields = {c["field"] for c in ev["changes"]}
            if "total_amount" in fields and last_cause[req]["entity"] == "order_item":
                ev["caused_by"] = last_cause[req]["audit_id"]
                ev["explanation"] = "total recalculated by trigger after an item change"
            elif "status" in fields and last_cause[req]["entity"] == "payment":
                ev["caused_by"] = last_cause[req]["audit_id"]
                ev["explanation"] = "status changed because the payment covered the balance"

    return {"order_id": order_id, "nodes": _dedupe(nodes), "edges": edges, "events": events}


def _dedupe(nodes: list[dict]) -> list[dict]:
    seen, out = set(), []
    for n in nodes:
        if n["id"] not in seen:
            seen.add(n["id"])
            out.append(n)
    return out


def request_trace(db: Db, request_id: str) -> dict[str, Any]:
    """How-provenance: everything a single API call changed, including trigger cascades."""
    changes = [audit_entry(r) for r in db.all(
        f"SELECT {AUDIT_COLS} FROM audit_log WHERE request_id = :r ORDER BY chain_seq", {"r": request_id})]
    if not changes:
        raise not_found("Request")
    events = db.all(
        "SELECT event_id, event_type, entity, entity_id, created_at, dispatched_at FROM outbox_events "
        "WHERE request_id = :r ORDER BY event_id", {"r": request_id},
    )
    return {
        "request_id": request_id,
        "actor": changes[0]["actor"],
        "started_at": changes[0]["changed_at"],
        "change_count": len(changes),
        "entities_touched": sorted({f"{c['entity']}:{c['record_pk']}" for c in changes}),
        "changes": changes,
        "events": events,
    }
