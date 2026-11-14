"""Provenance queries: why / where / how a value came to be, and what a record looked like before.

The audit log is one hash chain per tenant. `chain_seq` is commit order and `changed_at` is
assigned under the same lock, so both give the same total order of every change in the
organization. Historical state is reconstructed by replaying that log; it does not depend on
any database retention window.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from app.common import AUDIT_COLS, audit_entry, diff_values
from app.db import Db, utc
from app.errors import ApiError, not_found

# entity name -> human label. These are the values audit triggers write to audit_log.entity.
ENTITIES: dict[str, str] = {
    "customer": "Customer",
    "product": "Product",
    "order": "Order",
    "order_item": "Order line (key: order_id:product_id)",
    "payment": "Payment",
    "external_event": "Ingested event",
    "change_request": "Change request",
    "user": "User",
    "api_key": "API key",
    "webhook": "Webhook",
    "source": "Source",
    "settings": "Organization settings",
    "organization": "Organization",
}


def check_entity(entity: str) -> None:
    if entity not in ENTITIES:
        raise ApiError(404, f"Unknown entity '{entity}'. Use one of {sorted(ENTITIES)}", "UNKNOWN_ENTITY")


def history(db: Db, entity: str, record_pk: str) -> list[dict[str, Any]]:
    rows = db.all(f"SELECT {AUDIT_COLS} FROM audit_log WHERE entity = %s AND record_pk = %s ORDER BY chain_seq",
                  (entity, record_pk))
    return [audit_entry(r) for r in rows]


def _state_from_row(row: dict | None) -> dict | None:
    if not row or row["operation"] == "DELETE":
        return None
    return row["new_values"]


def state_at_time(db: Db, entity: str, record_pk: str, at: datetime) -> tuple[dict | None, dict | None]:
    row = db.one(
        "SELECT audit_id, chain_seq, operation, new_values, changed_at, actor, row_hash FROM audit_log "
        "WHERE entity = %s AND record_pk = %s AND changed_at <= %s ORDER BY chain_seq DESC LIMIT 1",
        (entity, record_pk, utc(at)))
    return _state_from_row(row), row


def state_at_seq(db: Db, entity: str, record_pk: str, seq: int) -> dict | None:
    row = db.one(
        "SELECT operation, new_values FROM audit_log WHERE entity = %s AND record_pk = %s AND chain_seq <= %s "
        "ORDER BY chain_seq DESC LIMIT 1", (entity, record_pk, seq))
    return _state_from_row(row)


def _children_at_time(db: Db, entity: str, prefix: str, at: datetime) -> list[dict]:
    """Latest surviving version of every record whose key starts with `prefix` (order lines)."""
    rows = db.all(
        """SELECT DISTINCT ON (record_pk) operation, new_values
             FROM audit_log
            WHERE entity = %s AND record_pk LIKE %s AND changed_at <= %s
            ORDER BY record_pk, chain_seq DESC""",
        (entity, prefix + "%", utc(at)))
    return [r["new_values"] for r in rows if r["operation"] != "DELETE"]


def _payments_at_time(db: Db, order_id: str, at: datetime) -> list[dict]:
    rows = db.all(
        """SELECT DISTINCT ON (record_pk) operation, new_values
             FROM audit_log
            WHERE entity = 'payment' AND changed_at <= %s
              AND COALESCE(new_values, old_values) ->> 'order_id' = %s
            ORDER BY record_pk, chain_seq DESC""",
        (utc(at), order_id))
    return [r["new_values"] for r in rows if r["operation"] != "DELETE"]


def as_of(db: Db, entity: str, record_pk: str, at: datetime) -> dict[str, Any]:
    state, row = state_at_time(db, entity, record_pk, at)
    result: dict[str, Any] = {
        "entity": entity, "record_pk": record_pk, "as_of": utc(at), "existed": state is not None, "state": state,
        "method": "audit log replay",
        "based_on": None if not row else {
            "audit_id": row["audit_id"], "chain_seq": row["chain_seq"], "operation": row["operation"],
            "changed_at": row["changed_at"], "actor": row["actor"], "row_hash": row["row_hash"]},
    }
    if entity == "order" and state is not None:
        # An order is its header plus its lines and payments: rebuild the whole document.
        result["items"] = _children_at_time(db, "order_item", f"{record_pk}:", at)
        result["payments"] = _payments_at_time(db, record_pk, at)
    return result


def compare(db: Db, entity: str, record_pk: str, t1: datetime, t2: datetime) -> dict[str, Any]:
    if utc(t1) > utc(t2):
        t1, t2 = t2, t1
    s1, _ = state_at_time(db, entity, record_pk, t1)
    s2, _ = state_at_time(db, entity, record_pk, t2)
    between = db.all(
        f"SELECT {AUDIT_COLS} FROM audit_log WHERE entity = %s AND record_pk = %s "
        "AND changed_at > %s AND changed_at <= %s ORDER BY chain_seq", (entity, record_pk, utc(t1), utc(t2)))
    result: dict[str, Any] = {
        "entity": entity, "record_pk": record_pk, "from": utc(t1), "to": utc(t2),
        "existed_from": s1 is not None, "existed_to": s2 is not None,
        "state_from": s1, "state_to": s2, "changes": diff_values(s1, s2),
        "events_between": [audit_entry(r) for r in between],
    }
    if entity == "order":
        key = lambda i: str(i["product_id"])  # noqa: E731
        a = {key(i): i for i in _children_at_time(db, "order_item", f"{record_pk}:", t1)}
        b = {key(i): i for i in _children_at_time(db, "order_item", f"{record_pk}:", t2)}
        result["item_changes"] = [
            {"product_id": int(k), "change": "added" if k not in a else "removed" if k not in b else "changed",
             "from": a.get(k), "to": b.get(k), "fields": diff_values(a.get(k), b.get(k))}
            for k in sorted(set(a) | set(b), key=int) if a.get(k) != b.get(k)]
    return result


def _num(v: Any) -> Decimal:
    return Decimal(str(v)) if v is not None else Decimal(0)


def explain_order(db: Db, order_id: int) -> dict[str, Any]:
    """Why-provenance: exactly which changes, by whom, produced this order's total."""
    order = db.one(
        "SELECT o.order_id, o.status, o.total_amount, o.currency, o.created_at, c.name AS customer_name "
        "FROM orders o JOIN customers c ON c.customer_id = o.customer_id WHERE o.order_id = %s", (order_id,))
    if not order:
        raise not_found("Order")
    prefix = f"{order_id}:%"
    names = {r["product_id"]: r for r in db.all(
        "SELECT p.product_id, p.name, p.sku, p.price FROM products p WHERE p.product_id IN "
        "(SELECT DISTINCT split_part(record_pk, ':', 2)::bigint FROM audit_log "
        " WHERE entity = 'order_item' AND record_pk LIKE %s)", (prefix,))}
    lines = db.all(
        "SELECT i.product_id, p.sku, p.name, i.quantity, i.unit_price, i.line_total, p.price AS current_list_price "
        "FROM order_items i JOIN products p ON p.product_id = i.product_id WHERE i.order_id = %s ORDER BY p.name",
        (order_id,))
    events = db.all(
        f"SELECT {AUDIT_COLS} FROM audit_log WHERE entity = 'order_item' AND record_pk LIKE %s ORDER BY chain_seq",
        (prefix,))

    running = Decimal(0)
    steps = []
    first_insert_seq: dict[int, int] = {}
    for ev in events:
        old, new = ev["old_values"], ev["new_values"]
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
            "delta": delta, "running_total": running, "request_id": ev["request_id"], "row_hash": ev["row_hash"],
        })

    # Compare each line's price with the catalogue price at the moment it was added.
    for line in lines:
        pid = int(line["product_id"])
        seq = first_insert_seq.get(pid)
        state = state_at_seq(db, "product", str(pid), seq) if seq else None
        list_then = _num(state.get("price")) if state else None
        line["list_price_at_order_time"] = list_then
        line["discount_pct"] = None
        line["price_note"] = None
        if list_then:
            discount = (list_then - line["unit_price"]) / list_then * 100
            line["discount_pct"] = round(discount, 2)
            line["price_note"] = (
                "matches catalogue price at order time" if line["unit_price"] == list_then
                else f"{abs(round(discount, 1))}% {'below' if discount > 0 else 'above'} catalogue price at order time")

    payments = db.all(
        "SELECT payment_id, amount, method, status, created_at FROM payments WHERE order_id = %s ORDER BY payment_id",
        (order_id,))
    lines_sum = sum((line["line_total"] for line in lines), Decimal(0))
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
        f"{'reproduces' if checks['replay_matches_total'] else 'does NOT reproduce'} that total.")
    return {"order": order, "summary": summary, "lines": lines, "steps": steps, "payments": payments, "checks": checks}


def order_lineage(db: Db, order_id: int) -> dict[str, Any]:
    """Graph of everything that contributed to an order, plus the causal chain of changes."""
    order = db.one(
        "SELECT o.order_id, o.status, o.total_amount, o.customer_id, c.name AS customer_name "
        "FROM orders o JOIN customers c ON c.customer_id = o.customer_id WHERE o.order_id = %s", (order_id,))
    if not order:
        raise not_found("Order")
    nodes: list[dict] = []
    edges: list[dict] = []
    oid = f"order:{order_id}"
    nodes.append({"id": oid, "type": "order", "label": f"Order #{order_id}",
                  "detail": f"{order['status']} - {order['total_amount']}", "record_pk": str(order_id)})
    cid = f"customer:{order['customer_id']}"
    nodes.append({"id": cid, "type": "customer", "label": order["customer_name"],
                  "detail": f"customer #{order['customer_id']}", "record_pk": str(order["customer_id"])})
    edges.append({"from": cid, "to": oid, "label": "placed"})

    items = db.all(
        "SELECT i.product_id, i.quantity, i.unit_price, i.line_total, p.name, p.sku, p.price "
        "FROM order_items i JOIN products p ON p.product_id = i.product_id WHERE i.order_id = %s ORDER BY p.name",
        (order_id,))
    product_ids = [str(it["product_id"]) for it in items]
    for it in items:
        iid = f"order_item:{order_id}:{it['product_id']}"
        pid = f"product:{it['product_id']}"
        nodes.append({"id": iid, "type": "order_item", "label": f"{it['quantity']} x {it['name']}",
                      "detail": f"@ {it['unit_price']} = {it['line_total']}",
                      "record_pk": f"{order_id}:{it['product_id']}"})
        nodes.append({"id": pid, "type": "product", "label": it["name"], "detail": f"{it['sku']} - list {it['price']}",
                      "record_pk": str(it["product_id"])})
        edges.append({"from": pid, "to": iid, "label": "priced"})
        edges.append({"from": iid, "to": oid, "label": "adds to total"})

    payments = db.all("SELECT payment_id, amount, method, status FROM payments WHERE order_id = %s ORDER BY payment_id",
                      (order_id,))
    for p in payments:
        pay = f"payment:{p['payment_id']}"
        nodes.append({"id": pay, "type": "payment", "label": f"{p['method']} {p['amount']}", "detail": p["status"],
                      "record_pk": str(p["payment_id"])})
        edges.append({"from": pay, "to": oid, "label": "pays"})

    if product_ids:
        for cr in db.all(
            "SELECT change_request_id, entity_id, status, requested_by, reviewed_by FROM change_requests "
            "WHERE entity = 'product' AND entity_id = ANY(%s) ORDER BY change_request_id", (product_ids,)):
            crn = f"change_request:{cr['change_request_id']}"
            nodes.append({"id": crn, "type": "change_request", "label": f"Price change #{cr['change_request_id']}",
                          "detail": f"{cr['status']} - by {cr['requested_by']}"
                                    + (f", reviewed by {cr['reviewed_by']}" if cr["reviewed_by"] else ""),
                          "record_pk": str(cr["change_request_id"])})
            edges.append({"from": crn, "to": f"product:{cr['entity_id']}", "label": "changed price"})

    for a in db.all(
        "SELECT alert_id, rule_code, severity, title FROM alerts WHERE (entity = 'order' AND entity_id = %s) "
        "OR (entity = 'order_item' AND entity_id LIKE %s) ORDER BY alert_id", (str(order_id), f"{order_id}:%")):
        an = f"alert:{a['alert_id']}"
        nodes.append({"id": an, "type": "alert", "label": f"{a['rule_code']} ({a['severity']})", "detail": a["title"],
                      "record_pk": str(a["alert_id"])})
        edges.append({"from": an, "to": oid, "label": "flags"})

    # Causal chain: a change made in the same request as an item/payment change (the trigger-driven
    # total recalculation, the automatic move to PAID) is linked back to what caused it.
    pay_ids = [str(p["payment_id"]) for p in payments]
    events = [audit_entry(r) for r in db.all(
        f"SELECT {AUDIT_COLS} FROM audit_log WHERE (entity = 'order' AND record_pk = %s) "
        "OR (entity = 'order_item' AND record_pk LIKE %s) OR (entity = 'payment' AND record_pk = ANY(%s)) "
        "ORDER BY chain_seq", (str(order_id), f"{order_id}:%", pay_ids))]
    last_cause: dict[str | None, dict] = {}
    for ev in events:
        req = ev["request_id"]
        ev["caused_by"] = None
        ev["explanation"] = None
        if ev["entity"] in ("order_item", "payment"):
            last_cause[req] = ev
        elif ev["entity"] == "order" and ev["operation"] == "UPDATE" and req is not None and req in last_cause:
            fields = {c["field"] for c in ev["changes"]}
            if "total_amount" in fields and last_cause[req]["entity"] == "order_item":
                ev["caused_by"] = last_cause[req]["audit_id"]
                ev["explanation"] = "total recalculated by the database after an item change"
            elif "status" in fields and last_cause[req]["entity"] == "payment":
                ev["caused_by"] = last_cause[req]["audit_id"]
                ev["explanation"] = "status changed because the payment covered the balance"

    seen: set[str] = set()
    unique = [n for n in nodes if not (n["id"] in seen or seen.add(n["id"]))]  # type: ignore[func-returns-value]
    return {"order_id": order_id, "nodes": unique, "edges": edges, "events": events}


def request_trace(db: Db, request_id: str) -> dict[str, Any]:
    """How-provenance: everything a single API call changed, including trigger cascades."""
    changes = [audit_entry(r) for r in db.all(
        f"SELECT {AUDIT_COLS} FROM audit_log WHERE request_id = %s ORDER BY chain_seq", (request_id,))]
    if not changes:
        raise not_found("Request")
    events = db.all(
        "SELECT event_id, event_type, entity, entity_id, created_at, dispatched_at FROM outbox_events "
        "WHERE request_id = %s ORDER BY event_id", (request_id,))
    return {
        "request_id": request_id,
        "actor": changes[0]["actor"],
        "started_at": changes[0]["changed_at"],
        "change_count": len(changes),
        "entities_touched": sorted({f"{c['entity']}:{c['record_pk']}" for c in changes}),
        "changes": changes,
        "events": events,
    }
