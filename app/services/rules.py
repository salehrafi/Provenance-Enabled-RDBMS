"""Data-quality and anomaly rules.

Each rule is a query over live tables or the audit log. Findings become alerts, deduplicated by
a fingerprint (INSERT ... ON CONFLICT DO NOTHING), and each new alert emits an `alert.raised`
outbox event. Rules run on demand (POST /alerts/run) and periodically in the worker.

Every rule runs inside a savepoint: in PostgreSQL a failed statement aborts the transaction, so
without one a single broken rule would discard the alerts raised by all the others.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import psycopg

from app.common import emit_event
from app.db import Db, jsonb
from app.services.integrity import verify_tenant

log = logging.getLogger("app.rules")


@dataclass
class Finding:
    rule_code: str
    severity: str
    entity: str
    entity_id: str
    title: str
    details: dict[str, Any]
    fingerprint: str


Rule = Callable[[Db, dict], list[Finding]]


def _payment_exceeds_total(db: Db, s: dict) -> list[Finding]:
    rows = db.all(
        """SELECT o.order_id, o.total_amount, sum(p.amount) AS paid
             FROM orders o JOIN payments p ON p.order_id = o.order_id AND p.status = 'CAPTURED'
            GROUP BY o.order_id, o.total_amount HAVING sum(p.amount) > o.total_amount""")
    return [Finding("DQ001", "HIGH", "order", str(r["order_id"]),
                    f"Order #{r['order_id']} captured {r['paid']} but its total is {r['total_amount']}",
                    r, f"DQ001:{r['order_id']}:{r['paid']}:{r['total_amount']}") for r in rows]


def _fulfilled_without_payment(db: Db, s: dict) -> list[Finding]:
    rows = db.all(
        """SELECT o.order_id, o.status, o.total_amount,
                  COALESCE((SELECT sum(amount) FROM payments p
                             WHERE p.order_id = o.order_id AND p.status = 'CAPTURED'), 0) AS paid
             FROM orders o WHERE o.status IN ('SHIPPED', 'DELIVERED')""")
    return [Finding("DQ002", "CRITICAL", "order", str(r["order_id"]),
                    f"Order #{r['order_id']} is {r['status']} but only {r['paid']} of {r['total_amount']} is paid",
                    r, f"DQ002:{r['order_id']}") for r in rows if r["paid"] < r["total_amount"]]


def _empty_paid_order(db: Db, s: dict) -> list[Finding]:
    rows = db.all(
        """SELECT o.order_id, o.status FROM orders o
            WHERE o.status NOT IN ('CREATED', 'CANCELLED')
              AND NOT EXISTS (SELECT 1 FROM order_items i WHERE i.order_id = o.order_id)""")
    return [Finding("DQ003", "MEDIUM", "order", str(r["order_id"]),
                    f"Order #{r['order_id']} is {r['status']} but has no items", r, f"DQ003:{r['order_id']}")
            for r in rows]


def _chain_integrity(db: Db, s: dict) -> list[Finding]:
    result = verify_tenant(db, s["tenant_id"])
    if result["ok"]:
        return []
    detail = {k: result[k] for k in ("first_bad_seq", "reason", "checked", "head_seq")}
    return [Finding("DQ004", "CRITICAL", "audit_log", str(result["first_bad_seq"]),
                    f"Audit chain integrity failure at record {result['first_bad_seq']}: {result['reason']}",
                    detail, f"DQ004:{result['first_bad_seq']}:{result['reason']}")]


def _large_price_change(db: Db, s: dict) -> list[Finding]:
    rows = db.all(
        """SELECT * FROM (
             SELECT a.audit_id, a.record_pk AS product_id, a.actor, a.changed_at, a.change_request_id,
                    a.new_values ->> 'name' AS name,
                    (a.old_values ->> 'price')::numeric AS old_price,
                    (a.new_values ->> 'price')::numeric AS new_price
               FROM audit_log a WHERE a.entity = 'product' AND a.operation = 'UPDATE') x
            WHERE old_price > 0 AND abs(new_price - old_price) / old_price * 100 >= %s""",
        (s["price_change_alert_pct"],))
    out = []
    for r in rows:
        pct = round(abs(r["new_price"] - r["old_price"]) / r["old_price"] * 100, 1)
        approved = f" (approved via change request #{r['change_request_id']})" if r["change_request_id"] else ""
        out.append(Finding("AN001", "MEDIUM" if r["change_request_id"] else "HIGH", "product", r["product_id"],
                           f"Price of '{r['name']}' changed {pct}% ({r['old_price']} -> {r['new_price']}) "
                           f"by {r['actor']}{approved}", r, f"AN001:{r['audit_id']}"))
    return out


def _deep_discount(db: Db, s: dict) -> list[Finding]:
    # Compare with the list price *when the item was added* (from the audit log), not today's
    # price; otherwise every later list-price increase would flag old orders as discounted.
    rows = db.all(
        """SELECT * FROM (
             SELECT i.order_id, i.product_id, p.name, i.unit_price,
                    COALESCE((SELECT (a.new_values ->> 'price')::numeric
                                FROM audit_log a
                               WHERE a.entity = 'product' AND a.record_pk = i.product_id::text
                                 AND a.operation <> 'DELETE' AND a.chain_seq < x.ins_seq
                               ORDER BY a.chain_seq DESC LIMIT 1), p.price) AS list_price
               FROM order_items i
               JOIN products p ON p.product_id = i.product_id
               LEFT JOIN (SELECT record_pk, min(chain_seq) AS ins_seq FROM audit_log
                           WHERE entity = 'order_item' AND operation = 'INSERT' GROUP BY record_pk) x
                 ON x.record_pk = i.order_id || ':' || i.product_id) y
            WHERE list_price > 0 AND (list_price - unit_price) / list_price * 100 >= %s""",
        (s["discount_alert_pct"],))
    return [Finding("AN002", "MEDIUM", "order_item", f"{r['order_id']}:{r['product_id']}",
                    f"Order #{r['order_id']} sells '{r['name']}' at {r['unit_price']}, "
                    f"{round((r['list_price'] - r['unit_price']) / r['list_price'] * 100, 1)}% below its list price "
                    f"at order time ({r['list_price']})",
                    r, f"AN002:{r['order_id']}:{r['product_id']}:{r['unit_price']}") for r in rows]


def _large_refund(db: Db, s: dict) -> list[Finding]:
    rows = db.all("SELECT payment_id, order_id, amount, method FROM payments WHERE status = 'REFUNDED' AND amount >= %s",
                  (s["large_refund_amount"],))
    return [Finding("AN003", "HIGH", "payment", str(r["payment_id"]),
                    f"Refund of {r['amount']} ({r['method']}) on order #{r['order_id']}", r,
                    f"AN003:{r['payment_id']}") for r in rows]


def _rapid_changes(db: Db, s: dict) -> list[Finding]:
    rows = db.all(
        """SELECT entity, record_pk, count(*) AS change_count, min(changed_at) AS first_at, max(changed_at) AS last_at,
                  string_agg(DISTINCT actor, ', ' ORDER BY actor) AS actors
             FROM audit_log
            WHERE operation = 'UPDATE' AND entity IN ('customer', 'product', 'order_item', 'payment')
              AND changed_at >= now() - make_interval(mins => %s)
            GROUP BY entity, record_pk HAVING count(*) >= %s""",
        (s["rapid_change_minutes"], s["rapid_change_count"]))
    return [Finding("AN004", "MEDIUM", r["entity"], r["record_pk"],
                    f"{r['entity']} {r['record_pk']} changed {r['change_count']} times in "
                    f"{s['rapid_change_minutes']} min by {r['actors']}",
                    r, f"AN004:{r['entity']}:{r['record_pk']}:{r['first_at']:%Y%m%d%H}") for r in rows]


def _out_of_band_change(db: Db, s: dict) -> list[Finding]:
    # db_user is the PostgreSQL role that logged in to make the change. Anything other than the
    # API's own role means someone wrote to the tables directly.
    rows = db.all("SELECT audit_id, entity, record_pk, operation, db_user, actor, changed_at FROM audit_log "
                  "WHERE db_user <> session_user ORDER BY audit_id LIMIT 500")
    return [Finding("AN005", "HIGH", r["entity"], r["record_pk"],
                    f"{r['operation']} on {r['entity']} {r['record_pk']} was made directly in the database as "
                    f"{r['db_user']}, bypassing the application", r, f"AN005:{r['audit_id']}") for r in rows]


RULES: dict[str, tuple[str, str, Rule]] = {
    "DQ001": ("Captured payments exceed order total", "HIGH", _payment_exceeds_total),
    "DQ002": ("Order fulfilled without full payment", "CRITICAL", _fulfilled_without_payment),
    "DQ003": ("Non-draft order has no items", "MEDIUM", _empty_paid_order),
    "DQ004": ("Audit chain or checkpoint verification failed", "CRITICAL", _chain_integrity),
    "AN001": ("Large product price change", "HIGH", _large_price_change),
    "AN002": ("Deep discount versus list price at order time", "MEDIUM", _deep_discount),
    "AN003": ("Large refund", "HIGH", _large_refund),
    "AN004": ("Rapid repeated changes to one record", "MEDIUM", _rapid_changes),
    "AN005": ("Change made outside the application", "HIGH", _out_of_band_change),
}
# Raised by other parts of the system, listed so the catalogue is complete.
EXTERNAL_RULES = {
    "RC001": ("Reconciliation found discrepancies", "HIGH"),
    "WH001": ("Webhook delivery abandoned after all retries", "MEDIUM"),
}


def raise_alert(db: Db, f: Finding, emit: bool = True) -> int | None:
    """Insert an alert unless one with the same fingerprint exists. Returns the new id."""
    alert_id = db.scalar(
        "INSERT INTO alerts (rule_code, severity, entity, entity_id, title, details, fingerprint) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (tenant_id, fingerprint) DO NOTHING RETURNING alert_id",
        (f.rule_code, f.severity, f.entity, f.entity_id, f.title[:300], jsonb(f.details), f.fingerprint[:200]))
    if alert_id is not None and emit:
        emit_event(db, "alert.raised", "alert", alert_id,
                   {"alert_id": alert_id, "rule_code": f.rule_code, "severity": f.severity,
                    "entity": f.entity, "entity_id": f.entity_id, "title": f.title})
    return alert_id


def run_rules(db: Db, tenant_id: int, only: set[str] | None = None, skip: set[str] | None = None) -> dict[str, Any]:
    settings = db.one("SELECT * FROM tenant_settings")
    if not settings:
        db.rollback()
        return {"new_alerts": 0, "findings": 0, "rules": {}}
    summary: dict[str, Any] = {}
    new_alerts = findings_total = 0
    for code, (name, _severity, rule) in RULES.items():
        if (only is not None and code not in only) or (skip and code in skip):
            continue
        try:
            with db.savepoint():
                findings = rule(db, settings)
                created = sum(1 for f in findings if raise_alert(db, f) is not None)
        except psycopg.Error:
            log.exception("rule %s failed for tenant %s", code, tenant_id)
            summary[code] = {"name": name, "error": True}
            continue
        summary[code] = {"name": name, "findings": len(findings), "new_alerts": created}
        new_alerts += created
        findings_total += len(findings)
    db.commit()
    return {"new_alerts": new_alerts, "findings": findings_total, "rules": summary}
