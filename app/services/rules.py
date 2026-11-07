"""Data-quality and anomaly rules.

Each rule is a SQL query over live tables or the audit log. Findings become alerts,
deduplicated by a fingerprint, and each new alert emits an `alert.raised` outbox event.
Runs on demand (POST /alerts/run) and periodically in the background worker.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

import oracledb

from app.common import dumps, emit_event
from app.config import get_settings
from app.db import Db

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
        """SELECT o.order_id, o.total_amount, SUM(p.amount) AS paid
             FROM orders o JOIN payments p ON p.order_id = o.order_id AND p.status = 'CAPTURED'
            GROUP BY o.order_id, o.total_amount HAVING SUM(p.amount) > o.total_amount"""
    )
    return [Finding("DQ001", "HIGH", "order", str(r["order_id"]),
                    f"Order #{r['order_id']} captured {r['paid']} but its total is {r['total_amount']}",
                    r, f"DQ001:{r['order_id']}:{r['paid']}:{r['total_amount']}") for r in rows]


def _fulfilled_without_payment(db: Db, s: dict) -> list[Finding]:
    rows = db.all(
        """SELECT o.order_id, o.status, o.total_amount,
                  NVL((SELECT SUM(amount) FROM payments p WHERE p.order_id = o.order_id AND p.status = 'CAPTURED'), 0) AS paid
             FROM orders o WHERE o.status IN ('SHIPPED', 'DELIVERED')"""
    )
    return [Finding("DQ002", "CRITICAL", "order", str(r["order_id"]),
                    f"Order #{r['order_id']} is {r['status']} but only {r['paid']} of {r['total_amount']} is paid",
                    r, f"DQ002:{r['order_id']}") for r in rows if r["paid"] < r["total_amount"]]


def _empty_paid_order(db: Db, s: dict) -> list[Finding]:
    rows = db.all(
        """SELECT o.order_id, o.status FROM orders o
            WHERE o.status NOT IN ('CREATED', 'CANCELLED')
              AND NOT EXISTS (SELECT 1 FROM order_items i WHERE i.order_id = o.order_id)"""
    )
    return [Finding("DQ003", "MEDIUM", "order", str(r["order_id"]),
                    f"Order #{r['order_id']} is {r['status']} but has no items", r, f"DQ003:{r['order_id']}") for r in rows]


def _chain_integrity(db: Db, s: dict) -> list[Finding]:
    result = verify_chain(db)
    if result["ok"]:
        return []
    return [Finding("DQ004", "CRITICAL", "audit_log", str(result["first_bad_seq"]),
                    f"Audit chain integrity failure at record {result['first_bad_seq']}: {result['reason']}",
                    result, f"DQ004:{result['first_bad_seq']}:{result['reason']}")]


def _large_price_change(db: Db, s: dict) -> list[Finding]:
    rows = db.all(
        """SELECT * FROM (
             SELECT a.audit_id, a.record_pk AS product_id, a.actor, a.changed_at, a.change_request_id,
                    JSON_VALUE(a.new_values, '$.name') AS name,
                    JSON_VALUE(a.old_values, '$.price' RETURNING NUMBER) AS old_price,
                    JSON_VALUE(a.new_values, '$.price' RETURNING NUMBER) AS new_price
               FROM audit_log a WHERE a.entity = 'product' AND a.operation = 'UPDATE')
            WHERE old_price > 0 AND ABS(new_price - old_price) / old_price * 100 >= :pct""",
        {"pct": s["price_change_alert_pct"]},
    )
    out = []
    for r in rows:
        pct = round(abs(r["new_price"] - r["old_price"]) / r["old_price"] * 100, 1)
        approved = f" (approved via change request #{r['change_request_id']})" if r["change_request_id"] else ""
        out.append(Finding("AN001", "MEDIUM" if r["change_request_id"] else "HIGH", "product", r["product_id"],
                           f"Price of '{r['name']}' changed {pct}% ({r['old_price']} -> {r['new_price']}) by {r['actor']}{approved}",
                           r, f"AN001:{r['audit_id']}"))
    return out


def _deep_discount(db: Db, s: dict) -> list[Finding]:
    # Compare with the list price *when the item was added* (from the audit log), not today's
    # price; otherwise every later list-price increase would flag old orders as discounted.
    rows = db.all(
        """SELECT * FROM (
             SELECT i.order_id, i.product_id, p.name, i.unit_price,
                    NVL((SELECT JSON_VALUE(a.new_values, '$.price' RETURNING NUMBER)
                           FROM audit_log a
                          WHERE a.entity = 'product' AND a.record_pk = TO_CHAR(i.product_id)
                            AND a.operation <> 'DELETE' AND a.chain_seq < x.ins_seq
                          ORDER BY a.chain_seq DESC FETCH FIRST 1 ROWS ONLY), p.price) AS list_price
               FROM order_items i
               JOIN products p ON p.product_id = i.product_id
               LEFT JOIN (SELECT record_pk, MIN(chain_seq) AS ins_seq FROM audit_log
                           WHERE entity = 'order_item' AND operation = 'INSERT' GROUP BY record_pk) x
                 ON x.record_pk = i.order_id || ':' || i.product_id)
            WHERE list_price > 0 AND (list_price - unit_price) / list_price * 100 >= :pct""",
        {"pct": s["discount_alert_pct"]},
    )
    return [Finding("AN002", "MEDIUM", "order_item", f"{r['order_id']}:{r['product_id']}",
                    f"Order #{r['order_id']} sells '{r['name']}' at {r['unit_price']}, "
                    f"{round((r['list_price'] - r['unit_price']) / r['list_price'] * 100, 1)}% below its list price "
                    f"at order time ({r['list_price']})",
                    r, f"AN002:{r['order_id']}:{r['product_id']}:{r['unit_price']}") for r in rows]


def _large_refund(db: Db, s: dict) -> list[Finding]:
    rows = db.all(
        "SELECT payment_id, order_id, amount, method FROM payments WHERE status = 'REFUNDED' AND amount >= :amt",
        {"amt": s["large_refund_amount"]},
    )
    return [Finding("AN003", "HIGH", "payment", str(r["payment_id"]),
                    f"Refund of {r['amount']} ({r['method']}) on order #{r['order_id']}", r,
                    f"AN003:{r['payment_id']}") for r in rows]


def _rapid_changes(db: Db, s: dict) -> list[Finding]:
    rows = db.all(
        """SELECT entity, record_pk, COUNT(*) AS change_count, MIN(changed_at) AS first_at, MAX(changed_at) AS last_at,
                  LISTAGG(DISTINCT actor, ', ') WITHIN GROUP (ORDER BY actor) AS actors
             FROM audit_log
            WHERE operation = 'UPDATE' AND entity <> 'order'
              AND changed_at >= SYS_EXTRACT_UTC(SYSTIMESTAMP) - NUMTODSINTERVAL(:mins, 'MINUTE')
            GROUP BY entity, record_pk HAVING COUNT(*) >= :cnt""",
        {"mins": s["rapid_change_minutes"], "cnt": s["rapid_change_count"]},
    )
    return [Finding("AN004", "MEDIUM", r["entity"], r["record_pk"],
                    f"{r['entity']} {r['record_pk']} changed {r['change_count']} times in {s['rapid_change_minutes']} min by {r['actors']}",
                    r, f"AN004:{r['entity']}:{r['record_pk']}:{r['first_at']:%Y%m%d%H}") for r in rows]


def _out_of_band_change(db: Db, s: dict) -> list[Finding]:
    app_user = get_settings().db_app_user.upper()
    rows = db.all(
        "SELECT audit_id, entity, record_pk, operation, db_user, actor, changed_at FROM audit_log WHERE db_user <> :u",
        {"u": app_user},
    )
    return [Finding("AN005", "HIGH", r["entity"], r["record_pk"],
                    f"{r['operation']} on {r['entity']} {r['record_pk']} was made directly in the database as "
                    f"{r['db_user']}, bypassing the application", r, f"AN005:{r['audit_id']}") for r in rows]


RULES: dict[str, tuple[str, Rule]] = {
    "DQ001": ("Captured payments exceed order total", _payment_exceeds_total),
    "DQ002": ("Order fulfilled without full payment", _fulfilled_without_payment),
    "DQ003": ("Non-draft order has no items", _empty_paid_order),
    "DQ004": ("Audit hash chain is intact", _chain_integrity),
    "AN001": ("Large product price change", _large_price_change),
    "AN002": ("Deep discount versus list price", _deep_discount),
    "AN003": ("Large refund", _large_refund),
    "AN004": ("Rapid repeated changes to one record", _rapid_changes),
    "AN005": ("Change made outside the application", _out_of_band_change),
}


def verify_chain(db: Db) -> dict[str, Any]:
    with db.cursor() as cur:
        ok, checked, bad, reason = cur.var(int), cur.var(int), cur.var(int), cur.var(str)
        cur.callproc("audit_api_pkg.verify_chain", [ok, checked, bad, reason])
        head = db.one("SELECT COUNT(*) AS n, MAX(chain_seq) AS head_seq FROM audit_log")
        return {"ok": ok.getvalue() == 1, "checked": checked.getvalue(), "first_bad_seq": bad.getvalue(),
                "reason": reason.getvalue(), "records": head["n"], "head_seq": head["head_seq"]}


def run_rules(db: Db, tenant_id: int) -> dict[str, Any]:
    settings = db.one("SELECT * FROM tenant_settings")
    if not settings:
        return {"new_alerts": 0, "findings": 0, "rules": {}}
    summary: dict[str, Any] = {}
    new_alerts = 0
    findings_total = 0
    for code, (name, rule) in RULES.items():
        try:
            findings = rule(db, settings)
        except oracledb.DatabaseError:
            log.exception("rule %s failed for tenant %s", code, tenant_id)
            summary[code] = {"name": name, "error": True}
            continue
        created = 0
        for f in findings:
            try:
                alert_id = db.insert(
                    "INSERT INTO alerts (rule_code, severity, entity, entity_id, title, details, fingerprint) "
                    "VALUES (:c, :s, :e, :i, :t, :d, :f)",
                    {"c": f.rule_code, "s": f.severity, "e": f.entity, "i": f.entity_id, "t": f.title[:300],
                     "d": dumps(f.details), "f": f.fingerprint[:200]},
                    "alert_id",
                )
            except oracledb.IntegrityError:
                continue  # already raised (same fingerprint)
            created += 1
            emit_event(db, tenant_id, "alert.raised", "alert", alert_id,
                       {"alert_id": alert_id, "rule_code": f.rule_code, "severity": f.severity,
                        "entity": f.entity, "entity_id": f.entity_id, "title": f.title})
        summary[code] = {"name": name, "findings": len(findings), "new_alerts": created}
        new_alerts += created
        findings_total += len(findings)
    db.commit()
    return {"new_alerts": new_alerts, "findings": findings_total, "rules": summary}
