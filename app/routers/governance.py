from __future__ import annotations

from decimal import Decimal
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.common import emit_event, not_found
from app.db import Db, parse_json
from app.deps import CurrentUser, admin, get_db, staff, viewer
from app.schemas import AlertUpdate, ReviewIn, WebhookIn, WebhookUpdate
from app.security import new_webhook_secret
from app.services import rules
from app.services.webhooks import validate_url

router = APIRouter(tags=["governance"])


# ---- alerts ---------------------------------------------------------------------------
@router.get("/alerts", summary="List alerts raised by data-quality and anomaly rules")
def list_alerts(
    status_: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"] | None = Query(None, alias="status"),
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
    limit: int = Query(100, ge=1, le=500),
    user: CurrentUser = Depends(viewer),
    db: Db = Depends(get_db),
):
    conds, params = [], {"lim": limit}
    if status_:
        conds.append("status = :s")
        params["s"] = status_
    if severity:
        conds.append("severity = :sev")
        params["sev"] = severity
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    rows = db.all(
        "SELECT alert_id, rule_code, severity, entity, entity_id, title, details, status, created_at, updated_at, updated_by "
        f"FROM alerts{where} ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, "
        "alert_id DESC FETCH FIRST :lim ROWS ONLY",
        params,
    )
    for r in rows:
        r["details"] = parse_json(r["details"])
    return rows


@router.get("/alerts/rules", summary="The rule catalogue")
def list_rules(user: CurrentUser = Depends(viewer)):
    return [{"code": code, "name": name} for code, (name, _) in rules.RULES.items()]


@router.post("/alerts/run", summary="Run all rules now")
def run_rules(user: CurrentUser = Depends(staff), db: Db = Depends(get_db)):
    return rules.run_rules(db, user.tenant_id)


@router.patch("/alerts/{alert_id}", summary="Acknowledge, resolve or reopen an alert")
def update_alert(alert_id: int, body: AlertUpdate, user: CurrentUser = Depends(staff), db: Db = Depends(get_db)):
    n = db.execute(
        "UPDATE alerts SET status = :s, updated_at = SYS_EXTRACT_UTC(SYSTIMESTAMP), updated_by = :u WHERE alert_id = :id",
        {"s": body.status, "u": user.email, "id": alert_id},
    )
    if not n:
        raise not_found("Alert")
    db.commit()
    row = db.one("SELECT alert_id, status, updated_at, updated_by FROM alerts WHERE alert_id = :id", {"id": alert_id})
    return row


# ---- maker-checker approvals ----------------------------------------------------------
_CR_COLS = ("change_request_id, entity, entity_id, change_type, payload, reason, status, requested_by_id, requested_by, "
            "requested_at, reviewed_by_id, reviewed_by, reviewed_at, review_note")


def _cr(db: Db, cr_id: int, lock: bool = False) -> dict:
    row = db.one(f"SELECT {_CR_COLS} FROM change_requests WHERE change_request_id = :id" + (" FOR UPDATE" if lock else ""),
                 {"id": cr_id})
    if not row:
        raise not_found("Change request")
    row["payload"] = parse_json(row["payload"])
    return row


@router.get("/approvals", summary="List change requests awaiting (or past) approval")
def list_approvals(
    status_: Literal["PENDING", "APPROVED", "REJECTED"] | None = Query(None, alias="status"),
    user: CurrentUser = Depends(viewer),
    db: Db = Depends(get_db),
):
    where, params = ("", {}) if not status_ else (" WHERE r.status = :s", {"s": status_})
    rows = db.all(
        f"SELECT r.*, p.name AS product_name FROM (SELECT {_CR_COLS} FROM change_requests) r "
        f"LEFT JOIN products p ON r.entity = 'product' AND TO_CHAR(p.product_id) = r.entity_id{where} "
        "ORDER BY r.change_request_id DESC",
        params,
    )
    for r in rows:
        r["payload"] = parse_json(r["payload"])
        r["can_review"] = r["status"] == "PENDING" and user.role == "admin" and r["requested_by_id"] != user.user_id
    return rows


def _review_guard(cr: dict, user: CurrentUser) -> None:
    if cr["status"] != "PENDING":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Change request is already {cr['status']}")
    if cr["requested_by_id"] == user.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Four-eyes rule: you cannot review your own change request")


@router.post("/approvals/{cr_id}/approve", summary="Approve and apply a change request (admin, not the requester)")
def approve(cr_id: int, body: ReviewIn, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    cr = _cr(db, cr_id, lock=True)
    _review_guard(cr, user)
    if cr["change_type"] != "PRICE_CHANGE":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unsupported change type {cr['change_type']}")
    product_id = int(cr["entity_id"])
    current = db.one("SELECT price FROM products WHERE product_id = :id FOR UPDATE", {"id": product_id})
    if not current:
        raise not_found("Product")
    if current["price"] != Decimal(str(cr["payload"]["old_price"])):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"Stale request: price is now {current['price']}, not {cr['payload']['old_price']}. Reject it.")
    # The audit row written by the product trigger will carry this change_request_id.
    db.callproc("ctx_pkg.set_change_request", [cr_id])
    db.execute("UPDATE products SET price = :p WHERE product_id = :id",
               {"p": Decimal(str(cr["payload"]["new_price"])), "id": product_id})
    db.execute(
        "UPDATE change_requests SET status = 'APPROVED', reviewed_by_id = :actor_id, reviewed_by = :u, "
        "reviewed_at = SYS_EXTRACT_UTC(SYSTIMESTAMP), review_note = :n WHERE change_request_id = :id",
        {"actor_id": user.user_id, "u": user.email, "n": body.note, "id": cr_id},
    )
    emit_event(db, user.tenant_id, "change_request.approved", "change_request", cr_id,
               {"change_request_id": cr_id, "product_id": product_id, **cr["payload"], "approved_by": user.email})
    db.commit()
    return _cr(db, cr_id)


@router.post("/approvals/{cr_id}/reject", summary="Reject a change request (admin, not the requester)")
def reject(cr_id: int, body: ReviewIn, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    cr = _cr(db, cr_id, lock=True)
    _review_guard(cr, user)
    db.execute(
        "UPDATE change_requests SET status = 'REJECTED', reviewed_by_id = :actor_id, reviewed_by = :u, "
        "reviewed_at = SYS_EXTRACT_UTC(SYSTIMESTAMP), review_note = :n WHERE change_request_id = :id",
        {"actor_id": user.user_id, "u": user.email, "n": body.note, "id": cr_id},
    )
    emit_event(db, user.tenant_id, "change_request.rejected", "change_request", cr_id,
               {"change_request_id": cr_id, **cr["payload"], "rejected_by": user.email})
    db.commit()
    return _cr(db, cr_id)


# ---- webhooks & events ----------------------------------------------------------------
_WH_COLS = "webhook_id, url, event_types, description, is_active, created_at"


def _webhook(db: Db, webhook_id: int) -> dict:
    row = db.one(
        f"SELECT {_WH_COLS}, "
        "(SELECT COUNT(*) FROM webhook_deliveries d WHERE d.webhook_id = w.webhook_id AND d.status = 'SUCCESS') AS delivered, "
        "(SELECT COUNT(*) FROM webhook_deliveries d WHERE d.webhook_id = w.webhook_id AND d.status IN ('FAILED','DEAD')) AS failing "
        "FROM webhooks w WHERE webhook_id = :id",
        {"id": webhook_id},
    )
    if not row:
        raise not_found("Webhook")
    return row


def _check_url(url: str) -> None:
    try:
        validate_url(url)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc))


@router.get("/webhooks", summary="List webhook subscriptions")
def list_webhooks(user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    ids = [r["webhook_id"] for r in db.all("SELECT webhook_id FROM webhooks ORDER BY webhook_id")]
    return [_webhook(db, i) for i in ids]


@router.post("/webhooks", status_code=status.HTTP_201_CREATED,
             summary="Subscribe a URL to events (the signing secret is shown only once)")
def create_webhook(body: WebhookIn, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    url = str(body.url)
    _check_url(url)
    secret = new_webhook_secret()
    new_id = db.insert(
        "INSERT INTO webhooks (url, secret, event_types, description) VALUES (:u, :s, :e, :d)",
        {"u": url, "s": secret, "e": ",".join(t.strip() for t in body.event_types), "d": body.description},
        "webhook_id",
    )
    db.commit()
    return {**_webhook(db, new_id), "secret": secret}


@router.patch("/webhooks/{webhook_id}", summary="Update or pause a webhook")
def update_webhook(webhook_id: int, body: WebhookUpdate, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    _webhook(db, webhook_id)
    sets, params = [], {"id": webhook_id}
    if body.url is not None:
        _check_url(str(body.url))
        sets.append("url = :u")
        params["u"] = str(body.url)
    if body.event_types is not None:
        sets.append("event_types = :e")
        params["e"] = ",".join(t.strip() for t in body.event_types)
    if body.description is not None:
        sets.append("description = :d")
        params["d"] = body.description
    if body.is_active is not None:
        sets.append("is_active = :a")
        params["a"] = "Y" if body.is_active else "N"
    if sets:
        db.execute(f"UPDATE webhooks SET {', '.join(sets)} WHERE webhook_id = :id", params)
        db.commit()
    return _webhook(db, webhook_id)


@router.get("/webhooks/{webhook_id}/deliveries", summary="Delivery log for a webhook")
def list_deliveries(webhook_id: int, limit: int = Query(50, ge=1, le=500), user: CurrentUser = Depends(admin),
                    db: Db = Depends(get_db)):
    _webhook(db, webhook_id)
    return db.all(
        "SELECT d.delivery_id, d.event_id, e.event_type, d.status, d.attempts, d.response_code, d.last_error, "
        "d.next_attempt_at, d.created_at, d.delivered_at FROM webhook_deliveries d "
        "JOIN outbox_events e ON e.event_id = d.event_id WHERE d.webhook_id = :id "
        "ORDER BY d.delivery_id DESC FETCH FIRST :lim ROWS ONLY",
        {"id": webhook_id, "lim": limit},
    )


@router.post("/webhooks/{webhook_id}/test", summary="Send a test event")
def test_webhook(webhook_id: int, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    _webhook(db, webhook_id)
    emit_event(db, user.tenant_id, "webhook.test", "webhook", webhook_id,
               {"message": "Test event from Provenance Cloud", "sent_by": user.email})
    db.commit()
    return {"queued": True}


@router.post("/webhooks/deliveries/{delivery_id}/retry", summary="Retry a failed delivery now")
def retry_delivery(delivery_id: int, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    n = db.execute(
        "UPDATE webhook_deliveries SET status = 'PENDING', attempts = 0, next_attempt_at = SYS_EXTRACT_UTC(SYSTIMESTAMP) "
        "WHERE delivery_id = :id AND status <> 'SUCCESS'",
        {"id": delivery_id},
    )
    if not n:
        raise HTTPException(status.HTTP_409_CONFLICT, "Delivery not found or already delivered")
    db.commit()
    return {"queued": True}


@router.get("/events", summary="Recent events from the transactional outbox")
def list_events(
    event_type: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    user: CurrentUser = Depends(staff),
    db: Db = Depends(get_db),
):
    where, params = ("", {"lim": limit}) if not event_type else (" WHERE event_type LIKE :t", {"lim": limit, "t": event_type.replace("*", "%")})
    rows = db.all(
        f"SELECT event_id, event_type, entity, entity_id, payload, request_id, created_at, dispatched_at FROM outbox_events{where} "
        "ORDER BY event_id DESC FETCH FIRST :lim ROWS ONLY",
        params,
    )
    for r in rows:
        r["payload"] = parse_json(r["payload"])
    return rows


# ---- dashboard ------------------------------------------------------------------------
@router.get("/dashboard", tags=["dashboard"], summary="Key metrics for the organization")
def dashboard(user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    counts = db.one(
        """SELECT (SELECT COUNT(*) FROM customers) AS customers,
                  (SELECT COUNT(*) FROM products WHERE active_flag = 'Y') AS active_products,
                  (SELECT COUNT(*) FROM orders) AS orders,
                  (SELECT NVL(SUM(total_amount), 0) FROM orders WHERE status IN ('PAID','SHIPPED','DELIVERED')) AS revenue,
                  (SELECT NVL(SUM(amount), 0) FROM payments WHERE status = 'REFUNDED') AS refunded,
                  (SELECT COUNT(*) FROM alerts WHERE status = 'OPEN') AS open_alerts,
                  (SELECT COUNT(*) FROM change_requests WHERE status = 'PENDING') AS pending_approvals,
                  (SELECT COUNT(*) FROM audit_log) AS audit_records,
                  (SELECT COUNT(*) FROM outbox_events) AS events,
                  (SELECT COUNT(*) FROM webhook_deliveries WHERE status IN ('FAILED','DEAD')) AS failing_deliveries
             FROM dual"""
    )
    return {
        "counts": counts,
        "currency": db.scalar("SELECT currency FROM tenant_settings"),
        "orders_by_status": db.all("SELECT status, COUNT(*) AS n, NVL(SUM(total_amount),0) AS amount FROM orders "
                                   "GROUP BY status ORDER BY status"),
        "alerts_by_severity": db.all("SELECT severity, COUNT(*) AS n FROM alerts WHERE status = 'OPEN' GROUP BY severity"),
        "revenue_by_day": db.all(
            "SELECT TRUNC(created_at) AS day, COUNT(*) AS orders, NVL(SUM(total_amount),0) AS amount FROM orders "
            "WHERE status IN ('PAID','SHIPPED','DELIVERED') AND created_at >= SYS_EXTRACT_UTC(SYSTIMESTAMP) - 14 "
            "GROUP BY TRUNC(created_at) ORDER BY day"),
        "top_products": db.all(
            "SELECT p.product_id, p.name, SUM(i.quantity) AS units, SUM(i.line_total) AS amount FROM order_items i "
            "JOIN products p ON p.product_id = i.product_id JOIN orders o ON o.order_id = i.order_id "
            "WHERE o.status IN ('PAID','SHIPPED','DELIVERED') GROUP BY p.product_id, p.name "
            "ORDER BY amount DESC FETCH FIRST 5 ROWS ONLY"),
        "top_actors": db.all("SELECT actor, COUNT(*) AS changes FROM audit_log GROUP BY actor ORDER BY changes DESC "
                             "FETCH FIRST 5 ROWS ONLY"),
        "recent_activity": db.all(
            "SELECT audit_id, entity, record_pk, operation, actor, changed_at, request_id FROM audit_log "
            "ORDER BY audit_id DESC FETCH FIRST 10 ROWS ONLY"),
    }
