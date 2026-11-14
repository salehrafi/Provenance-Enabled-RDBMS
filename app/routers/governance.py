from __future__ import annotations

from decimal import Decimal
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Response

from app.auth import Ctx, require, require_user
from app.common import emit_event
from app.db import Db
from app.errors import ApiError, not_found
from app.schemas import AlertUpdate, ReviewIn, WebhookIn, WebhookUpdate
from app.security import new_webhook_secret
from app.services import rules, webhooks

router = APIRouter(tags=["governance"])


# ---- alerts ---------------------------------------------------------------------------
@router.get("/alerts", summary="List alerts raised by data-quality and anomaly rules")
def list_alerts(
    status_: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"] | None = Query(None, alias="status"),
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
    rule_code: str | None = Query(None, max_length=20),
    limit: int = Query(100, ge=1, le=500),
    ctx: Ctx = Depends(require("alerts:read")),
):
    conds: list[str] = []
    params: dict[str, Any] = {"lim": limit}
    for col, val, key in (("status", status_, "s"), ("severity", severity, "sev"), ("rule_code", rule_code, "r")):
        if val:
            conds.append(f"{col} = %({key})s")
            params[key] = val
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    rows = ctx.db.all(
        "SELECT alert_id, rule_code, severity, entity, entity_id, title, details, status, created_at, updated_at, "
        f"updated_by FROM alerts{where} ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
        "WHEN 'MEDIUM' THEN 2 ELSE 3 END, alert_id DESC LIMIT %(lim)s", params)
    return {"items": rows}


@router.get("/alerts/rules", summary="The rule catalogue")
def list_rules(ctx: Ctx = Depends(require("alerts:read"))):
    items = [{"code": c, "name": n, "severity": s} for c, (n, s, _) in rules.RULES.items()]
    items += [{"code": c, "name": n, "severity": s} for c, (n, s) in rules.EXTERNAL_RULES.items()]
    return {"items": items}


@router.post("/alerts/run", summary="Run all rules now")
def run_rules(ctx: Ctx = Depends(require_user("alerts:manage"))):
    return rules.run_rules(ctx.db, ctx.tenant_id)


@router.patch("/alerts/{alert_id}", summary="Acknowledge, resolve or reopen an alert")
def update_alert(alert_id: int, body: AlertUpdate, ctx: Ctx = Depends(require_user("alerts:manage"))):
    n = ctx.db.execute("UPDATE alerts SET status = %s, updated_at = now(), updated_by = %s WHERE alert_id = %s",
                       (body.status, ctx.actor, alert_id))
    if not n:
        raise not_found("Alert")
    ctx.db.commit()
    return ctx.db.one("SELECT alert_id, status, updated_at, updated_by FROM alerts WHERE alert_id = %s", (alert_id,))


# ---- maker-checker approvals ----------------------------------------------------------
_CR_COLS = ("change_request_id, entity, entity_id, change_type, payload, reason, status, requested_by_id, "
            "requested_by, requested_at, reviewed_by_id, reviewed_by, reviewed_at, review_note")


def _cr(db: Db, cr_id: int, lock: bool = False) -> dict[str, Any]:
    row = db.one(f"SELECT {_CR_COLS} FROM change_requests WHERE change_request_id = %s" + (" FOR UPDATE" if lock else ""),
                 (cr_id,))
    if not row:
        raise not_found("Change request")
    return row


@router.get("/approvals", summary="List change requests awaiting (or past) approval")
def list_approvals(status_: Literal["PENDING", "APPROVED", "REJECTED"] | None = Query(None, alias="status"),
                   ctx: Ctx = Depends(require("approvals:read"))):
    where, params = ("", ()) if not status_ else (" WHERE r.status = %s", (status_,))
    rows = ctx.db.all(
        f"SELECT r.*, p.name AS product_name FROM (SELECT {_CR_COLS} FROM change_requests) r "
        f"LEFT JOIN products p ON r.entity = 'product' AND p.product_id::text = r.entity_id{where} "
        "ORDER BY r.change_request_id DESC LIMIT 500", params)
    can_review = ctx.principal.can("approvals:review")
    for r in rows:
        r["can_review"] = r["status"] == "PENDING" and can_review and r["requested_by_id"] != ctx.principal.user_id
    return {"items": rows}


def _review_guard(cr: dict, ctx: Ctx) -> None:
    if cr["status"] != "PENDING":
        raise ApiError(409, f"Change request is already {cr['status']}", "CHANGE_REQUEST_DECIDED")
    if cr["requested_by_id"] == ctx.principal.user_id:
        raise ApiError(403, "Four-eyes rule: you cannot review your own change request", "FOUR_EYES")


@router.post("/approvals/{cr_id}/approve", summary="Approve and apply a change request (not by its requester)")
def approve(cr_id: int, body: ReviewIn, ctx: Ctx = Depends(require_user("approvals:review"))):
    db = ctx.db
    cr = _cr(db, cr_id, lock=True)
    _review_guard(cr, ctx)
    if cr["change_type"] != "PRICE_CHANGE":
        raise ApiError(422, f"Unsupported change type {cr['change_type']}", "UNSUPPORTED")
    product_id = int(cr["entity_id"])
    current = db.one("SELECT price FROM products WHERE product_id = %s FOR UPDATE", (product_id,))
    if not current:
        raise not_found("Product")
    old, new = Decimal(str(cr["payload"]["old_price"])), Decimal(str(cr["payload"]["new_price"]))
    if current["price"] != old:
        raise ApiError(409, f"Stale request: price is now {current['price']}, not {old}. Reject it.", "STALE_REQUEST")
    # The audit record written by the product trigger will carry this change_request_id.
    db.execute("SELECT prov.set_change_request(%s)", (cr_id,))
    db.execute("UPDATE products SET price = %s WHERE product_id = %s", (new, product_id))
    db.execute("SELECT prov.set_change_request(NULL)")
    db.execute("UPDATE change_requests SET status = 'APPROVED', reviewed_by_id = %s, reviewed_by = %s, "
               "reviewed_at = now(), review_note = %s WHERE change_request_id = %s",
               (ctx.principal.user_id, ctx.actor, body.note, cr_id))
    emit_event(db, "change_request.approved", "change_request", cr_id,
               {"change_request_id": cr_id, "product_id": product_id, **cr["payload"], "approved_by": ctx.actor})
    db.commit()
    return _cr(db, cr_id)


@router.post("/approvals/{cr_id}/reject", summary="Reject a change request (not by its requester)")
def reject(cr_id: int, body: ReviewIn, ctx: Ctx = Depends(require_user("approvals:review"))):
    db = ctx.db
    cr = _cr(db, cr_id, lock=True)
    _review_guard(cr, ctx)
    db.execute("UPDATE change_requests SET status = 'REJECTED', reviewed_by_id = %s, reviewed_by = %s, "
               "reviewed_at = now(), review_note = %s WHERE change_request_id = %s",
               (ctx.principal.user_id, ctx.actor, body.note, cr_id))
    emit_event(db, "change_request.rejected", "change_request", cr_id,
               {"change_request_id": cr_id, **cr["payload"], "rejected_by": ctx.actor})
    db.commit()
    return _cr(db, cr_id)


# ---- webhooks & events ----------------------------------------------------------------
_WH_SQL = """
    SELECT w.webhook_id, w.url, w.event_types, w.description, w.is_active, w.created_at,
           count(d.*) FILTER (WHERE d.status = 'SUCCESS') AS delivered,
           count(d.*) FILTER (WHERE d.status IN ('FAILED', 'DEAD')) AS failing
      FROM webhooks w LEFT JOIN webhook_deliveries d ON d.webhook_id = w.webhook_id
"""


def _webhook(db: Db, webhook_id: int) -> dict[str, Any]:
    row = db.one(_WH_SQL + " WHERE w.webhook_id = %s GROUP BY w.webhook_id", (webhook_id,))
    if not row:
        raise not_found("Webhook")
    return row


def _check_url(url: str) -> None:
    try:
        webhooks.resolve_target(url)
    except ValueError as exc:
        raise ApiError(422, str(exc), "INVALID_WEBHOOK_URL") from None


@router.get("/webhooks", summary="List webhook subscriptions")
def list_webhooks(ctx: Ctx = Depends(require("webhooks:manage"))):
    return {"items": ctx.db.all(_WH_SQL + " GROUP BY w.webhook_id ORDER BY w.webhook_id")}


@router.post("/webhooks", status_code=201, summary="Subscribe a URL to events (the signing secret is shown once)")
def create_webhook(body: WebhookIn, ctx: Ctx = Depends(require_user("webhooks:manage"))):
    url = str(body.url)
    _check_url(url)
    secret = new_webhook_secret()
    new_id = ctx.db.insert(
        "INSERT INTO webhooks (url, secret_enc, event_types, description) VALUES (%s, %s, %s, %s)",
        (url, webhooks.seal_secret(ctx.tenant_id, secret), body.event_types, body.description), "webhook_id")
    ctx.db.commit()
    return {**_webhook(ctx.db, new_id), "secret": secret}


@router.patch("/webhooks/{webhook_id}", summary="Update or pause a webhook")
def update_webhook(webhook_id: int, body: WebhookUpdate, ctx: Ctx = Depends(require_user("webhooks:manage"))):
    _webhook(ctx.db, webhook_id)
    sets: list[str] = []
    params: list[Any] = []
    if body.url is not None:
        _check_url(str(body.url))
        sets.append("url = %s")
        params.append(str(body.url))
    if body.event_types is not None:
        sets.append("event_types = %s")
        params.append(body.event_types)
    if body.description is not None:
        sets.append("description = %s")
        params.append(body.description)
    if body.is_active is not None:
        sets.append("is_active = %s")
        params.append(body.is_active)
    if sets:
        ctx.db.execute(f"UPDATE webhooks SET {', '.join(sets)} WHERE webhook_id = %s", (*params, webhook_id))
        ctx.db.commit()
    return _webhook(ctx.db, webhook_id)


@router.delete("/webhooks/{webhook_id}", status_code=204, summary="Delete a webhook and its delivery log")
def delete_webhook(webhook_id: int, ctx: Ctx = Depends(require_user("webhooks:manage"))):
    if not ctx.db.execute("DELETE FROM webhooks WHERE webhook_id = %s", (webhook_id,)):
        raise not_found("Webhook")
    ctx.db.commit()
    return Response(status_code=204)


@router.post("/webhooks/{webhook_id}/rotate-secret", summary="Issue a new signing secret (shown once)")
def rotate_secret(webhook_id: int, ctx: Ctx = Depends(require_user("webhooks:manage"))):
    _webhook(ctx.db, webhook_id)
    secret = new_webhook_secret()
    ctx.db.execute("UPDATE webhooks SET secret_enc = %s WHERE webhook_id = %s",
                   (webhooks.seal_secret(ctx.tenant_id, secret), webhook_id))
    ctx.db.commit()
    return {"webhook_id": webhook_id, "secret": secret}


@router.get("/webhooks/{webhook_id}/deliveries", summary="Delivery log for a webhook (debugging)")
def list_deliveries(webhook_id: int, status_: Literal["PENDING", "FAILED", "SUCCESS", "DEAD"] | None = Query(None, alias="status"),
                    limit: int = Query(50, ge=1, le=500), ctx: Ctx = Depends(require("webhooks:manage"))):
    _webhook(ctx.db, webhook_id)
    rows = ctx.db.all(
        "SELECT d.delivery_id, d.event_id, e.event_type, d.status, d.attempts, d.response_code, d.response_snippet, "
        "d.last_error, d.duration_ms, d.next_attempt_at, d.created_at, d.delivered_at FROM webhook_deliveries d "
        "JOIN outbox_events e ON e.event_id = d.event_id WHERE d.webhook_id = %s "
        "AND (%s::text IS NULL OR d.status = %s) ORDER BY d.delivery_id DESC LIMIT %s",
        (webhook_id, status_, status_, limit))
    return {"items": rows}


@router.post("/webhooks/{webhook_id}/test", summary="Send a test event")
def test_webhook(webhook_id: int, ctx: Ctx = Depends(require_user("webhooks:manage"))):
    _webhook(ctx.db, webhook_id)
    emit_event(ctx.db, "webhook.test", "webhook", webhook_id,
               {"message": "Test event from Provenance Cloud", "sent_by": ctx.actor})
    ctx.db.commit()
    return {"queued": True}


@router.post("/webhooks/deliveries/{delivery_id}/retry", summary="Retry a failed delivery now")
def retry_delivery(delivery_id: int, ctx: Ctx = Depends(require_user("webhooks:manage"))):
    n = ctx.db.execute("UPDATE webhook_deliveries SET status = 'PENDING', attempts = 0, next_attempt_at = now(), "
                       "locked_until = NULL WHERE delivery_id = %s AND status IN ('FAILED', 'DEAD')", (delivery_id,))
    if not n:
        raise ApiError(409, "Delivery not found, or not in a failed state", "NOT_RETRYABLE")
    ctx.db.commit()
    return {"queued": True}


@router.get("/events", summary="Recent events from the transactional outbox")
def list_events(event_type: str | None = Query(None, max_length=80), limit: int = Query(50, ge=1, le=500),
                before_id: int | None = None, ctx: Ctx = Depends(require("audit:read"))):
    pattern = event_type.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%") if event_type else None
    rows = ctx.db.all(
        "SELECT event_id, event_type, entity, entity_id, payload, request_id, created_at, dispatched_at "
        "FROM outbox_events WHERE (%(t)s::text IS NULL OR event_type LIKE %(t)s) "
        "AND (%(b)s::bigint IS NULL OR event_id < %(b)s) ORDER BY event_id DESC LIMIT %(l)s",
        {"t": pattern, "b": before_id, "l": limit})
    return {"items": rows, "next_before_id": rows[-1]["event_id"] if len(rows) == limit else None}


@router.get("/event-types", summary="Event types this service emits")
def event_types(ctx: Ctx = Depends(require("settings:read"))):
    entities = ["customer", "product", "order", "order_item", "payment", "external_event", "change_request",
                "user", "api_key", "webhook", "source", "settings", "organization"]
    return {"items": sorted([f"{e}.{v}" for e in entities for v in ("created", "updated", "deleted")] + [
        "order.status_changed", "change_request.submitted", "change_request.approved", "change_request.rejected",
        "alert.raised", "reconciliation.completed", "audit.checkpoint", "audit.integrity_failed",
        "security.refresh_token_reuse", "webhook.test"])}


# ---- dashboard ------------------------------------------------------------------------
@router.get("/dashboard", tags=["dashboard"], summary="Key metrics for the organization")
def dashboard(ctx: Ctx = Depends(require("orders:read"))):
    db = ctx.db
    counts = db.one("""
        SELECT (SELECT count(*) FROM customers) AS customers,
               (SELECT count(*) FROM products WHERE active) AS active_products,
               (SELECT count(*) FROM orders) AS orders,
               (SELECT COALESCE(sum(total_amount), 0) FROM orders WHERE status IN ('PAID','SHIPPED','DELIVERED')) AS revenue,
               (SELECT COALESCE(sum(amount), 0) FROM payments WHERE status = 'REFUNDED') AS refunded,
               (SELECT count(*) FROM alerts WHERE status = 'OPEN') AS open_alerts,
               (SELECT count(*) FROM change_requests WHERE status = 'PENDING') AS pending_approvals,
               (SELECT COALESCE(last_seq, 0) FROM audit_chain_head) AS audit_records,
               (SELECT count(*) FROM sources WHERE status = 'ACTIVE') AS sources,
               (SELECT count(*) FROM external_events) AS external_events,
               (SELECT count(*) FROM webhook_deliveries WHERE status IN ('FAILED','DEAD')) AS failing_deliveries""")
    return {
        "counts": counts,
        "currency": db.scalar("SELECT currency FROM tenant_settings"),
        "orders_by_status": db.all("SELECT status, count(*) AS n, COALESCE(sum(total_amount),0) AS amount "
                                   "FROM orders GROUP BY status ORDER BY status"),
        "alerts_by_severity": db.all("SELECT severity, count(*) AS n FROM alerts WHERE status = 'OPEN' GROUP BY severity"),
        "revenue_by_day": db.all(
            "SELECT created_at::date AS day, count(*) AS orders, COALESCE(sum(total_amount),0) AS amount FROM orders "
            "WHERE status IN ('PAID','SHIPPED','DELIVERED') AND created_at >= now() - interval '14 days' "
            "GROUP BY 1 ORDER BY 1"),
        "top_products": db.all(
            "SELECT p.product_id, p.name, sum(i.quantity) AS units, sum(i.line_total) AS amount FROM order_items i "
            "JOIN products p ON p.product_id = i.product_id JOIN orders o ON o.order_id = i.order_id "
            "WHERE o.status IN ('PAID','SHIPPED','DELIVERED') GROUP BY p.product_id, p.name ORDER BY amount DESC LIMIT 5"),
        "top_actors": db.all("SELECT actor, count(*) AS changes FROM audit_log WHERE changed_at >= now() - interval '30 days' "
                             "GROUP BY actor ORDER BY changes DESC LIMIT 5"),
        "recent_activity": db.all(
            "SELECT audit_id, chain_seq, entity, record_pk, operation, actor, changed_at, request_id FROM audit_log "
            "ORDER BY chain_seq DESC LIMIT 10"),
        "latest_checkpoint": db.one("SELECT chain_seq, created_at FROM audit_checkpoints ORDER BY chain_seq DESC LIMIT 1"),
    }
