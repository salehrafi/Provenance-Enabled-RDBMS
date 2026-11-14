from __future__ import annotations

from decimal import Decimal
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from app.auth import Ctx, require, require_user
from app.common import page
from app.db import Db
from app.errors import ApiError, not_found
from app.schemas import OrderCreate, OrderItemIn, OrderItemUpdate, OrderStatus, PaymentIn, StatusChange
from app.services import idempotency

router = APIRouter(prefix="/orders", tags=["orders"])

_ORDER_SQL = """
    SELECT o.order_id, o.customer_id, c.name AS customer_name, o.status, o.total_amount, o.currency,
           o.notes, o.created_at, o.updated_at,
           (SELECT count(*) FROM order_items i WHERE i.order_id = o.order_id) AS item_count,
           (SELECT COALESCE(sum(p.amount), 0) FROM payments p
             WHERE p.order_id = o.order_id AND p.status = 'CAPTURED') AS paid_amount
      FROM orders o JOIN customers c ON c.customer_id = o.customer_id
"""


def order_detail(db: Db, order_id: int) -> dict[str, Any]:
    order = db.one(_ORDER_SQL + " WHERE o.order_id = %s", (order_id,))
    if not order:
        raise not_found("Order")
    order["balance_due"] = max(order["total_amount"] - order["paid_amount"], Decimal(0))
    order["items"] = db.all(
        "SELECT i.product_id, p.sku, p.name, i.quantity, i.unit_price, i.line_total, p.price AS list_price "
        "FROM order_items i JOIN products p ON p.product_id = i.product_id WHERE i.order_id = %s ORDER BY p.name",
        (order_id,))
    order["payments"] = db.all(
        "SELECT payment_id, amount, method, status, reference, created_at FROM payments "
        "WHERE order_id = %s ORDER BY payment_id", (order_id,))
    order["allowed_transitions"] = [
        r["to_status"] for r in db.all(
            "SELECT to_status FROM order_status_transitions WHERE from_status = %s ORDER BY to_status",
            (order["status"],))]
    return order


def _lock_order(db: Db, order_id: int) -> dict[str, Any]:
    """Row lock: everything that changes an order is serialised per order."""
    row = db.one("SELECT order_id, status, total_amount FROM orders WHERE order_id = %s FOR UPDATE", (order_id,))
    if not row:
        raise not_found("Order")
    return row


def _add_item(db: Db, order_id: int, item: OrderItemIn) -> None:
    product = db.one("SELECT price, active, name FROM products WHERE product_id = %s", (item.product_id,))
    if not product:
        raise ApiError(422, f"Product {item.product_id} not found", "PRODUCT_NOT_FOUND")
    if not product["active"]:
        raise ApiError(422, f"Product '{product['name']}' is inactive", "PRODUCT_INACTIVE")
    # Without an override, the price is captured from the catalogue at order time.
    unit_price = item.unit_price if item.unit_price is not None else product["price"]
    db.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s, %s, %s, %s)",
               (order_id, item.product_id, item.quantity, unit_price))


@router.get("", summary="List orders")
def list_orders(
    status_: OrderStatus | None = Query(None, alias="status"),
    customer_id: int | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ctx: Ctx = Depends(require("orders:read")),
):
    conds: list[str] = []
    params: dict[str, Any] = {"lim": limit, "off": offset}
    if status_:
        conds.append("o.status = %(s)s")
        params["s"] = status_
    if customer_id:
        conds.append("o.customer_id = %(c)s")
        params["c"] = customer_id
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    rows = ctx.db.all(
        f"SELECT x.*, count(*) OVER () AS total_count FROM ({_ORDER_SQL}{where}) x "
        "ORDER BY x.order_id DESC LIMIT %(lim)s OFFSET %(off)s", params)
    return page(rows, limit, offset)


@router.post("", status_code=201, summary="Create an order (optionally with items)",
             description="Send an `Idempotency-Key` header to make retries safe.")
def create_order(body: OrderCreate, request: Request, ctx: Ctx = Depends(require_user("orders:write"))):
    db = ctx.db

    def work():
        if not db.scalar("SELECT count(*) FROM customers WHERE customer_id = %s", (body.customer_id,)):
            raise ApiError(422, "Customer not found", "CUSTOMER_NOT_FOUND")
        if len({i.product_id for i in body.items}) != len(body.items):
            raise ApiError(422, "Each product may appear only once per order", "DUPLICATE_PRODUCT")
        currency = db.scalar("SELECT currency FROM tenant_settings") or "USD"
        order_id = db.insert("INSERT INTO orders (customer_id, notes, currency) VALUES (%s, %s, %s)",
                             (body.customer_id, body.notes, currency), "order_id")
        for item in body.items:
            _add_item(db, order_id, item)
        return order_detail(db, order_id)

    return idempotency.run(ctx, request, body, 201, work)


@router.get("/{order_id}", summary="Get an order with items, payments and allowed status transitions")
def get_order(order_id: int, ctx: Ctx = Depends(require("orders:read"))):
    return order_detail(ctx.db, order_id)


@router.post("/{order_id}/items", status_code=201, summary="Add a line item")
def add_item(order_id: int, body: OrderItemIn, ctx: Ctx = Depends(require_user("orders:write"))):
    db = ctx.db
    _lock_order(db, order_id)
    if db.scalar("SELECT count(*) FROM order_items WHERE order_id = %s AND product_id = %s",
                 (order_id, body.product_id)):
        raise ApiError(409, "Product already on this order; update its quantity instead", "DUPLICATE_PRODUCT")
    _add_item(db, order_id, body)
    db.commit()
    return order_detail(db, order_id)


@router.put("/{order_id}/items/{product_id}", summary="Change quantity or unit price of a line item")
def update_item(order_id: int, product_id: int, body: OrderItemUpdate,
                ctx: Ctx = Depends(require_user("orders:write"))):
    db = ctx.db
    _lock_order(db, order_id)
    if body.unit_price is not None:
        n = db.execute("UPDATE order_items SET quantity = %s, unit_price = %s WHERE order_id = %s AND product_id = %s",
                       (body.quantity, body.unit_price, order_id, product_id))
    else:
        n = db.execute("UPDATE order_items SET quantity = %s WHERE order_id = %s AND product_id = %s",
                       (body.quantity, order_id, product_id))
    if not n:
        raise not_found("Order item")
    db.commit()
    return order_detail(db, order_id)


@router.delete("/{order_id}/items/{product_id}", summary="Remove a line item")
def delete_item(order_id: int, product_id: int, ctx: Ctx = Depends(require_user("orders:write"))):
    db = ctx.db
    _lock_order(db, order_id)
    if not db.execute("DELETE FROM order_items WHERE order_id = %s AND product_id = %s", (order_id, product_id)):
        raise not_found("Order item")
    db.commit()
    return order_detail(db, order_id)


@router.post("/{order_id}/payments", status_code=201,
             summary="Record a payment; the order becomes PAID when fully paid",
             description="Send an `Idempotency-Key` header to make retries safe.")
def add_payment(order_id: int, body: PaymentIn, request: Request, ctx: Ctx = Depends(require_user("orders:write"))):
    db = ctx.db

    def work():
        order = _lock_order(db, order_id)  # two concurrent payments cannot both pass the balance check
        if order["status"] != "CREATED":
            raise ApiError(409, f"Payments can only be added to CREATED orders (order is {order['status']})",
                           "ORDER_NOT_PAYABLE")
        if order["total_amount"] <= 0:
            raise ApiError(409, "Order has no items to pay for", "ORDER_NOT_PAYABLE")
        paid = db.scalar("SELECT COALESCE(sum(amount), 0) FROM payments WHERE order_id = %s AND status = 'CAPTURED'",
                         (order_id,))
        balance = order["total_amount"] - paid
        if body.amount > balance:
            raise ApiError(422, f"Amount exceeds balance due ({balance})", "PAYMENT_EXCEEDS_BALANCE")
        db.execute("INSERT INTO payments (order_id, amount, method, reference) VALUES (%s, %s, %s, %s)",
                   (order_id, body.amount, body.method, body.reference))
        if paid + body.amount >= order["total_amount"]:
            db.execute("UPDATE orders SET status = 'PAID' WHERE order_id = %s", (order_id,))
        return order_detail(db, order_id)

    return idempotency.run(ctx, request, body, 201, work)


@router.post("/{order_id}/status", summary="Move the order through its lifecycle",
             description="The database enforces the allowed transitions (409 `ORDER_INVALID_TRANSITION`). "
             "Refunding also marks captured payments as REFUNDED.")
def change_status(order_id: int, body: StatusChange, ctx: Ctx = Depends(require_user("orders:write"))):
    db = ctx.db
    _lock_order(db, order_id)
    db.execute("UPDATE orders SET status = %s WHERE order_id = %s", (body.status, order_id))
    if body.status == "REFUNDED":
        db.execute("UPDATE payments SET status = 'REFUNDED' WHERE order_id = %s AND status = 'CAPTURED'", (order_id,))
    db.commit()
    return order_detail(db, order_id)
