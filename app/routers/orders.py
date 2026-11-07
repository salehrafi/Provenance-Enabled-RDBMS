from __future__ import annotations

from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.common import not_found, paginate
from app.db import Db
from app.deps import CurrentUser, get_db, staff, viewer
from app.schemas import OrderCreate, OrderItemIn, OrderItemUpdate, PaymentIn, StatusChange

router = APIRouter(prefix="/orders", tags=["orders"])

_ORDER_SQL = """
    SELECT o.order_id, o.customer_id, c.name AS customer_name, o.status, o.total_amount, o.currency,
           o.notes, o.created_at, o.updated_at,
           (SELECT COUNT(*) FROM order_items i WHERE i.order_id = o.order_id) AS item_count,
           (SELECT NVL(SUM(p.amount), 0) FROM payments p
             WHERE p.order_id = o.order_id AND p.status = 'CAPTURED') AS paid_amount
      FROM orders o JOIN customers c ON c.customer_id = o.customer_id
"""


def order_detail(db: Db, order_id: int) -> dict:
    order = db.one(_ORDER_SQL + " WHERE o.order_id = :id", {"id": order_id})
    if not order:
        raise not_found("Order")
    order["balance_due"] = max(order["total_amount"] - order["paid_amount"], Decimal(0))
    order["items"] = db.all(
        "SELECT i.product_id, p.sku, p.name, i.quantity, i.unit_price, i.line_total, p.price AS list_price "
        "FROM order_items i JOIN products p ON p.product_id = i.product_id WHERE i.order_id = :id ORDER BY p.name",
        {"id": order_id},
    )
    order["payments"] = db.all(
        "SELECT payment_id, amount, method, status, reference, created_at FROM payments "
        "WHERE order_id = :id ORDER BY payment_id",
        {"id": order_id},
    )
    order["allowed_transitions"] = [
        r["to_status"]
        for r in db.all("SELECT to_status FROM order_status_transitions WHERE from_status = :s ORDER BY to_status",
                        {"s": order["status"]})
    ]
    return order


def _lock_order(db: Db, order_id: int) -> dict:
    row = db.one("SELECT order_id, status, total_amount FROM orders WHERE order_id = :id FOR UPDATE", {"id": order_id})
    if not row:
        raise not_found("Order")
    return row


def _add_item(db: Db, order_id: int, item: OrderItemIn) -> None:
    product = db.one("SELECT price, active_flag, name FROM products WHERE product_id = :id", {"id": item.product_id})
    if not product:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Product {item.product_id} not found")
    if product["active_flag"] != "Y":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Product '{product['name']}' is inactive")
    # Without an override, the price is captured from the catalogue at order time.
    unit_price = item.unit_price if item.unit_price is not None else product["price"]
    db.execute(
        "INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (:o, :p, :q, :u)",
        {"o": order_id, "p": item.product_id, "q": item.quantity, "u": unit_price},
    )


@router.get("", summary="List orders")
def list_orders(
    status_: str | None = Query(None, alias="status"),
    customer_id: int | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(viewer),
    db: Db = Depends(get_db),
):
    conds, params = [], {"lim": limit, "off": offset}
    if status_:
        conds.append("o.status = :s")
        params["s"] = status_.upper()
    if customer_id:
        conds.append("o.customer_id = :c")
        params["c"] = customer_id
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    rows = db.all(
        f"SELECT x.*, COUNT(*) OVER () AS total_count FROM ({_ORDER_SQL}{where}) x "
        "ORDER BY x.order_id DESC OFFSET :off ROWS FETCH NEXT :lim ROWS ONLY",
        params,
    )
    return paginate(rows, limit, offset)


@router.post("", status_code=status.HTTP_201_CREATED, summary="Create an order (optionally with items)")
def create_order(body: OrderCreate, user: CurrentUser = Depends(staff), db: Db = Depends(get_db)):
    if not db.scalar("SELECT COUNT(*) FROM customers WHERE customer_id = :id", {"id": body.customer_id}):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Customer not found")
    if len({i.product_id for i in body.items}) != len(body.items):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Each product may appear only once per order")
    currency = db.scalar("SELECT currency FROM tenant_settings") or "USD"
    order_id = db.insert(
        "INSERT INTO orders (customer_id, notes, currency) VALUES (:c, :n, :cur)",
        {"c": body.customer_id, "n": body.notes, "cur": currency},
        "order_id",
    )
    for item in body.items:
        _add_item(db, order_id, item)
    db.commit()
    return order_detail(db, order_id)


@router.get("/{order_id}", summary="Get an order with items, payments and allowed status transitions")
def get_order(order_id: int, user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    return order_detail(db, order_id)


@router.post("/{order_id}/items", status_code=status.HTTP_201_CREATED, summary="Add a line item")
def add_item(order_id: int, body: OrderItemIn, user: CurrentUser = Depends(staff), db: Db = Depends(get_db)):
    _lock_order(db, order_id)
    if db.scalar("SELECT COUNT(*) FROM order_items WHERE order_id = :o AND product_id = :p",
                 {"o": order_id, "p": body.product_id}):
        raise HTTPException(status.HTTP_409_CONFLICT, "Product already on this order; update its quantity instead")
    _add_item(db, order_id, body)
    db.commit()
    return order_detail(db, order_id)


@router.put("/{order_id}/items/{product_id}", summary="Change quantity or unit price of a line item")
def update_item(order_id: int, product_id: int, body: OrderItemUpdate, user: CurrentUser = Depends(staff),
                db: Db = Depends(get_db)):
    _lock_order(db, order_id)
    sets, params = ["quantity = :q"], {"q": body.quantity, "o": order_id, "p": product_id}
    if body.unit_price is not None:
        sets.append("unit_price = :u")
        params["u"] = body.unit_price
    if not db.execute(f"UPDATE order_items SET {', '.join(sets)} WHERE order_id = :o AND product_id = :p", params):
        raise not_found("Order item")
    db.commit()
    return order_detail(db, order_id)


@router.delete("/{order_id}/items/{product_id}", summary="Remove a line item")
def delete_item(order_id: int, product_id: int, user: CurrentUser = Depends(staff), db: Db = Depends(get_db)):
    _lock_order(db, order_id)
    if not db.execute("DELETE FROM order_items WHERE order_id = :o AND product_id = :p",
                      {"o": order_id, "p": product_id}):
        raise not_found("Order item")
    db.commit()
    return order_detail(db, order_id)


@router.post("/{order_id}/payments", status_code=status.HTTP_201_CREATED,
             summary="Record a payment; the order becomes PAID when fully paid")
def add_payment(order_id: int, body: PaymentIn, user: CurrentUser = Depends(staff), db: Db = Depends(get_db)):
    order = _lock_order(db, order_id)  # row lock prevents two concurrent payments over-paying
    if order["status"] != "CREATED":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Payments can only be added to CREATED orders (order is {order['status']})")
    if order["total_amount"] <= 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "Order has no items to pay for")
    paid = db.scalar("SELECT NVL(SUM(amount), 0) FROM payments WHERE order_id = :o AND status = 'CAPTURED'",
                     {"o": order_id})
    balance = order["total_amount"] - paid
    if body.amount > balance:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Amount exceeds balance due ({balance})")
    db.execute(
        "INSERT INTO payments (order_id, amount, method, reference) VALUES (:o, :a, :m, :r)",
        {"o": order_id, "a": body.amount, "m": body.method, "r": body.reference},
    )
    if paid + body.amount >= order["total_amount"]:
        db.execute("UPDATE orders SET status = 'PAID', updated_at = SYS_EXTRACT_UTC(SYSTIMESTAMP) WHERE order_id = :o",
                   {"o": order_id})
    db.commit()
    return order_detail(db, order_id)


@router.post("/{order_id}/status", summary="Move the order through its lifecycle",
             description="The database enforces the allowed transitions (ORA-20001 becomes HTTP 409). "
             "Refunding also marks captured payments as REFUNDED.")
def change_status(order_id: int, body: StatusChange, user: CurrentUser = Depends(staff), db: Db = Depends(get_db)):
    _lock_order(db, order_id)
    db.execute("UPDATE orders SET status = :s, updated_at = SYS_EXTRACT_UTC(SYSTIMESTAMP) WHERE order_id = :o",
               {"s": body.status, "o": order_id})
    if body.status == "REFUNDED":
        db.execute("UPDATE payments SET status = 'REFUNDED' WHERE order_id = :o AND status = 'CAPTURED'", {"o": order_id})
    db.commit()
    return order_detail(db, order_id)
