from __future__ import annotations

from decimal import Decimal
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response

from app.auth import Ctx, require, require_user
from app.common import emit_event, page, update_set
from app.db import Db, jsonb
from app.errors import not_found
from app.schemas import CustomerIn, CustomerUpdate, ProductIn, ProductUpdate
from app.services import idempotency

router = APIRouter(tags=["catalog"])


def _like(term: str) -> str:
    """Escape LIKE wildcards so a search for '50%' means the literal text."""
    return "%" + term.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


# ---- customers ------------------------------------------------------------------------
_CUSTOMER_SQL = """
    SELECT c.customer_id, c.name, c.email, c.phone, c.created_at,
           (SELECT count(*) FROM orders o WHERE o.customer_id = c.customer_id) AS order_count,
           (SELECT COALESCE(sum(o.total_amount), 0) FROM orders o
             WHERE o.customer_id = c.customer_id AND o.status IN ('PAID', 'SHIPPED', 'DELIVERED')) AS lifetime_value
      FROM customers c
"""


def _customer(db: Db, customer_id: int) -> dict[str, Any]:
    row = db.one(_CUSTOMER_SQL + " WHERE c.customer_id = %s", (customer_id,))
    if not row:
        raise not_found("Customer")
    return row


@router.get("/customers", summary="List customers")
def list_customers(
    search: str | None = Query(None, max_length=100),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ctx: Ctx = Depends(require("catalog:read")),
):
    where = ""
    params: dict[str, Any] = {"lim": limit, "off": offset}
    if search:
        where = " WHERE lower(c.name) LIKE %(q)s OR lower(c.email) LIKE %(q)s"
        params["q"] = _like(search)
    rows = ctx.db.all(
        f"SELECT x.*, count(*) OVER () AS total_count FROM ({_CUSTOMER_SQL}{where}) x "
        "ORDER BY x.customer_id DESC LIMIT %(lim)s OFFSET %(off)s", params)
    return page(rows, limit, offset)


@router.post("/customers", status_code=201, summary="Create a customer")
def create_customer(body: CustomerIn, request: Request, ctx: Ctx = Depends(require_user("catalog:write"))):
    def work():
        new_id = ctx.db.insert("INSERT INTO customers (name, email, phone) VALUES (%s, %s, %s)",
                               (body.name, body.email.lower(), body.phone), "customer_id")
        return _customer(ctx.db, new_id)

    return idempotency.run(ctx, request, body, 201, work)


@router.get("/customers/{customer_id}", summary="Get a customer")
def get_customer(customer_id: int, ctx: Ctx = Depends(require("catalog:read"))):
    return _customer(ctx.db, customer_id)


@router.patch("/customers/{customer_id}", summary="Update a customer")
def update_customer(customer_id: int, body: CustomerUpdate, ctx: Ctx = Depends(require_user("catalog:write"))):
    _customer(ctx.db, customer_id)
    fields = body.model_dump(exclude_unset=True)
    if fields.get("email"):
        fields["email"] = fields["email"].lower()
    for required in ("name", "email"):
        if required in fields and fields[required] is None:
            fields.pop(required)
    sets, params = update_set(fields, {"name": "name", "email": "email", "phone": "phone"})
    if sets:
        ctx.db.execute(f"UPDATE customers SET {sets} WHERE customer_id = %(id)s", {**params, "id": customer_id})
        ctx.db.commit()
    return _customer(ctx.db, customer_id)


@router.delete("/customers/{customer_id}", status_code=204, summary="Delete a customer (only if they have no orders)")
def delete_customer(customer_id: int, ctx: Ctx = Depends(require_user("catalog:delete"))):
    # A customer with orders violates fk_orders_customer -> 409 REFERENCE_VIOLATION.
    if not ctx.db.execute("DELETE FROM customers WHERE customer_id = %s", (customer_id,)):
        raise not_found("Customer")
    ctx.db.commit()
    return Response(status_code=204)


# ---- products -------------------------------------------------------------------------
_PRODUCT_SQL = """
    SELECT p.product_id, p.sku, p.name, p.price, p.active, p.created_at,
           (SELECT count(*) FROM change_requests r
             WHERE r.entity = 'product' AND r.entity_id = p.product_id::text AND r.status = 'PENDING')
             AS pending_changes
      FROM products p
"""


def _product(db: Db, product_id: int) -> dict[str, Any]:
    row = db.one(_PRODUCT_SQL + " WHERE p.product_id = %s", (product_id,))
    if not row:
        raise not_found("Product")
    return row


@router.get("/products", summary="List products")
def list_products(
    search: str | None = Query(None, max_length=100),
    active: bool | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ctx: Ctx = Depends(require("catalog:read")),
):
    conds: list[str] = []
    params: dict[str, Any] = {"lim": limit, "off": offset}
    if search:
        conds.append("(lower(p.name) LIKE %(q)s OR lower(p.sku) LIKE %(q)s)")
        params["q"] = _like(search)
    if active is not None:
        conds.append("p.active = %(a)s")
        params["a"] = active
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    rows = ctx.db.all(
        f"SELECT x.*, count(*) OVER () AS total_count FROM ({_PRODUCT_SQL}{where}) x "
        "ORDER BY x.product_id DESC LIMIT %(lim)s OFFSET %(off)s", params)
    return page(rows, limit, offset)


@router.post("/products", status_code=201, summary="Create a product")
def create_product(body: ProductIn, request: Request, ctx: Ctx = Depends(require_user("catalog:write"))):
    def work():
        new_id = ctx.db.insert("INSERT INTO products (sku, name, price, active) VALUES (%s, %s, %s, %s)",
                               (body.sku, body.name, body.price, body.active), "product_id")
        return _product(ctx.db, new_id)

    return idempotency.run(ctx, request, body, 201, work)


@router.get("/products/{product_id}", summary="Get a product")
def get_product(product_id: int, ctx: Ctx = Depends(require("catalog:read"))):
    return _product(ctx.db, product_id)


@router.patch(
    "/products/{product_id}",
    summary="Update a product",
    description="A price change at or above the organization's approval threshold is not applied. It creates a "
    "pending change request (HTTP 202) that a different admin must approve.",
)
def update_product(product_id: int, body: ProductUpdate, response: Response,
                   ctx: Ctx = Depends(require_user("catalog:write"))):
    db, user = ctx.db, ctx.principal
    # Row lock: the percentage is computed against a price nobody else can change meanwhile.
    current = db.one("SELECT product_id, price FROM products WHERE product_id = %s FOR UPDATE", (product_id,))
    if not current:
        raise not_found("Product")

    fields: dict[str, Any] = {}
    if body.name is not None:
        fields["name"] = body.name
    if body.active is not None:
        fields["active"] = body.active

    change_request = None
    if body.price is not None and body.price != current["price"]:
        old_price: Decimal = current["price"]
        pct = (abs(body.price - old_price) / old_price * 100) if old_price else Decimal(100)
        threshold = db.scalar("SELECT approval_price_change_pct FROM tenant_settings")
        if threshold is not None and pct >= threshold:
            payload = {"old_price": old_price, "new_price": body.price, "change_pct": round(pct, 2)}
            cr_id = db.insert(
                "INSERT INTO change_requests (entity, entity_id, change_type, payload, reason, requested_by_id, requested_by) "
                "VALUES ('product', %s, 'PRICE_CHANGE', %s, %s, %s, %s)",
                (str(product_id), jsonb(payload), body.reason, user.user_id, user.email), "change_request_id")
            emit_event(db, "change_request.submitted", "change_request", cr_id,
                       {"change_request_id": cr_id, "product_id": product_id, **payload, "requested_by": user.email})
            change_request = {"change_request_id": cr_id, "status": "PENDING", **payload,
                              "message": f"Price change of {round(pct, 1)}% needs approval (threshold {threshold}%)"}
        else:
            fields["price"] = body.price

    sets, params = update_set(fields, {"name": "name", "active": "active", "price": "price"})
    if sets:
        db.execute(f"UPDATE products SET {sets} WHERE product_id = %(id)s", {**params, "id": product_id})
    db.commit()

    result = _product(db, product_id)
    if change_request:
        response.status_code = 202
        result["pending_change_request"] = change_request
    return result
