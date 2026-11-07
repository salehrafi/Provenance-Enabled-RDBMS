from __future__ import annotations

from decimal import Decimal

from fastapi import APIRouter, Depends, Query, Response, status

from app.common import dumps, emit_event, not_found, paginate, update_set
from app.db import Db
from app.deps import CurrentUser, admin, get_db, staff, viewer
from app.schemas import CustomerIn, CustomerUpdate, ProductIn, ProductUpdate

router = APIRouter(tags=["catalog"])


# ---- customers ------------------------------------------------------------------------
_CUSTOMER_SQL = """
    SELECT c.customer_id, c.name, c.email, c.phone, c.created_at,
           (SELECT COUNT(*) FROM orders o WHERE o.customer_id = c.customer_id) AS order_count,
           (SELECT NVL(SUM(o.total_amount), 0) FROM orders o
             WHERE o.customer_id = c.customer_id AND o.status IN ('PAID', 'SHIPPED', 'DELIVERED')) AS lifetime_value
      FROM customers c
"""


def _customer(db: Db, customer_id: int) -> dict:
    row = db.one(_CUSTOMER_SQL + " WHERE c.customer_id = :id", {"id": customer_id})
    if not row:
        raise not_found("Customer")
    return row


@router.get("/customers", summary="List customers")
def list_customers(
    search: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(viewer),
    db: Db = Depends(get_db),
):
    where, params = "", {"lim": limit, "off": offset}
    if search:
        where = " WHERE LOWER(c.name) LIKE :q OR LOWER(c.email) LIKE :q"
        params["q"] = f"%{search.lower()}%"
    rows = db.all(
        f"SELECT x.*, COUNT(*) OVER () AS total_count FROM ({_CUSTOMER_SQL}{where}) x "
        "ORDER BY x.customer_id DESC OFFSET :off ROWS FETCH NEXT :lim ROWS ONLY",
        params,
    )
    return paginate(rows, limit, offset)


@router.post("/customers", status_code=status.HTTP_201_CREATED, summary="Create a customer")
def create_customer(body: CustomerIn, user: CurrentUser = Depends(staff), db: Db = Depends(get_db)):
    new_id = db.insert(
        "INSERT INTO customers (name, email, phone) VALUES (:n, :e, :p)",
        {"n": body.name, "e": body.email.lower(), "p": body.phone},
        "customer_id",
    )
    db.commit()
    return _customer(db, new_id)


@router.get("/customers/{customer_id}", summary="Get a customer")
def get_customer(customer_id: int, user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    return _customer(db, customer_id)


@router.patch("/customers/{customer_id}", summary="Update a customer")
def update_customer(customer_id: int, body: CustomerUpdate, user: CurrentUser = Depends(staff), db: Db = Depends(get_db)):
    _customer(db, customer_id)
    fields = body.model_dump(exclude_none=True)
    if "email" in fields:
        fields["email"] = fields["email"].lower()
    sets, params = update_set(fields, {"name": "name", "email": "email", "phone": "phone"})
    if sets:
        db.execute(f"UPDATE customers SET {sets} WHERE customer_id = :id", {**params, "id": customer_id})
        db.commit()
    return _customer(db, customer_id)


@router.delete("/customers/{customer_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a customer")
def delete_customer(customer_id: int, user: CurrentUser = Depends(admin), db: Db = Depends(get_db)):
    if not db.execute("DELETE FROM customers WHERE customer_id = :id", {"id": customer_id}):
        raise not_found("Customer")
    db.commit()  # ORA-02292 (has orders) becomes 409 via the global handler
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---- products -------------------------------------------------------------------------
_PRODUCT_SQL = """
    SELECT p.product_id, p.sku, p.name, p.price, p.active_flag, p.created_at,
           (SELECT COUNT(*) FROM change_requests r
             WHERE r.entity = 'product' AND r.entity_id = TO_CHAR(p.product_id) AND r.status = 'PENDING')
             AS pending_changes
      FROM products p
"""


def _product(db: Db, product_id: int) -> dict:
    row = db.one(_PRODUCT_SQL + " WHERE p.product_id = :id", {"id": product_id})
    if not row:
        raise not_found("Product")
    row["active"] = row.pop("active_flag") == "Y"
    return row


@router.get("/products", summary="List products")
def list_products(
    search: str | None = None,
    active: bool | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(viewer),
    db: Db = Depends(get_db),
):
    conds, params = [], {"lim": limit, "off": offset}
    if search:
        conds.append("(LOWER(p.name) LIKE :q OR LOWER(p.sku) LIKE :q)")
        params["q"] = f"%{search.lower()}%"
    if active is not None:
        conds.append("p.active_flag = :a")
        params["a"] = "Y" if active else "N"
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    rows = db.all(
        f"SELECT x.*, COUNT(*) OVER () AS total_count FROM ({_PRODUCT_SQL}{where}) x "
        "ORDER BY x.product_id DESC OFFSET :off ROWS FETCH NEXT :lim ROWS ONLY",
        params,
    )
    for r in rows:
        r["active"] = r.pop("active_flag") == "Y"
    return paginate(rows, limit, offset)


@router.post("/products", status_code=status.HTTP_201_CREATED, summary="Create a product")
def create_product(body: ProductIn, user: CurrentUser = Depends(staff), db: Db = Depends(get_db)):
    new_id = db.insert(
        "INSERT INTO products (sku, name, price, active_flag) VALUES (:s, :n, :p, :a)",
        {"s": body.sku, "n": body.name, "p": body.price, "a": "Y" if body.active else "N"},
        "product_id",
    )
    db.commit()
    return _product(db, new_id)


@router.get("/products/{product_id}", summary="Get a product")
def get_product(product_id: int, user: CurrentUser = Depends(viewer), db: Db = Depends(get_db)):
    return _product(db, product_id)


@router.patch(
    "/products/{product_id}",
    summary="Update a product",
    description="Price changes at or above the organization's approval threshold are not applied directly. "
    "They create a pending change request (HTTP 202) that a different admin must approve.",
)
def update_product(
    product_id: int,
    body: ProductUpdate,
    response: Response,
    user: CurrentUser = Depends(staff),
    db: Db = Depends(get_db),
):
    current = db.one("SELECT product_id, price FROM products WHERE product_id = :id FOR UPDATE", {"id": product_id})
    if not current:
        raise not_found("Product")

    fields: dict = {}
    if body.name is not None:
        fields["name"] = body.name
    if body.active is not None:
        fields["active_flag"] = "Y" if body.active else "N"

    change_request = None
    if body.price is not None and body.price != current["price"]:
        old_price: Decimal = current["price"]
        pct = (abs(body.price - old_price) / old_price * 100) if old_price else Decimal(100)
        threshold = db.scalar("SELECT approval_price_change_pct FROM tenant_settings")
        if threshold is not None and pct >= threshold:
            payload = {"old_price": old_price, "new_price": body.price, "change_pct": round(pct, 2)}
            cr_id = db.insert(
                "INSERT INTO change_requests (entity, entity_id, change_type, payload, reason, requested_by_id, requested_by) "
                "VALUES ('product', :id, 'PRICE_CHANGE', :p, :r, :actor_id, :u)",
                {"id": str(product_id), "p": dumps(payload), "r": body.reason, "actor_id": user.user_id, "u": user.email},
                "change_request_id",
            )
            emit_event(db, user.tenant_id, "change_request.created", "change_request", cr_id,
                       {"change_request_id": cr_id, "product_id": product_id, **payload, "requested_by": user.email})
            change_request = {"change_request_id": cr_id, "status": "PENDING", **payload,
                              "message": f"Price change of {round(pct, 1)}% needs approval (threshold {threshold}%)"}
        else:
            fields["price"] = body.price

    sets, params = update_set(fields, {"name": "name", "active_flag": "active_flag", "price": "price"})
    if sets:
        db.execute(f"UPDATE products SET {sets} WHERE product_id = :id", {**params, "id": product_id})
    db.commit()

    result = _product(db, product_id)
    if change_request:
        response.status_code = status.HTTP_202_ACCEPTED
        result["pending_change_request"] = change_request
    return result
