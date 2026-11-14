"""Sandbox: load clearly-labelled sample data into your own organization to explore the product."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends

from app.auth import Ctx, require_user
from app.errors import ApiError
from app.schemas import CloudEventIn
from app.services.ingestion import ingest_one
from app.services.rules import run_rules

router = APIRouter(prefix="/sandbox", tags=["sandbox"])

TAG = "[sample]"


@router.post("/sample-data", status_code=201, summary="Load sample customers, products, orders and events",
             description="Creates a small, realistic data set (marked `[sample]`) through the normal write paths, so "
             "every change is audited exactly like real data. Safe to call once per organization.")
def load_sample_data(ctx: Ctx = Depends(require_user("settings:manage"))):
    db = ctx.db
    if db.scalar("SELECT count(*) FROM products WHERE sku LIKE 'SAMPLE-%'"):
        raise ApiError(409, "Sample data is already loaded", "SAMPLE_DATA_EXISTS")
    customers = [db.insert("INSERT INTO customers (name, email, phone) VALUES (%s, %s, %s)", (n, e, p), "customer_id")
                 for n, e, p in ((f"Northwind Cafe {TAG}", "orders@northwind.sample", "+1 555 0101"),
                                 (f"Blue Harbor Co {TAG}", "buy@blueharbor.sample", None),
                                 (f"Kite & Co {TAG}", "hello@kite.sample", "+1 555 0133"))]
    prods = {sku: db.insert("INSERT INTO products (sku, name, price) VALUES (%s, %s, %s)", (sku, f"{n} {TAG}", p), "product_id")
             for sku, n, p in (("SAMPLE-LAP", "Laptop 14in", 1099.99), ("SAMPLE-MON", "Monitor 27in", 299.00),
                               ("SAMPLE-KEY", "Mechanical keyboard", 150.00), ("SAMPLE-MSE", "Wireless mouse", 39.50))}
    db.commit()

    o1 = db.insert("INSERT INTO orders (customer_id, notes) VALUES (%s, 'Office refresh')", (customers[0],), "order_id")
    db.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s, %s, 1, 1099.99)", (o1, prods["SAMPLE-LAP"]))
    db.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s, %s, 2, 150.00)", (o1, prods["SAMPLE-KEY"]))
    db.commit()
    db.execute("UPDATE order_items SET quantity = 3 WHERE order_id = %s AND product_id = %s", (o1, prods["SAMPLE-KEY"]))
    db.commit()
    o2 = db.insert("INSERT INTO orders (customer_id) VALUES (%s)", (customers[1],), "order_id")
    db.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s, %s, 4, 299.00)", (o2, prods["SAMPLE-MON"]))
    db.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s, %s, 10, 20.00)", (o2, prods["SAMPLE-MSE"]))
    db.commit()  # the mouse is sold at about half its list price: the deep-discount rule will flag it
    db.execute("INSERT INTO payments (order_id, amount, method) VALUES (%s, 1396.00, 'BANK')", (o2,))
    db.execute("UPDATE orders SET status = 'PAID' WHERE order_id = %s", (o2,))
    db.commit()

    db.execute("INSERT INTO sources (code, name, capture_method, trust_level) VALUES ('sample-shop', 'Sample shop (CDC)', 'CDC', 'HIGH') "
               "ON CONFLICT (tenant_id, code) DO NOTHING")
    base = datetime.now(UTC) - timedelta(days=3)
    cache: dict = {}
    for i, (op, before, after) in enumerate([
            ("c", None, {"status": "NEW", "total": "1500.00"}),
            ("u", {"status": "NEW", "total": "1500.00"}, {"status": "NEW", "total": "1200.00"}),
            ("u", {"status": "NEW", "total": "1200.00"}, {"status": "SHIPPED", "total": "1200.00"})]):
        ingest_one(db, CloudEventIn(specversion="1.0", id=f"sample-{ctx.tenant_id}-{i}", source="sample-shop",
                                    type="order.created" if op == "c" else "order.updated", subject="order/10045",
                                    time=base + timedelta(hours=i * 20),
                                    data={"op": op, "before": before, "after": after}), cache)
    db.commit()
    alerts = run_rules(db, ctx.tenant_id)
    return {"customers": len(customers), "products": len(prods), "orders": 2, "events": 3,
            "order_ids": [o1, o2], "new_alerts": alerts["new_alerts"],
            "message": "Sample data loaded. Open an order and choose Explain to see how its total was built."}
