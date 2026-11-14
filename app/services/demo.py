"""Demo data for local development: two organizations with orders, an approval, an external
source with events, alerts, and a change made directly in the database.

Idempotent: does nothing if the demo organization already exists. Refuses to run in production.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta

from app.config import get_settings
from app.db import close_pool, system_session, tenant_session
from app.security import hash_password, new_api_key, sha256_hex
from app.services import integrity, rules

ORGS = [
    ("Acme Retail", "acme", [("admin", "admin@acme.example.com", "Ada Admin"),
                             ("admin", "approver@acme.example.com", "Aaron Approver"),
                             ("staff", "staff@acme.example.com", "Sam Staff"),
                             ("auditor", "auditor@acme.example.com", "Alex Auditor"),
                             ("viewer", "viewer@acme.example.com", "Vic Viewer")]),
    ("Globex Trading", "globex", [("admin", "admin@globex.example.com", "Gina Globex")]),
]


def seed_demo() -> None:
    s = get_settings()
    if not s.is_dev:
        sys.exit("Demo data is for development only (ENVIRONMENT is not development).")
    if not s.demo_password:
        sys.exit("Set DEMO_PASSWORD in .env first (python -m app.cli init does this).")
    pw = hash_password(s.demo_password)
    created: dict[str, tuple[int, dict[str, int]]] = {}
    for name, slug, users in ORGS:
        with system_session() as db:
            if db.scalar("SELECT 1 FROM prov.auth_user_by_email(%s)", (users[0][1],)):
                print(f"  {name}: already exists")
                continue
            first = users[0]
            org = db.one("SELECT * FROM prov.create_organization(%s, %s, %s, %s, %s, 'seed')",
                         (name, f"{slug}-demo", first[1], first[2], pw))
            db.commit()
        assert org
        ids = {first[1]: org["user_id"]}
        with tenant_session(org["tenant_id"], org["user_id"], first[1], "seed") as db:
            for role, email, full in users[1:]:
                ids[email] = db.insert("INSERT INTO users (email, full_name, password_hash, role) VALUES (%s, %s, %s, %s)",
                                       (email, full, pw, role), "user_id")
            db.commit()
        created[slug] = (org["tenant_id"], ids)
        print(f"  {name}: created ({len(users)} users)")

    if "acme" in created:
        _seed_acme(*created["acme"])
    if created:
        print(f"  demo password: {s.demo_password}")


def _seed_acme(tid: int, ids: dict[str, int]) -> None:
    admin, approver, staff = "admin@acme.example.com", "approver@acme.example.com", "staff@acme.example.com"
    with tenant_session(tid, ids[staff], staff, "seed-catalog") as db:
        cust = [db.insert("INSERT INTO customers (name, email, phone) VALUES (%s, %s, %s)", (n, e, p), "customer_id")
                for n, e, p in (("Northwind Cafe", "orders@northwind.example", "+1 555 0101"),
                                ("Blue Harbor Co", "buy@blueharbor.example", None),
                                ("Kite & Co", "hello@kite.example", "+1 555 0133"))]
        prods = {sku: db.insert("INSERT INTO products (sku, name, price) VALUES (%s, %s, %s)", (sku, n, p), "product_id")
                 for sku, n, p in (("LAP-14", "Laptop 14in", 1099.99), ("MON-27", "Monitor 27in", 299.00),
                                   ("KEY-MX", "Mechanical keyboard", 150.00), ("MSE-01", "Wireless mouse", 39.50))}
        db.commit()
    with tenant_session(tid, ids[staff], staff, "seed-orders-1") as db:
        o1 = db.insert("INSERT INTO orders (customer_id, notes) VALUES (%s, 'Office refresh')", (cust[0],), "order_id")
        db.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s,%s,1,1099.99)", (o1, prods["LAP-14"]))
        db.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s,%s,2,150.00)", (o1, prods["KEY-MX"]))
        db.commit()
    with tenant_session(tid, ids[staff], staff, "seed-orders-2") as db:
        db.execute("UPDATE order_items SET quantity = 3 WHERE order_id = %s AND product_id = %s", (o1, prods["KEY-MX"]))
        db.commit()
    with tenant_session(tid, ids[staff], staff, "seed-orders-3") as db:
        o2 = db.insert("INSERT INTO orders (customer_id) VALUES (%s)", (cust[1],), "order_id")
        db.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s,%s,4,299.00)", (o2, prods["MON-27"]))
        db.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s,%s,10,20.00)", (o2, prods["MSE-01"]))
        db.execute("INSERT INTO payments (order_id, amount, method) VALUES (%s, 1396.00, 'BANK')", (o2,))
        db.execute("UPDATE orders SET status = 'PAID' WHERE order_id = %s", (o2,))
        db.commit()
    with tenant_session(tid, ids[staff], staff, "seed-approval") as db:
        pid = prods["MON-27"]
        db.insert(
            "INSERT INTO change_requests (entity, entity_id, change_type, payload, reason, requested_by_id, requested_by) "
            "VALUES ('product', %s, 'PRICE_CHANGE', %s::jsonb, 'Supplier cost increase', %s, %s)",
            (str(pid), '{"old_price": 299.00, "new_price": 399.00, "change_pct": 33.44}', ids[staff], staff),
            "change_request_id")
        db.commit()
    # An out-of-band change: made straight in the database by the schema owner would be flagged
    # by AN005; here the app role edits a price without a human actor.
    with tenant_session(tid, None, None, None) as db:
        db.execute("UPDATE products SET price = 120.00 WHERE product_id = %s", (prods["KEY-MX"],))
        db.commit()
    # An external source with a short history, and an API key to send more.
    with tenant_session(tid, ids[admin], admin, "seed-source") as db:
        db.execute("INSERT INTO sources (code, name, capture_method, trust_level) VALUES ('legacy-shop', 'Legacy shop (CDC)', 'CDC', 'HIGH')")
        key_id, secret, token = new_api_key()
        db.execute("INSERT INTO api_keys (key_id, name, secret_hash, scopes, created_by) VALUES (%s, 'legacy-connector', %s, %s, %s)",
                   (key_id, sha256_hex(secret), ["events:write", "events:read"], admin))
        db.commit()
        print(f"  demo API key (shown once): {token}")
    with tenant_session(tid, None, "apikey:legacy-connector", "seed-events") as db:
        base = datetime.now(UTC) - timedelta(days=3)
        for i, (op, before, after) in enumerate([
                ("c", None, {"status": "NEW", "total": "1500.00"}),
                ("u", {"status": "NEW", "total": "1500.00"}, {"status": "NEW", "total": "1200.00"}),
                ("u", {"status": "NEW", "total": "1200.00"}, {"status": "SHIPPED", "total": "1200.00"})]):
            when = base + timedelta(hours=i * 20)
            from app.schemas import CloudEventIn
            from app.services.ingestion import ingest_one
            ingest_one(db, CloudEventIn(specversion="1.0", id=f"seed-{i}", source="legacy-shop",
                                        type="order.updated" if op == "u" else "order.created", subject="order/10045",
                                        time=when, data={"op": op, "before": before, "after": after}))
        db.commit()
    with tenant_session(tid, ids[approver], approver, "seed-rules") as db:
        rules.run_rules(db, tid)
    with tenant_session(tid, None, "system:seed", "seed-checkpoint") as db:
        integrity.create_checkpoint(db, tid)


if __name__ == "__main__":
    try:
        seed_demo()
    finally:
        close_pool()
