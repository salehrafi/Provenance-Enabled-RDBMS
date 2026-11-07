"""Load a realistic demo dataset through the real API, so provenance shows real actors.

Creates two organizations (to demonstrate tenant isolation):
  * Acme Electronics   admin@acme.example.com, approver@acme.example.com (admins), staff@acme.example.com, viewer@acme.example.com
  * Globex Retail      admin@globex.example.com
All demo users share the password in .env (DEMO_PASSWORD).

Usage:  python scripts/seed.py [--base-url http://127.0.0.1:8000]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["WORKERS_ENABLED"] = "false"  # deliveries happen once the real server runs

import oracledb  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.main import app  # noqa: E402

S = get_settings()


def demo_password() -> str:
    from dotenv import dotenv_values

    value = dotenv_values(ROOT / ".env").get("DEMO_PASSWORD")
    if not value or value == "change-me":
        raise SystemExit("Set DEMO_PASSWORD in .env first (scripts/setup_db.py generates one).")
    return value


class Api:
    def __init__(self, client: TestClient, token: str | None = None):
        self.c, self.token = client, token

    def call(self, method: str, path: str, body=None, expect=(200, 201, 202, 204)):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        r = self.c.request(method, "/api/v1" + path, json=body, headers=headers)
        if r.status_code not in expect:
            raise SystemExit(f"{method} {path} -> {r.status_code}: {r.text}")
        return r.json() if r.content else None

    def login(self, email: str, password: str) -> "Api":
        return Api(self.c, self.call("POST", "/auth/login", {"email": email, "password": password})["access_token"])


def seed(base_url: str) -> None:
    pw = demo_password()
    with TestClient(app) as client:
        anon = Api(client)
        exists = client.post("/api/v1/auth/login", json={"email": "admin@acme.example.com", "password": pw})
        if exists.status_code == 200:
            print("Demo data already present (admin@acme.example.com exists). Use scripts/setup_db.py --reset to start over.")
            return

        # ---- Acme: users -------------------------------------------------------------
        signup = anon.call("POST", "/auth/signup", {"organization": "Acme Electronics", "full_name": "Ayesha Rahman",
                                                     "email": "admin@acme.example.com", "password": pw})
        admin = Api(client, signup["access_token"])
        tenant_id = signup["user"]["tenant"]["tenant_id"]
        for email, name, role in [("approver@acme.example.com", "Omar Faruk", "admin"), ("staff@acme.example.com", "Siyam Hossain", "staff"),
                                  ("viewer@acme.example.com", "Vera Auditor", "viewer")]:
            admin.call("POST", "/users", {"email": email, "full_name": name, "password": pw, "role": role})
        staff = anon.login("staff@acme.example.com", pw)
        approver = anon.login("approver@acme.example.com", pw)

        admin.call("POST", "/webhooks", {"url": f"{base_url}/api/v1/dev/webhook-sink",
                                         "event_types": ["order.*", "alert.raised", "change_request.*", "webhook.test"],
                                         "description": "Local development receiver"})

        # ---- catalogue ---------------------------------------------------------------
        p = {}
        for sku, name, price in [("LAP-14", "Laptop 14\"", "1000.00"), ("TAB-10", "Tablet 10\"", "500.00"),
                                 ("HP-PRO", "Headphones Pro", "150.00"), ("BUD-2", "Wireless Buds", "250.00"),
                                 ("MON-27", "Monitor 27\"", "320.00"), ("KB-MX", "Mechanical Keyboard", "80.00")]:
            p[sku] = staff.call("POST", "/products", {"sku": sku, "name": name, "price": price})["product_id"]
        staff.call("PATCH", f"/products/{p['LAP-14']}", {"price": "1099.99", "reason": "New model year"})  # +10%: direct

        c = {}
        for name, email, phone in [("Rafi Ahmed", "rafi@example.com", "+880 1711 000001"), ("Siyam Khan", "siyam@example.com", None),
                                   ("Sanim Islam", "sanim@example.com", None), ("Shakib Hasan", "shakib@example.com", "+880 1811 000004"),
                                   ("Nadia Chowdhury", "nadia@example.com", None), ("Tanvir Alam", "tanvir@example.com", None)]:
            c[name.split()[0]] = staff.call("POST", "/customers", {"name": name, "email": email, "phone": phone})["customer_id"]
        staff.call("PATCH", f"/customers/{c['Rafi']}", {"phone": "+880 1711 999999"})

        # ---- orders ------------------------------------------------------------------
        # Order: the classic story from the course project (why is the total 1549.99?)
        o1 = staff.call("POST", "/orders", {"customer_id": c["Rafi"], "notes": "Gift wrap",
                                            "items": [{"product_id": p["LAP-14"], "quantity": 1},
                                                      {"product_id": p["HP-PRO"], "quantity": 2}]})["order_id"]
        staff.call("PUT", f"/orders/{o1}/items/{p['HP-PRO']}", {"quantity": 3})
        staff.call("POST", f"/orders/{o1}/payments", {"amount": "1549.99", "method": "CARD", "reference": "VISA-4242"})
        staff.call("POST", f"/orders/{o1}/status", {"status": "SHIPPED"})
        admin.call("POST", f"/orders/{o1}/status", {"status": "DELIVERED"})

        o2 = staff.call("POST", "/orders", {"customer_id": c["Siyam"], "items": [{"product_id": p["BUD-2"], "quantity": 2},
                                                                                  {"product_id": p["KB-MX"], "quantity": 1}]})["order_id"]
        staff.call("POST", f"/orders/{o2}/payments", {"amount": "300.00", "method": "BKASH"})
        staff.call("POST", f"/orders/{o2}/payments", {"amount": "280.00", "method": "BKASH"})
        staff.call("POST", f"/orders/{o2}/status", {"status": "SHIPPED"})

        # Manual discount: flagged by the deep-discount rule (AN002)
        o3 = staff.call("POST", "/orders", {"customer_id": c["Sanim"], "notes": "Price match with competitor",
                                            "items": [{"product_id": p["MON-27"], "quantity": 1, "unit_price": "199.00"}]})["order_id"]
        staff.call("POST", f"/orders/{o3}/payments", {"amount": "199.00", "method": "NAGAD"})

        # Open cart
        o4 = staff.call("POST", "/orders", {"customer_id": c["Shakib"], "items": [{"product_id": p["TAB-10"], "quantity": 1}]})["order_id"]
        staff.call("POST", f"/orders/{o4}/items", {"product_id": p["HP-PRO"], "quantity": 1})

        # Large refund (AN003)
        o5 = staff.call("POST", "/orders", {"customer_id": c["Nadia"], "items": [{"product_id": p["LAP-14"], "quantity": 2}]})["order_id"]
        staff.call("POST", f"/orders/{o5}/payments", {"amount": "2199.98", "method": "CARD"})
        admin.call("POST", f"/orders/{o5}/status", {"status": "REFUNDED"})

        o6 = staff.call("POST", "/orders", {"customer_id": c["Tanvir"], "items": [{"product_id": p["KB-MX"], "quantity": 4}]})["order_id"]
        staff.call("POST", f"/orders/{o6}/status", {"status": "CANCELLED"})

        # ---- governance --------------------------------------------------------------
        # +32.7% price rise -> needs approval; approved by a different admin (AN001 notes the approval)
        cr = staff.call("PATCH", f"/products/{p['HP-PRO']}", {"price": "199.00", "reason": "Supplier cost increase"})
        approver.call("POST", f"/approvals/{cr['pending_change_request']['change_request_id']}/approve",
                      {"note": "Matches new supplier invoice"})
        # -52% price drop, left pending for the demo
        staff.call("PATCH", f"/products/{p['BUD-2']}", {"price": "120.00", "reason": "Clearance sale"})
        staff.call("PATCH", f"/products/{p['TAB-10']}", {"active": False})

        # Out-of-band change: someone edits a price directly in SQL as the schema owner (AN005)
        conn = oracledb.connect(user=S.db_owner_user, password=S.db_owner_password, dsn=S.db_dsn)
        with conn.cursor() as cur:
            cur.callproc("ctx_pkg.set_ctx", [tenant_id, None, None, None])
            cur.execute("UPDATE products SET price = 75 WHERE product_id = :id", {"id": p["KB-MX"]})
        conn.commit()
        conn.close()

        # ---- Integration: a legacy POS pushes CloudEvents, then reconciles -------------
        admin.call("POST", "/sources", {"code": "legacy-pos", "name": "Legacy point-of-sale", "capture_method": "CDC",
                                        "trust_level": "HIGH"})
        admin.call("POST", "/sources", {"code": "nightly-csv", "name": "Warehouse nightly export",
                                        "capture_method": "CSV_IMPORT", "trust_level": "LOW"})
        connector = Api(client, admin.call("POST", "/api-keys", {"name": "legacy-pos-connector",
                                                                 "scopes": ["events:write", "events:read"]})["api_key"])

        def ev(i, typ, ext, op, before, after, t):
            return {"specversion": "1.0", "id": f"pos-{i}", "source": "legacy-pos", "type": typ,
                    "subject": f"order/{ext}", "time": t, "data": {"op": op, "before": before, "after": after}}

        connector.call("POST", "/events:batch", [
            ev(1, "order.created", "L-1001", "c", None, {"status": "OPEN", "total": "1500.00"}, "2026-11-01T09:00:00Z"),
            ev(2, "order.updated", "L-1001", "u", {"status": "OPEN", "total": "1500.00"},
               {"status": "PAID", "total": "1200.00"}, "2026-11-01T09:30:00Z"),
            ev(3, "order.created", "L-1002", "c", None, {"status": "OPEN", "total": "640.00"}, "2026-11-02T11:00:00Z"),
            ev(4, "order.created", "L-1004", "c", None, {"status": "OPEN", "total": "99.00"}, "2026-11-03T08:15:00Z"),
        ])
        connector.call("POST", "/events", ev(2, "order.updated", "L-1001", "u", {}, {}, "2026-11-01T09:30:00Z"))  # retry: duplicate
        # Upstream's view today: L-1002's total changed without an event, L-1003 was never sent,
        # and L-1004 is gone upstream although no delete event arrived.
        connector.call("POST", "/reconciliations", {
            "source": "legacy-pos", "entity": "order", "complete": True,
            "records": [{"external_id": "L-1001", "fields": {"status": "PAID", "total": "1200.00"}},
                        {"external_id": "L-1002", "fields": {"status": "OPEN", "total": "690.00"}},
                        {"external_id": "L-1003", "fields": {"status": "OPEN", "total": "75.00"}}]})

        # CSV path: the warehouse can only export a nightly file. Two nights of snapshots;
        # the second import records just the differences.
        def upload(path, csv_text, **form):
            r = client.post(f"/api/v1{path}", data={"source": "nightly-csv", "entity": "stock", **form},
                            files={"file": ("snapshot.csv", csv_text.encode(), "text/csv")},
                            headers={"Authorization": f"Bearer {admin.token}"})
            if r.status_code not in (200, 201):
                raise SystemExit(f"{path} -> {r.status_code}: {r.text}")

        upload("/imports", "external_id,sku,on_hand,bin\nW-1,LAP-14,40,A1\nW-2,HP-PRO,120,A2\nW-3,KB-MX,60,B4\n")
        upload("/imports", "external_id,sku,on_hand,bin\nW-1,LAP-14,37,A1\nW-2,HP-PRO,120,A2\nW-4,MON-27,15,C1\n",
               complete="true")
        upload("/reconciliations/upload", "external_id,on_hand\nW-1,37\nW-2,118\nW-4,15\n")

        print("rules:", admin.call("POST", "/alerts/run")["new_alerts"], "alerts raised")

        # ---- Globex: a second, isolated tenant ----------------------------------------
        g = Api(client, anon.call("POST", "/auth/signup", {"organization": "Globex Retail", "full_name": "Hank Scorpio",
                                                            "email": "admin@globex.example.com", "password": pw})["access_token"])
        gp = g.call("POST", "/products", {"sku": "LAP-14", "name": "Globex Laptop", "price": "899.00"})["product_id"]
        gc = g.call("POST", "/customers", {"name": "Marge S.", "email": "marge@example.com"})["customer_id"]
        go = g.call("POST", "/orders", {"customer_id": gc, "items": [{"product_id": gp, "quantity": 1}]})["order_id"]
        g.call("POST", f"/orders/{go}/payments", {"amount": "899.00", "method": "CASH"})

        print(f"seeded Acme Electronics (orders {o1}-{o6}) and Globex Retail")
        print("log in as admin@acme.example.com / approver@acme.example.com / staff@acme.example.com / viewer@acme.example.com / admin@globex.example.com")
        print("password: DEMO_PASSWORD in .env")


if __name__ == "__main__":
    url = "http://127.0.0.1:8000"
    if "--base-url" in sys.argv:
        url = sys.argv[sys.argv.index("--base-url") + 1].rstrip("/")
    seed(url)
