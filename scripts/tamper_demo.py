"""Demonstrate that the audit hash chain detects tampering, even by a DBA.

Creates a throwaway organization "Tamper Demo", records a few changes, then connects as
the schema owner, disables the append-only trigger, rewrites one audit record (as an
attacker covering their tracks would), and re-enables the trigger. Verification then
pinpoints the modified record.

The main demo organization is not touched (each organization has its own chain).

Usage:  python scripts/tamper_demo.py
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["WORKERS_ENABLED"] = "false"

import oracledb  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.main import app  # noqa: E402


def main() -> None:
    s = get_settings()
    with TestClient(app) as client:
        email = f"tamper-{secrets.token_hex(3)}@example.com"
        pw = secrets.token_urlsafe(12)
        r = client.post("/api/v1/auth/signup", json={"organization": "Tamper Demo", "full_name": "Demo Admin",
                                                      "email": email, "password": pw})
        r.raise_for_status()
        tenant_id = r.json()["user"]["tenant"]["tenant_id"]
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        pid = client.post("/api/v1/products", headers=h, json={"sku": "GOLD", "name": "Gold bar", "price": "5000"}).json()["product_id"]
        client.patch(f"/api/v1/products/{pid}", headers=h, json={"price": "5100"})
        print("before tampering:", client.post("/api/v1/audit/verify", headers=h).json())

        conn = oracledb.connect(user=s.db_owner_user, password=s.db_owner_password, dsn=s.db_dsn)
        cur = conn.cursor()
        cur.callproc("ctx_pkg.set_ctx", [tenant_id, None, None, None])
        cur.execute("ALTER TRIGGER trg_audit_log_immutable DISABLE")
        try:
            # Pretend the product was created at a lower price and by someone else.
            cur.execute(
                """UPDATE audit_log SET actor = 'someone.else@example.com',
                          new_values = REPLACE(new_values, '"price":5000', '"price":50')
                    WHERE tenant_id = :t AND entity = 'product' AND operation = 'INSERT'""",
                {"t": tenant_id},
            )
            conn.commit()
            print(f"tampered with {cur.rowcount} audit record(s) as {s.db_owner_user}")
        finally:
            cur.execute("ALTER TRIGGER trg_audit_log_immutable ENABLE")
            conn.close()

        result = client.post("/api/v1/audit/verify", headers=h).json()
        print("after tampering: ", result)
        print(f"\nlog in as {email} / {pw} to see it in the UI (Audit log -> Verify chain)")


if __name__ == "__main__":
    main()
