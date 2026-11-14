"""Reproducible micro-benchmark of audited write throughput and chain verification.

    python scripts/bench.py [--writes 300]

Creates a throw-away organization in the database named by DATABASE_URL (development only) and
reports transactions per second for one organization. Numbers depend entirely on your hardware and
PostgreSQL settings; use them to compare configurations, not as a capacity promise.
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.db import close_pool, system_session, tenant_session  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--writes", type=int, default=300)
    n = ap.parse_args().writes
    if not get_settings().is_dev:
        sys.exit("The benchmark writes data; run it against a development database.")
    with system_session() as db:
        org = db.one("SELECT * FROM prov.create_organization(%s, %s, %s, %s, %s, 'bench')",
                     ("Bench", "bench-" + uuid.uuid4().hex[:6], f"b{uuid.uuid4().hex[:6]}@example.com", "Bench", "x"))
        db.commit()
    assert org
    tid, uid = org["tenant_id"], org["user_id"]

    def insert(i: int) -> None:
        with tenant_session(tid, uid, "bench", f"r{i}") as db:
            db.insert("INSERT INTO customers (name, email) VALUES ('c', %s)", (uuid.uuid4().hex + "@example.com",), "customer_id")
            db.commit()

    def workflow(i: int) -> None:
        with tenant_session(tid, uid, "bench", f"o{i}") as db:
            c = db.insert("INSERT INTO customers (name, email) VALUES ('c', %s)", (uuid.uuid4().hex + "@example.com",), "customer_id")
            p = db.insert("INSERT INTO products (sku, name, price) VALUES (%s, 'p', 10)", (uuid.uuid4().hex[:12],), "product_id")
            o = db.insert("INSERT INTO orders (customer_id) VALUES (%s)", (c,), "order_id")
            db.execute("INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (%s, %s, 1, 10)", (o, p))
            db.commit()

    def run(fn, workers: int, count: int) -> float:
        start = time.perf_counter()
        with ThreadPoolExecutor(workers) as pool:
            list(pool.map(fn, range(count)))
        return count / (time.perf_counter() - start)

    for w in (1, 4, 8):
        print(f"single-row audited insert, {w} client(s): {run(insert, w, n):.0f} tx/s")
    print(f"order workflow (5 audited rows incl. derived total), 8 clients: {run(workflow, 8, n // 2):.0f} tx/s")
    with tenant_session(tid, uid, "bench", "verify") as db:
        start = time.perf_counter()
        r = db.one("SELECT * FROM prov.audit_verify(1, 1000000)")
        assert r
        print(f"verified {r['checked']} records in {time.perf_counter() - start:.2f}s (ok={r['ok']})")
    close_pool()


if __name__ == "__main__":
    main()
