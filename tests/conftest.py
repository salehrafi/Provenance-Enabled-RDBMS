"""Integration tests against the local Oracle database.

Each test creates its own organization (tenant), so tests never see each other's data or
the demo data. Audit records are append-only by design, so test tenants remain in the
database afterwards; `python scripts/setup_db.py --reset` wipes everything.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["WORKERS_ENABLED"] = "false"
os.environ["LOGIN_RATE_LIMIT_PER_MINUTE"] = "10000"
os.environ["API_KEY_RATE_LIMIT_PER_MINUTE"] = "10000"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

PASSWORD = "test-password-123"


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


class Org:
    def __init__(self, client: TestClient, label: str):
        self.client = client
        self.suffix = uuid.uuid4().hex[:8]
        self.admin_email = f"admin-{self.suffix}@example.com"
        r = client.post("/api/v1/auth/signup", json={"organization": f"Test {label} {self.suffix}", "full_name": "Test Admin",
                                                      "email": self.admin_email, "password": PASSWORD})
        assert r.status_code == 201, r.text
        body = r.json()
        self.tenant_id = body["user"]["tenant"]["tenant_id"]
        self.token = body["access_token"]

    def headers(self, token: str | None = None) -> dict:
        return {"Authorization": f"Bearer {token or self.token}"}

    def req(self, method: str, path: str, body=None, token: str | None = None, expect: int | None = None, **params):
        r = self.client.request(method, "/api/v1" + path, json=body, headers=self.headers(token), params=params or None)
        if expect is not None:
            assert r.status_code == expect, f"{method} {path}: expected {expect}, got {r.status_code}: {r.text}"
        return r

    def add_user(self, role: str) -> str:
        email = f"{role}-{uuid.uuid4().hex[:6]}-{self.suffix}@example.com"
        self.req("POST", "/users", {"email": email, "full_name": f"Test {role}", "password": PASSWORD, "role": role}, expect=201)
        r = self.client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert r.status_code == 200, r.text
        return r.json()["access_token"]

    def product(self, price: str = "100.00", sku: str | None = None) -> int:
        return self.req("POST", "/products", {"sku": sku or uuid.uuid4().hex[:8], "name": "Thing", "price": price},
                        expect=201).json()["product_id"]

    def customer(self) -> int:
        return self.req("POST", "/customers", {"name": "Cust", "email": f"c-{uuid.uuid4().hex[:8]}@example.com"},
                        expect=201).json()["customer_id"]

    def order(self, items: list[dict]) -> dict:
        return self.req("POST", "/orders", {"customer_id": self.customer(), "items": items}, expect=201).json()


@pytest.fixture
def org(client) -> Org:
    return Org(client, "A")


@pytest.fixture
def other_org(client) -> Org:
    return Org(client, "B")
