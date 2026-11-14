"""Test harness. Every test runs against a real PostgreSQL 16 database.

A throw-away database (`provenance_test`) is dropped, recreated, bootstrapped and migrated at the
start of the session using the same code path as production (`app.cli`). Each test then creates
its own organization, so tests never see each other's rows. Audit records are append-only by
design, so the database is simply discarded at the next session.

Connection: DATABASE_ADMIN_URL / DATABASE_URL / DATABASE_OWNER_URL from the environment or .env
(`python -m app.cli init` + `python scripts/dev_postgres.py start` give you a working setup).
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from psycopg import sql

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TEST_DB = "provenance_test"
PASSWORD = "test-password-123"
CLIENT_IP = "203.0.113.10"

os.environ["WORKERS_ENABLED"] = "false"
os.environ["ENVIRONMENT"] = "test"
os.environ["COOKIE_SECURE"] = "false"
os.environ["WEBHOOK_ALLOW_HTTP"] = "false"
os.environ["WEBHOOK_ALLOW_PRIVATE_URLS"] = "false"
os.environ["LOGIN_RATE_LIMIT_PER_MINUTE"] = "100000"
os.environ["API_KEY_RATE_LIMIT_PER_MINUTE"] = "100000"
os.environ["USER_RATE_LIMIT_PER_MINUTE"] = "100000"


def with_db(url: str, dbname: str = TEST_DB) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path="/" + dbname))


def _point_at_test_db() -> None:
    from app.config import get_settings

    base = get_settings()
    for var, url in (("DATABASE_URL", base.database_url), ("DATABASE_OWNER_URL", base.database_owner_url),
                     ("DATABASE_PLATFORM_URL", base.database_platform_url)):
        os.environ[var] = with_db(url)
    os.environ["DATABASE_ADMIN_URL"] = base.database_admin_url
    get_settings.cache_clear()


@pytest.fixture(scope="session", autouse=True)
def database():
    _point_at_test_db()
    from app import cli
    from app.config import get_settings

    admin = get_settings().database_admin_url
    if not admin:
        pytest.exit("DATABASE_ADMIN_URL is not set. Run `python -m app.cli init` and start PostgreSQL.", 2)
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(TEST_DB)))
    cli.cmd_bootstrap(None)  # type: ignore[arg-type]
    cli.cmd_migrate(type("A", (), {"revision": "head"})())
    yield
    from app.db import close_pool

    close_pool()


@pytest.fixture(scope="session")
def client(database):
    from fastapi.testclient import TestClient

    from app.main import app

    # A real (documentation-range) client address, so the activity log's IP column can be asserted.
    with TestClient(app, client=(CLIENT_IP, 50000)) as c:
        yield c


@pytest.fixture(autouse=True)
def _reset_limits():
    from app import ratelimit

    ratelimit.reset()
    yield


@pytest.fixture(scope="session")
def admin_conn(database):
    """A superuser connection to the test database, for tamper tests only."""
    from app.config import get_settings

    url = with_db(get_settings().database_admin_url)
    with psycopg.connect(url, autocommit=True) as conn:
        yield conn


class Org:
    """A fresh organization with an admin, plus helpers for the common calls."""

    def __init__(self, client, label: str = "A"):
        self.client = client
        self.suffix = uuid.uuid4().hex[:8]
        self.admin_email = f"admin-{self.suffix}@example.com"
        r = client.post("/api/v1/auth/signup", json={
            "organization": f"Test {label} {self.suffix}", "full_name": "Test Admin",
            "email": self.admin_email, "password": PASSWORD})
        assert r.status_code == 201, r.text
        body = r.json()
        self.tenant_id = body["user"]["tenant"]["tenant_id"]
        self.user_id = body["user"]["user_id"]
        self.token = body["access_token"]
        self.refresh_token = body["refresh_token"]
        client.cookies.clear()

    def headers(self, token: str | None = None) -> dict:
        return {"Authorization": f"Bearer {token or self.token}"}

    def req(self, method: str, path: str, body=None, token: str | None = None, expect: int | None = None,
            headers: dict | None = None, **params):
        r = self.client.request(method, "/api/v1" + path, json=body, headers={**self.headers(token), **(headers or {})},
                                params=params or None)
        if expect is not None:
            assert r.status_code == expect, f"{method} {path}: expected {expect}, got {r.status_code}: {r.text}"
        return r

    def add_user(self, role: str) -> str:
        email = f"{role}-{uuid.uuid4().hex[:6]}-{self.suffix}@example.com"
        self.req("POST", "/users", {"email": email, "full_name": f"Test {role}", "password": PASSWORD, "role": role},
                 expect=201)
        r = self.client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert r.status_code == 200, r.text
        self.client.cookies.clear()
        return r.json()["access_token"]

    def product(self, price: str = "100.00", sku: str | None = None) -> int:
        return self.req("POST", "/products", {"sku": sku or uuid.uuid4().hex[:8], "name": "Thing", "price": price},
                        expect=201).json()["product_id"]

    def customer(self) -> int:
        return self.req("POST", "/customers", {"name": "Cust", "email": f"c-{uuid.uuid4().hex[:8]}@example.com"},
                        expect=201).json()["customer_id"]

    def order(self, items: list[dict]) -> dict:
        return self.req("POST", "/orders", {"customer_id": self.customer(), "items": items}, expect=201).json()

    def source(self, code: str | None = None, trust: str = "HIGH", method: str = "CDC") -> str:
        code = code or f"legacy-{uuid.uuid4().hex[:6]}"
        self.req("POST", "/sources", {"code": code, "name": "Legacy shop", "capture_method": method,
                                      "trust_level": trust}, expect=201)
        return code

    def api_key(self, scopes=("events:write", "events:read")) -> str:
        return self.req("POST", "/api-keys", {"name": f"connector-{uuid.uuid4().hex[:4]}", "scopes": list(scopes)},
                        expect=201).json()["api_key"]


@pytest.fixture
def org(client) -> Org:
    return Org(client, "A")


@pytest.fixture
def other_org(client) -> Org:
    return Org(client, "B")
