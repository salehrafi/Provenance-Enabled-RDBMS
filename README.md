# Provenance Cloud

**Know why every number is what it is.** Provenance Cloud is a multi-tenant SaaS that records *who changed what, when and why* in a tamper-evident audit chain, rebuilds any record as it was at any past moment, explains calculated values, and lets you connect any external system with CloudEvents and reconcile it against what it claims today.

Stack: **FastAPI** · **PostgreSQL 16** (row-level security, triggers, jsonb) · **Alembic** · optional **Redis** · dependency-free, responsive web UI (desktop, tablet, phone).

> History: this started as a course project (Flask + SQLite, then Oracle). Version 3 replaces Oracle with PostgreSQL and rebuilds the platform for production. See [CHANGELOG](CHANGELOG.md) and [ADR 0001](docs/adr/0001-postgresql-over-oracle.md). The original course code is kept in [`legacy/`](legacy/).

## What you get

| Capability | How it works | Read more |
|---|---|---|
| **Provenance capture** | Database triggers record every change (old/new JSON, actor, request id, database role) in the writer's own transaction. Nothing to call, nothing to forget. | [DATABASE](docs/DATABASE.md) |
| **Tamper-evident audit** | Per-organization SHA-256 chain sealed at commit, **plus Ed25519-signed checkpoints** published to webhooks and an optional append-only file, so even a full rewrite by a database superuser is detectable. | [SECURITY](docs/SECURITY.md) |
| **Explainability** | `explain` replays the audit log to rebuild an order total step by step and compares each price with the list price *at order time*. | [API](docs/API.md) |
| **Time travel** | Rebuild any record (orders include lines and payments) at any instant, compare two instants, and query external records bitemporally (what was true vs. what we knew). | [API](docs/API.md) |
| **Causal lineage** | Graph of everything that shaped an order, with cause→effect links for database-derived changes. | [ARCHITECTURE](docs/ARCHITECTURE.md) |
| **Tenant isolation** | PostgreSQL row-level security on every tenant table, fail-closed, transaction-local context, composite foreign keys, least-privilege roles. | [SECURITY](docs/SECURITY.md) |
| **Maker-checker** | Large price changes need a *different* admin. The database itself rejects self-approval. | [DATABASE](docs/DATABASE.md) |
| **Integrations** | CloudEvents ingestion (single and batch), idempotent, trust set by an admin per source, CSV snapshot import, reconciliation. | [INTEGRATION_GUIDE](docs/INTEGRATION_GUIDE.md) |
| **Reliable events** | Transactional outbox → leased, retried, dead-lettered, SSRF-safe, Standard Webhooks-signed deliveries. | [ARCHITECTURE](docs/ARCHITECTURE.md) |
| **Anomaly rules** | Overpayment, fulfilled-but-unpaid, deep discounts, large price changes and refunds, rapid edits, out-of-band database changes, chain integrity. | [API](docs/API.md) |
| **Developer experience** | Versioned REST API, accurate OpenAPI, RFC 9457 errors with stable codes, idempotency keys, scoped API keys, sandbox data, Python and TypeScript SDKs. | [API](docs/API.md) |

## Quick start (no Docker)

Requirements: Python 3.12 and [uv](https://docs.astral.sh/uv/) (or pip). A PostgreSQL 16 server is needed: use Docker (below), your own, or the bundled development server.

```bash
uv venv .venv --python 3.12
uv pip install --python .venv/Scripts/python.exe -r requirements-dev.txt     # Linux/macOS: .venv/bin/python

.venv/Scripts/python.exe scripts/dev_postgres.py start                        # local PostgreSQL on 127.0.0.1:54329
.venv/Scripts/python.exe -m app.cli init --port 54329                         # writes .env with generated secrets
.venv/Scripts/python.exe -m app.cli setup                                     # creates roles + schema, runs migrations
.venv/Scripts/python.exe -m app.cli seed                                      # optional: demo organizations and data
.venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```

Open <http://127.0.0.1:8000>. Sign in with `admin@acme.example.com` and the demo password printed by `seed` (also `DEMO_PASSWORD` in `.env`), or **create your own organization** on the sign-up screen and use *Load sample data* on the dashboard. API docs are at <http://127.0.0.1:8000/docs>.

`dev_postgres.py` is for developer laptops only (trust authentication, no TLS). On Linux/macOS with Docker, `docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16` and `python -m app.cli init --port 5432` work equally well.

## Quick start (Docker Compose)

```bash
cp .env.docker.example .env.docker      # then replace every change-me with a generated secret
docker compose --env-file .env.docker up --build
```

Starts PostgreSQL, a one-shot `setup` job (roles + migrations), the API on :8000, a background worker, and Redis. See [DEPLOYMENT](docs/DEPLOYMENT.md).

## The first ten minutes

1. **Create an organization** (sign-up screen) → you are its admin.
2. **Load sample data** (dashboard) → open an order → **Explain total**, then **Lineage**.
3. **Explorer** → pick `product`, id `1` → drag the slider through its history; ask the server what it looked like an hour ago.
4. **Integrations → Sources** → register `legacy-shop` (trust High, capture CDC) → **API keys** → create a key with `events:write` → send the `curl` shown on the page.
5. **Audit & integrity** → *Verify now*, then copy a signed checkpoint somewhere safe. That copy is what makes a wholesale rewrite of history detectable.

## Repository layout

```
app/                FastAPI application (modular monolith)
  main.py             app factory, middleware, health, metrics
  auth.py             principals, permissions, per-request tenant-scoped connection
  db.py               psycopg pool, transaction-local tenant context
  routers/            auth, users, catalog, orders, audit, governance, integration, ingest, sandbox
  services/           provenance, integrity (hash chain + checkpoints), rules, webhooks, ingestion, records,
                      reconcile, imports, idempotency, demo
  worker.py           outbox dispatch, rules, checkpoints, housekeeping (own process in production)
  static/             web UI (ES modules, no build step)
migrations/         Alembic environment + SQL files (schema, audit chain, row-level security, grants)
sdk/                Python and TypeScript clients
scripts/            dev_postgres, backup, restore_check, import_legacy_history
tests/              160+ tests against a real PostgreSQL
docs/               architecture, database, security, API, operations, ADRs
legacy/             the original course project
```

## Documentation

[Product overview](docs/PRODUCT_OVERVIEW.md) · [Architecture](docs/ARCHITECTURE.md) · [Database](docs/DATABASE.md) · [Security](docs/SECURITY.md) · [API](docs/API.md) · [Integration guide](docs/INTEGRATION_GUIDE.md) · [Deployment](docs/DEPLOYMENT.md) · [Development](docs/DEVELOPMENT.md) · [Testing](docs/TESTING.md) · [Operations](docs/OPERATIONS.md) · [Platform administration & break-glass](docs/PLATFORM_ADMIN.md) · [Migrating from Oracle](docs/MIGRATING_FROM_ORACLE.md) · [Decision records](docs/adr/)

## Status and honest limits

Verified in development: the full test suite (real PostgreSQL 16, including concurrency, tampering and cross-tenant tests), ruff, mypy, a from-scratch setup, a backup + restore + verification cycle, both SDKs against a live server, and the UI in a browser.
**Not verified here:** the Docker image and Compose file, the GitHub Actions workflow, behaviour under production-scale data, and any third-party penetration test. Read [SECURITY](docs/SECURITY.md#limitations-and-non-goals) before relying on this for regulated data.

MIT licensed.
