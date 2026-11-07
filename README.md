# Provenance Cloud — Provenance-Enabled RDBMS for E-Commerce

A multi-tenant SaaS backend on **Oracle** and **FastAPI** that records *why*, *where* and *how* every piece of
commerce data came to be. Database triggers capture every change into a **tamper-evident SHA-256 hash chain**. Tenants
are isolated by **Oracle Virtual Private Database (VPD)**. The API can explain any order total, time-travel any record,
and trace a single request through every change it caused.

> This started as a course project (Flask + SQLite, see [`legacy/`](legacy/)). Version 2 rebuilds it as a production-style
> service on Oracle 19c+.

## Features

| Area | What you get | Where |
|---|---|---|
| **Provenance capture** | Triggers on every business table write old/new JSON, the human actor, request ID and DB user. No application code needed. | `db/migrations/003_triggers.sql` |
| **Tamper-evident audit** | Per-tenant SHA-256 hash chain. The API account has `SELECT` only on `audit_log`, and an append-only trigger blocks even the owner. `POST /audit/verify` pinpoints any edited, deleted or re-ordered record. | `002_audit.sql`, `scripts/tamper_demo.py` |
| **Why-provenance** | `GET /provenance/orders/{id}/explain` replays the audit log to rebuild the total step by step and compares each price with the list price *at order time*. | `app/services/provenance.py` |
| **Where-provenance** | Full field-level history of any record. | `/provenance/{entity}/{id}/history` |
| **How-provenance** | Every change one API request caused, including trigger cascades. Lineage graph per order with cause→effect links. | `/provenance/requests/{id}`, `/provenance/orders/{id}/lineage` |
| **Time travel** | Rebuild any record (orders include their items) at any instant, or diff two instants. Oracle **Flashback Query** (`AS OF TIMESTAMP`) is also available for recent physical state. | `/as-of`, `/compare`, `/flashback` |
| **Multi-tenancy** | Oracle VPD predicate on every tenant table (fails closed with no context), composite `(tenant_id, id)` foreign keys, and an Oracle application context set per request. | `004_features.sql`, `app/db.py` |
| **Business rules in the DB** | Order state machine, item locking after payment, and totals kept by a compound trigger. They apply to every client, not just the API. | `003_triggers.sql` |
| **Maker-checker approvals** | Price changes above a threshold need a *different* admin. The DB itself rejects self-approval (`CK_CR_FOUR_EYES`), and the resulting audit row carries the approval ID. | `/approvals` |
| **Anomaly & data-quality rules** | Overpayment, fulfilled-but-unpaid, deep discounts (vs. price at order time), large price changes, large refunds, rapid edits, changes made outside the app, chain integrity. Rules run every minute and dedupe by fingerprint. | `app/services/rules.py` |
| **Transactional outbox + webhooks** | Events are written in the same transaction as the change. Deliveries are HMAC-SHA256 signed and retried with exponential backoff and a dead-letter state, with an SSRF guard. | `app/services/webhooks.py` |
| **SaaS essentials** | Sign-up creates an org and its admin. JWT access/refresh tokens, Argon2 hashing, RBAC (viewer/staff/admin), login rate limiting, security headers and CSP, request IDs, JSON logs, `/health` and `/ready`, OpenAPI docs. | `app/` |
| **Web UI** | Dependency-free SPA: dashboard, commerce screens, explain/lineage/time-travel views, audit explorer with CSV/JSON export, alerts, approvals, webhooks, team, settings. | `app/static/` |

## Architecture

```
Browser SPA ──HTTP──▶ FastAPI (JWT, RBAC, rate limit, request-id)
                        │  per request: pool.acquire() → ctx_pkg.set_ctx(tenant, user, email, request_id)
                        ▼
                Oracle 19c PDB  (connect as PROV_APP, CURRENT_SCHEMA = PROV_OWNER)
                ├─ VPD policy: tenant_id = SYS_CONTEXT('PROV_CTX','TENANT_ID')
                ├─ triggers ──▶ audit_pkg.log_change ──▶ audit_log (hash chain) ──▶ outbox_events
                └─ compound trigger keeps order totals; status guard enforces the state machine
                        ▲
Background worker ──────┘  per tenant: fan out outbox → webhook_deliveries → signed POST; run rules
```

Two schemas keep privileges minimal. `PROV_OWNER` owns all objects. `PROV_APP` (used by the API) gets DML on
business tables, `SELECT` only on `audit_log`, and `EXECUTE` on three small packages. It cannot call
`audit_pkg.log_change`, so it cannot forge or rewrite history.

## Documentation

The full guide (setup, business rules, API reference, integrations, security, limits and glossary) is in
[docs/DOCUMENTATION.md](docs/DOCUMENTATION.md).

## Quick start (Windows, local Oracle)

Requirements: Oracle Database 19c+ with a pluggable database (Enterprise Edition for VPD), SQL*Plus with OS
authentication (`/ as sysdba`), Python 3.12+, and [uv](https://docs.astral.sh/uv/) (or plain pip).

```bash
uv venv .venv --python 3.12
uv pip install --python .venv/Scripts/python.exe -r requirements.txt
```

Create `.env` (generated secrets), the two schemas and the context, then apply migrations:

```bash
.venv/Scripts/python.exe scripts/setup_db.py
```

Load demo data (two organizations, orders, an approval, alerts, a direct-SQL edit):

```bash
.venv/Scripts/python.exe scripts/seed.py
```

Run the server:

```bash
.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 for the app and http://127.0.0.1:8000/docs for the API.
Demo logins are `admin@acme.example.com`, `approver@acme.example.com`, `staff@acme.example.com`,
`viewer@acme.example.com` and `admin@globex.example.com`. They all use the `DEMO_PASSWORD` from `.env`.

Settings live in `.env` (see `.env.example`). The defaults assume service `orclpdb` on `localhost:1521`,
SID `ORCL` and `sqlplus` at `C:\oracle_db\bin`.

### Things to try

- **Orders → #1 → Explain total.** Shows why the total is 1549.99, replayed from the audit log.
- **Lineage graph.** Shows the trigger-recalculated totals linked to the item changes that caused them.
- **Approvals.** Sign in as `approver@…` to approve the pending price change made by `staff@…`.
- **Alerts.** Lists findings, including the price edited directly in SQL as `PROV_OWNER`.
- **Tamper detection.** Run `.venv/Scripts/python.exe scripts/tamper_demo.py`. It edits an audit row as the schema owner (after disabling the guard trigger), and verification pinpoints it.

## Integrating an existing system

An upstream system (legacy shop, ERP, CDC pipeline) pushes changes as CloudEvents. It does not
need to replace anything; this service records the evidence next to it.

1. An admin registers the source and its capture method/trust level: `POST /api/v1/sources`
   `{"code": "legacy-shop", "name": "Legacy shop", "capture_method": "CDC", "trust_level": "HIGH"}`.
   Trust comes from this registration, never from the sender.
2. An admin creates an API key: `POST /api/v1/api-keys` `{"name": "legacy-connector", "scopes": ["events:write"]}`.
   The key (`prv_...`) is shown once; only its SHA-256 hash is stored.
3. The system sends events with `Authorization: Bearer prv_...`:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/events \
  -H "Authorization: Bearer $PROV_API_KEY" -H "Content-Type: application/json" \
  -d '{"specversion":"1.0","id":"legacy-evt-88421","source":"legacy-shop","type":"order.updated",
       "subject":"order/10045","time":"2026-11-07T10:12:03Z",
       "data":{"op":"u","before":{"total":"1500.00"},"after":{"total":"1200.00"}}}'
```

- **Idempotent:** the same `source` + `id` returns `200` with `"duplicate": true` instead of a second record.
- **Evidence:** each accepted event goes into the hash-chained audit log (`/provenance/external_event/{event_pk}/history`)
  and emits an `external_event.created` webhook.
- **Reading back:** `GET /api/v1/ingested-events?cursor=...` with the `events:read` scope.
- **Batches:** `POST /api/v1/events:batch` takes a JSON array of up to 500 events; each one succeeds or fails on its
  own and the response reports `created` / `duplicate` / `invalid` / `rejected` per index.
- **Reconciliation:** `POST /api/v1/reconciliations` with the upstream system's current records for one entity
  (`{"source", "entity", "complete", "records": [{"external_id", "fields"}]}`). Each record is compared with the
  latest event we hold: **MISMATCH** (field differs), **MISSING** (no event ever arrived), and with
  `complete: true` **UNEXPECTED** (we hold a record upstream no longer has). Discrepancies raise an RC001 alert.
- **CSV files (no API on the other side):** `POST /api/v1/imports` takes a snapshot CSV (`external_id` + any columns)
  and records only what changed since the last file: created, updated (with before/after) and, with `complete=true`,
  deleted. Re-uploading the same file records nothing; `dry_run=true` previews. `POST /api/v1/reconciliations/upload`
  reconciles a CSV without recording anything. Both are on the Integrations page.
- **Rate limit:** per API key (`API_KEY_RATE_LIMIT_PER_MINUTE`, default 600), with `Retry-After` on 429. Set
  `REDIS_URL` to share limits across processes and servers; without it (or if Redis is down) limits are per process.
  `/ready` reports which backend is active.
- The **Integrations** page in the UI (admins) manages sources and keys and shows reconciliation results.

Standards followed: CloudEvents 1.0 (envelope), Debezium-style `op/before/after` (payload), RFC 9457 problem details
(errors, `application/problem+json`), Standard Webhooks (`webhook-id`, `webhook-timestamp`, `webhook-signature`).

## Tests

54 integration tests run against the real Oracle database (the Redis limiter is tested with fakeredis). Each test uses its own tenant.

```bash
.venv/Scripts/python.exe -m pytest
```

They cover auth/RBAC, VPD isolation (including a DB-level cross-tenant insert), the trigger-maintained totals, the
state machine, explain/history/trace/lineage, time travel, Flashback Query, the read-only audit log, hash-chain
verification, export, four-eyes approvals (API and DB constraint), rules, and signed webhook delivery and retry.

Audit records are append-only, so test tenants stay in the database. `scripts/setup_db.py --reset` drops both
schemas and starts clean (this deletes all project data).

## Project layout

```
app/
  main.py            FastAPI app, middleware, health checks
  db.py              Oracle pool, per-request tenant context, dict rows
  deps.py            auth + RBAC dependencies
  routers/           auth, users/settings, catalog, orders, audit+provenance, governance, dev
  services/          provenance (explain, lineage, time travel), rules, webhooks
  workers.py         background dispatcher + rules runner
  static/            web UI (index.html, app.js, styles.css)
db/
  bootstrap/         create/drop schemas (SYSDBA)
  migrations/        001_core, 002_audit, 003_triggers, 004_features
scripts/             setup_db.py, seed.py, tamper_demo.py
tests/               pytest integration suite
legacy/              original Flask + SQLite course project
```

## Production notes

- Set `ENVIRONMENT=production` (removes the dev webhook receiver), `WEBHOOK_ALLOW_PRIVATE_URLS=false`, a strong
  `JWT_SECRET`, and `CORS_ORIGINS` if the UI is hosted elsewhere.
- Run with several uvicorn/gunicorn workers, but only one process should have `WORKERS_ENABLED=true`. Alternatively,
  move dispatch and rules to `DBMS_SCHEDULER` or a separate worker.
- Set `REDIS_URL` when running several instances, so login and API-key rate limits are shared.
- Webhook secrets are stored in plain text, so encrypt them at rest (e.g. Oracle TDE or a KMS).
- Flashback Query only covers the undo retention window (`undo_retention`, 900 s here), and Oracle samples its time→SCN
  map every few seconds. For exact or older history use `/as-of`, which replays the audit log.
- The hash chain serialises audit writes per tenant (one locked head row), which is fine for typical OLTP volumes per
  organization.

## What changed from the course version

- SQLite/Flask/raw SQL page → Oracle + FastAPI, with auth, multi-tenancy and a real UI.
- Per-table audit tables → one JSON audit log with a hash chain, actor, request ID and DB user.
- The legacy Oracle script recomputed totals from a row-level trigger that read `order_items`. That raises
  **ORA-04091 (mutating table)**, and it is now a compound trigger.
- Free-form "SELECT-only" SQL endpoint removed (it was an injection and data-exposure risk).
- Money is `NUMBER(12,2)`/`Decimal` end to end (no floats). The actor comes from an application context instead of a
  hard-coded `'app_user'` or the pooled DB user.
