# Testing

All tests run against a **real PostgreSQL 16**. There is no mocked database: row-level security, triggers, constraints, locking and the audit chain are the product, so they are tested where they run.

## Running

```bash
# a PostgreSQL superuser URL is needed so the harness can create a throw-away database
.venv/Scripts/python.exe scripts/dev_postgres.py start
.venv/Scripts/python.exe -m app.cli init --port 54329      # writes DATABASE_ADMIN_URL etc. to .env
.venv/Scripts/python.exe -m pytest                         # ~20 s
.venv/Scripts/ruff.exe check . && .venv/Scripts/mypy.exe
```

`tests/conftest.py` drops and recreates database `provenance_test` at the start of every session and bootstraps and migrates it with the same code as production (`app.cli`). Each test then signs up its own organization, so tests never see each other's rows. Audit records are append-only, so the database is simply discarded next session.

## What is covered

| File | Focus |
|---|---|
| `test_auth.py` | login, token forgery/expiry/`alg:none`, refresh rotation, reuse detection and family revocation, password change and sign-out-everywhere revocation, deactivation, RBAC matrix, last-admin rule, API-key scopes/expiry/revocation/rate limits, rate limiter (memory and Redis via fakeredis), security headers, body-size limit |
| `test_tenancy.py` | API-level cross-tenant attempts on every resource; SQL-level insert/update/move/read attempts; fail-closed with no context; context does not outlive the transaction; pooled connections never leak identity; the runtime role is unprivileged; 18 statements the runtime role must be unable to execute; composite foreign keys stop cross-tenant references even for a superuser; **every `tenant_id` table has RLS and a policy** |
| `test_ledger.py` | derived totals, state machine, item locking, payments, wildcard-safe search and injection attempts, history/diff/actor/db-role, secrets never in audit rows, explain, request trace, lineage, time travel for records and whole orders, deleted records, maker-checker (including the database refusing self-approval and stale requests), anomaly rules, out-of-band changes, alerts, settings, sandbox |
| `test_audit_integrity.py` | chain links and gap-free sequence; detection of edited record, edited payload, mid-chain delete, tail truncation, re-ordering, unsealed insert; **full recompute of every hash caught only by signed checkpoints**, including a customer-held copy after the stored checkpoints are deleted; forged and cross-tenant checkpoints; checkpoint refusal on a broken chain; append-only even for the owner; 8 concurrent writers → valid gap-free chain; rolled-back work leaves nothing; filters, pagination, CSV/JSON export, CSV formula injection |
| `test_ingest.py` | CloudEvents idempotency, trust from registration, validation and limits, batch isolation with savepoints, cursors, record history/as-of/compare, bitemporal queries, out-of-order arrival, reconciliation outcomes, CSV import (idempotent, dry-run, A→B→A→B history), key scope for reconstruction |
| `test_concurrency.py` | idempotency-key replay and mismatch, per-tenant keys, concurrent identical requests → one order, concurrent payments cannot overpay, concurrent item edits keep totals correct, payment vs. cancel serialise, concurrent sign-ups with one email, deadlock handling |
| `test_webhooks.py` | Standard Webhooks signature, filtering, retry → backoff → dead-letter → alert → manual retry, stable message id, network errors and redirects, leases prevent double delivery, idempotent fan-out, no backlog for new subscriptions, **SSRF** (loopback, private, link-local/metadata, IPv6, IPv4-mapped, mixed answers, schemes, credentials, DNS rebinding after creation), secret encryption at rest and tenant binding, rotation, cross-tenant isolation |
| `test_operations.py` | health/ready/metrics, OpenAPI completeness, every endpoint requires authentication, migrations idempotent and downgrade guarded, unsafe production config rejected, worker end-to-end (delivery, checkpoint, refuses to sign a broken chain), anchor file, housekeeping never touches history, no database detail leaks in 500s, CSP |
| `test_platform.py` | platform administration and break-glass: MFA enrolment and replay protection, token separation both ways, the platform role refused on every tenant table and the application role refused on every platform object, no role with BYPASSRLS, metadata-only overview, suspension (organization blocked, recorded in its own audit chain), full break-glass flow (four-eyes, requester-only activation and use, cross-tenant isolation, secrets never exposed, customer notification), database-enforced read-only session, expiry that cannot be extended (even by a superuser) and is enforced by the database, approval lapse, fresh-MFA requirements, immutable requests, account recovery, legal hold, fail-closed logging, operator management and anti-self-escalation, last-super-admin rule, CLI bootstrap lockout, operator email validation, every request logged with IP, platform chain tamper detection and an anchor that catches a full rewrite |
| `test_activity.py` | activity log: sign-in success/failure with IP and user agent, changes with SUCCESS/DENIED/FAILURE, sensitive vs routine reads, admin-only access, tenant isolation, immutability for the app role and the table owner, spoofed `X-Forwarded-For` ignored, token reuse and sign-out, filters (actor, action, IP/CIDR, outcome, method, time), pagination, CSV/JSON export with formula-injection defence |
| `test_sdk.py` | Python SDK retry/backoff/`Retry-After`/error mapping, cursor iteration, webhook verification (valid, altered, wrong secret, replayed, malformed) against the server's signer |

## Not covered (and how to cover it)

* **Browser end-to-end tests.** The UI was exercised manually in a browser (every route loads without errors; sign-in, explain, lineage, time travel, verification) and its scripts are syntax-checked in CI, but there is no automated UI suite. Add Playwright against `docker compose up` for regression protection.
* **Load and soak tests.** See measurements below; there is no sustained-load suite.
* **Docker image and CI workflow** were not executed by the authors' environment.
* **TypeScript SDK** has no automated tests in this repository (it was run against a live server by hand). Python SDK has unit tests.
* **Penetration testing** and fuzzing.

## Measurements

Developer laptop, local PostgreSQL 16 with default settings, one organization, Python threads as clients. **Indicative only; not a capacity guarantee.**

| Workload | Result |
|---|---|
| single-row audited insert, 1 client | ≈ 1,400 transactions/s |
| same, 4–8 clients (one organization) | ≈ 3,000 transactions/s (bounded by the per-organization chain-head lock at commit) |
| order workflow (customer, product, order, line → 5 audited rows + trigger-derived total) , 8 clients | ≈ 1,200 workflows/s |
| full chain verification | ≈ 1,650 records in 10 ms (≈ 150k records/s, single connection) |
| audit row size | ≈ 1.1 KB including all indexes |

Reproduce with `python scripts/bench.py` (development database only).

## Continuous integration

`.github/workflows/ci.yml` runs, against a PostgreSQL 16 service: ruff, mypy, pytest, migrations from empty and re-run, `pip-audit`, JavaScript syntax checks, and a Docker build. **Any failing test fails the build; there are no skipped or expected-failure tests.**
