# Operations

## Service-level targets

These are **design targets** for a standard deployment (managed PostgreSQL with automated backups and WAL archiving, ≥ 2 API replicas, ≥ 2 workers). They are not measured SLAs; confirm them with your own drill.

| Objective | Target | How it is achieved |
|---|---|---|
| **RPO** (data loss) | ≤ 5 minutes with WAL archiving / PITR; ≤ 24 hours with nightly logical backups only | Continuous WAL archiving (managed-service PITR or `archive_command`) plus `scripts/backup.sh` |
| **RTO** (time to restore service) | ≤ 1 hour for a single-region restore of a database under ~100 GB; API/worker redeploy < 10 min | Restore latest base backup + WAL, run `scripts/restore_check.sh`, redeploy stateless services |
| Webhook delivery | at-least-once; first attempt within seconds; retries for about 8 hours (12 attempts, 15 s doubling, capped at 6 h) before dead-letter | outbox + leases |
| Integrity detection latency | ≤ 1 hour (full verification interval); checkpoints every 5 minutes | worker |

## What to monitor

`GET /metrics` (Prometheus text, per process), `GET /ready`, structured logs.

| Signal | Alert when |
|---|---|
| `GET /ready` ≠ 200 | any |
| `http_requests_total{status=~"5.."}` rate | > 1 % of requests for 5 min |
| `http_request_duration_seconds` p95 | > 1 s for 10 min |
| `db_pool_requests_waiting`, `db_pool_requests_errors` | waiting > 0 for 1 min (pool exhausted) |
| `worker_last_dispatch_timestamp`, `worker_last_checkpoint_timestamp` | older than 5× the interval (worker down) |
| Alerts in the product: `DQ004` (CRITICAL) | **any**: audit chain or checkpoint verification failed; treat as a security incident |
| `WH001` alerts / `dead` deliveries | rising: a customer endpoint is down |
| PostgreSQL: replication lag, disk, `max_connections`, long transactions, lock waits | standard thresholds |

Logs are one JSON object per line on stdout with `request_id`, `tenant_id`, `actor`, `method`, `path`, `status`, `ms`. Ship them to your log platform; the request id is also stored in the audit log, so a log line leads to the exact changes a request made (`GET /provenance/requests/{id}`).

## Backups

Two complementary layers.

**1. Logical backup (portable, easy to test).**
```bash
PGURL=postgresql://postgres:...@db:5432/provenance scripts/backup.sh /var/backups/provenance
```
Writes a custom-format dump of schema `prov` and a `.sha256`. Schedule nightly, encrypt at rest, copy off-host, retain per your policy.

**2. Continuous WAL archiving / PITR** for the 5-minute RPO. On managed PostgreSQL enable the provider's point-in-time recovery. Self-run: base backups (`pg_basebackup`) + `archive_command` to object storage.

**Prove restores, regularly (at least monthly and after any schema change):**
```bash
ADMIN_URL=postgresql://postgres:...@db:5432/postgres DATABASE_URL=postgresql://prov_app:...@db:5432/provenance \
  scripts/restore_check.sh /var/backups/provenance/provenance-<stamp>.dump
```
It verifies the checksum, restores into a throw-away database, runs the **full hash-chain and checkpoint verification for every organization** against the restored copy, and drops it. Exit status 0 means the backup is restorable *and* its history is intact. (Verified in development: 35- and 3-record chains restored and verified.)

**What a backup does not contain:** the secrets. Keep `JWT_SECRET`, `DATA_ENCRYPTION_KEY` and `CHECKPOINT_SIGNING_KEY` in your secret manager. Without `DATA_ENCRYPTION_KEY`, restored webhook secrets cannot be decrypted (rotate them); without the signing key, new checkpoints use a new key and old ones are reported as "unknown key".

## Disaster recovery runbook

1. **Declare** and freeze writes (stop API replicas; leave the worker stopped).
2. **Restore** the database: PITR to the last good time, or `pg_restore` the latest dump into a fresh cluster. Create roles first (`python -m app.cli bootstrap` with the admin URL), then `pg_restore --role=prov_owner --no-owner`.
3. **Verify:** `python -m app.cli verify` (every organization's chain + checkpoints must be `ok`). Compare against any checkpoints customers or your anchor file hold; a mismatch means the restore point is *older* than data they saw, or history was altered.
4. **Redeploy** API and worker with the original secrets; check `/ready`.
5. **Reconcile** after PITR: events ingested after the restore point were lost from our side; senders retry idempotently (stable event ids), and `POST /reconciliations` reveals any remaining gaps.
6. **Review** `DQ004`/`WH001` alerts and the dead-letter list; communicate to affected customers.

## Runbooks

| Symptom | Likely cause and action |
|---|---|
| `DQ004` CRITICAL / `audit.integrity_failed` | Run `POST /audit/verify` for the exact record and reason. "hash mismatch": a record was edited. "Record missing": deletion. "history was rewritten": a stored/external checkpoint disagrees with the chain. Preserve the database and logs, restore from backup into a side database and compare. Do not "fix" rows in place. |
| API 503 `UNAVAILABLE` | connection pool exhausted: raise `DB_POOL_MAX` (and PostgreSQL `max_connections`) or add PgBouncer; look for slow queries/long transactions. |
| API 409 `RETRY` | deadlock or lock timeout under contention; clients should retry (SDKs do not retry 409). Investigate hot rows if frequent. |
| Deliveries stuck `FAILED` | customer endpoint down or slow (timeout 5 s); they retry automatically; see the delivery log (HTTP code, snippet). `DEAD` ones need *Retry* once the endpoint is fixed. |
| Webhook "resolves to a private or internal address" | the hostname now points inside your network (or DNS changed): working as intended. |
| Worker not delivering | check `worker_last_dispatch_timestamp`, logs for `worker failed for tenant`; confirm `DATABASE_URL` and that `prov.worker_tenants()` returns ids. |
| `Unsafe configuration` at startup | run `python -m app.cli check` and fix each item. |
| Refresh tokens revoked unexpectedly | `security.refresh_token_reuse` event: a rotated token was replayed (possible theft). Contact the user, force password change. |

## Routine tasks

| Task | How |
|---|---|
| Rotate a webhook secret | UI *Webhooks → Rotate secret* or `POST /webhooks/{id}/rotate-secret`; update the receiver first |
| Revoke an API key | UI or `DELETE /api-keys/{key_id}` (immediate) |
| Force a user out | deactivate (`PATCH /users/{id}`) or the user's *Sign out everywhere* |
| Verify now / checkpoint now | `POST /audit/verify`, `POST /audit/checkpoints` |
| Prune | automatic; `prune_operational_data()` never touches `audit_log`, `audit_checkpoints`, `external_events` |
| Vacuum/analyze | autovacuum; consider tighter settings on `outbox_events` and `webhook_deliveries` (high churn) |

## Troubleshooting setup

| Problem | Fix |
|---|---|
| `DATABASE_URL is not set` | `python -m app.cli init` writes `.env` |
| `permission denied for schema prov` | `python -m app.cli bootstrap` was not run, or the connection is not `prov_app` |
| `role "prov_app" does not exist` | run `python -m app.cli setup` with `DATABASE_ADMIN_URL` set |
| Migrations fail with "must be owner" | `DATABASE_OWNER_URL` must connect as `prov_owner` |
| Tests: `DATABASE_ADMIN_URL is not set` | tests need a PostgreSQL superuser URL; see [TESTING](TESTING.md) |
| `invalid value for parameter "TimeZone"` starting the bundled dev server | the dev build has no tz database; `dev_postgres.py` avoids setting it. Use a normal PostgreSQL elsewhere. |
