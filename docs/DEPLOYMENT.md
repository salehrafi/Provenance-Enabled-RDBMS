# Deployment

> **Verification status.** The application, migrations, worker, backup and restore scripts were exercised in development against PostgreSQL 16. The `Dockerfile`, `docker-compose.yml` and the GitHub Actions workflow were written carefully but **have not been executed** (no Docker in the authoring environment). Build and smoke-test them in a staging environment before relying on them.

## Topology

```
Internet ─ TLS ─▶ reverse proxy / load balancer ─▶ API replicas (N) ─┐
                                                     worker (1..M) ──┼─▶ PostgreSQL 16 (primary + backups/WAL)
                                                     Redis (optional)┘
```

* **Required:** PostgreSQL 16 (managed or self-run), the API, one worker.
* **Optional:** Redis (shared rate limits across replicas). Without it limits are per process; the app keeps working if Redis is down.
* **You supply:** TLS termination, secret injection, backups, monitoring, log shipping.

## Docker Compose (single host)

```bash
cp .env.docker.example .env.docker      # replace every change-me
docker compose --env-file .env.docker up --build -d
curl -fsS localhost:8000/ready
```

`setup` creates the roles and schema and runs migrations, then exits; `api` and `worker` start after it succeeds. Run replicas with `docker compose up --scale api=3` behind your proxy (remove the fixed `ports` mapping first). PostgreSQL is **not** published to the host.

## Any other platform (Kubernetes, ECS, VMs)

1. **Database.** Provision PostgreSQL 16. As a superuser, once:
   ```bash
   DATABASE_ADMIN_URL=postgresql://admin:...@db/postgres DATABASE_URL=... DATABASE_OWNER_URL=... python -m app.cli bootstrap
   ```
   creates `prov_owner`, `prov_app`, the `provenance` database and schema `prov` (roles are `NOSUPERUSER NOBYPASSRLS`). On managed services where you cannot be superuser, create the two roles/database yourself with the same attributes, `GRANT CONNECT`, and `CREATE SCHEMA prov AUTHORIZATION prov_owner`.
2. **Migrations** as a release step (job/init container), *not* from every API replica:
   ```bash
   python -m app.cli migrate        # needs DATABASE_OWNER_URL only
   ```
3. **API:** `uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips <proxy ip/cidr>` with `ENVIRONMENT=production`. It needs only `DATABASE_URL` (the `prov_app` role); give it no owner or admin credentials.
4. **First platform operator (once):** `python -m app.cli create-platform-admin --email ... --name ...` (needs `DATABASE_PLATFORM_URL`). Restrict `/platform` and `/api/platform/` to an internal network at the proxy if you can. See [PLATFORM_ADMIN](PLATFORM_ADMIN.md).
5. **Worker:** `python -m app.worker`, same image and environment, `WORKERS_ENABLED=false` on the API. Run ≥ 1 (2 for availability; they coordinate safely).
5. **Probes:** liveness `GET /health`; readiness `GET /ready` (checks the database). Scrape `GET /metrics` per instance, restricted at the proxy.
6. **Shutdown:** the worker handles SIGTERM; deliveries in flight are re-leased after `WEBHOOK_LEASE_SECONDS` (60 s).

### Sizing starting points
API: 2 replicas × 2 uvicorn workers, `DB_POOL_MAX=10` each → 40 connections maximum; keep the total under PostgreSQL `max_connections` minus headroom, or use PgBouncer in **transaction mode** with `DB_PREPARED_STATEMENTS=false`. These are starting points, not benchmarked capacity ([TESTING](TESTING.md#measurements)).

## Configuration reference

Environment variables (a `.env` file is read in development). **Bold** = required in production.

| Variable | Default | Meaning |
|---|---|---|
| `ENVIRONMENT` | `development` | `development`/`test` relax safety checks; anything else enforces them at startup |
| **`DATABASE_URL`** | | runtime connection as `prov_app` |
| `DATABASE_OWNER_URL` | | `prov_owner`, migrations only (leave unset on API/worker) |
| `DATABASE_PLATFORM_URL` | | platform console (role `prov_platform`); unset disables the console |
| `PLATFORM_ANCHOR_PATH` | | append-only file for platform checkpoints; put it on write-once storage |
| `PLATFORM_TOKEN_MINUTES` / `PLATFORM_MFA_FRESH_MINUTES` / `PLATFORM_CHECKPOINT_INTERVAL_SECONDS` | 30 / 5 / 300 | operator session length, step-up window, checkpoint cadence |
| `DATABASE_ADMIN_URL` | | superuser, `bootstrap` only (leave unset everywhere else) |
| `DB_POOL_MIN` / `DB_POOL_MAX` | 2 / 10 | per process |
| `DB_RECONNECT_TIMEOUT_SECONDS` | 15 | how long the pool retries before restarting its backoff after a database outage |
| `DB_STATEMENT_TIMEOUT_MS` / `DB_LOCK_TIMEOUT_MS` / `DB_IDLE_IN_TRANSACTION_TIMEOUT_MS` | 15000 / 10000 / 60000 | server-side limits per connection |
| `DB_PREPARED_STATEMENTS` | `true` | set `false` behind PgBouncer transaction mode |
| **`JWT_SECRET`** | | ≥ 32 chars |
| **`DATA_ENCRYPTION_KEY`** | | 32 random bytes, base64url (webhook secrets at rest) |
| **`CHECKPOINT_SIGNING_KEY`** | | 32-byte Ed25519 seed, base64url |
| `ACCESS_TOKEN_MINUTES` / `REFRESH_TOKEN_DAYS` | 15 / 14 | |
| `COOKIE_SECURE` | `true` | must be true outside development |
| `CORS_ORIGINS` | `[]` | JSON list of origins; never `*` in production |
| `LOGIN_RATE_LIMIT_PER_MINUTE` / `API_KEY_RATE_LIMIT_PER_MINUTE` / `USER_RATE_LIMIT_PER_MINUTE` | 10 / 600 / 600 | |
| `REDIS_URL` | | shared rate limits |
| `MAX_REQUEST_BYTES` | 6 MiB | |
| `ACTIVITY_LOG_READS` | `false` | also record every authenticated read in the activity log (changes, sign-ins and sensitive reads are always recorded) |
| `DOCS_ENABLED` | `true` | serve `/docs` and `/redoc` |
| `LOG_LEVEL` | `INFO` | JSON logs to stdout |
| `WORKERS_ENABLED` | `false` | embed a worker in the API process (laptops) |
| `DISPATCHER_INTERVAL_SECONDS` / `RULES_INTERVAL_SECONDS` | 2 / 60 | |
| `CHECKPOINT_INTERVAL_SECONDS` / `FULL_VERIFY_INTERVAL_SECONDS` | 300 / 3600 | checkpoint cadence; full chain re-verification cadence |
| `PRUNE_INTERVAL_SECONDS` / `DELIVERY_RETENTION_DAYS` | 3600 / 30 | housekeeping |
| `CHECKPOINT_ANCHOR_PATH` | | append-only JSONL file receiving every checkpoint |
| `WEBHOOK_TIMEOUT_SECONDS` / `WEBHOOK_MAX_ATTEMPTS` / `WEBHOOK_LEASE_SECONDS` | 5 / 12 / 60 | |
| `WEBHOOK_ALLOW_PRIVATE_URLS` / `WEBHOOK_ALLOW_HTTP` | `false` | development only; refused in production |
| `DEMO_PASSWORD` | | password for `app.cli seed` (development only) |

`python -m app.cli check` prints configuration problems and exits non-zero; the API and worker refuse to start in production while any exist.

### Generating secrets
```bash
python -c "import secrets,base64; print(secrets.token_urlsafe(48))"                                  # JWT_SECRET
python -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"  # DATA_ENCRYPTION_KEY, CHECKPOINT_SIGNING_KEY
```
Store them in your platform's secret manager and inject as environment variables. Keep a sealed offline copy of `CHECKPOINT_SIGNING_KEY` (or at least its public key, from `GET /audit/checkpoints`).

## Upgrading

1. Take a backup ([OPERATIONS](OPERATIONS.md#backups)).
2. Run `python -m app.cli migrate` with the new image.
3. Roll the API, then the worker. Write migrations so the previous release still works against the new schema for one version (expand → migrate → contract); that is what makes a rolling restart safe. Release notes call out any exception.
4. Roll back by redeploying the previous image; schema downgrades that delete data are blocked unless `ALLOW_DESTRUCTIVE_MIGRATION=yes`.

## Production checklist

- [ ] TLS in front; `COOKIE_SECURE=true`; HSTS reaches clients; `--forwarded-allow-ips` set to the proxy
- [ ] Secrets from a secret manager; none in the image or repository
- [ ] API/worker use `prov_app` only; owner and admin URLs absent at runtime
- [ ] PostgreSQL not reachable from the internet; TLS to the database (`sslmode=verify-full` in `DATABASE_URL`)
- [ ] Backups + WAL archiving enabled and a **restore drill completed** (`scripts/restore_check.sh`)
- [ ] Webhook subscriber for `audit.checkpoint` (or `CHECKPOINT_ANCHOR_PATH` on write-once storage)
- [ ] `/metrics` and `/ready` restricted at the proxy; alerts on the metrics listed in OPERATIONS
- [ ] `python -m app.cli check` passes
