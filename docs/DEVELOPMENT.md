# Development

## Setup

```bash
uv venv .venv --python 3.12
uv pip install --python .venv/Scripts/python.exe -r requirements-dev.txt     # .venv/bin/python on Linux/macOS
.venv/Scripts/python.exe scripts/dev_postgres.py start                        # or any PostgreSQL 16, see below
.venv/Scripts/python.exe -m app.cli init --port 54329
.venv/Scripts/python.exe -m app.cli setup
.venv/Scripts/python.exe -m app.cli seed
.venv/Scripts/python.exe -m uvicorn app.main:app --reload --port 8000
```

`scripts/dev_postgres.py start|stop|status|destroy` runs the PostgreSQL 16 binaries shipped in the `pgserver` wheel (Python < 3.13) with data in `.pgdata/`. It is **only** for development machines: `trust` authentication, no TLS, no timezone database (the app never relies on named time zones in SQL). With Docker, use `docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16` and `python -m app.cli init --port 5432 --admin-url postgresql://postgres:postgres@127.0.0.1:5432/postgres`.

Everything configurable is in `app/config.py` and documented in [DEPLOYMENT](DEPLOYMENT.md#configuration-reference). `.env` is git-ignored.

## Daily commands

```bash
pytest                          # full suite, ~20 s, real PostgreSQL
ruff check . && mypy            # lint + types (also run in CI)
python -m app.cli verify        # verify every organization's audit chain in your dev DB
python -m app.worker            # run the worker separately (or WORKERS_ENABLED=true)
```

## Code conventions

* **SQL, not an ORM.** Handlers call `ctx.db.one/all/scalar/execute` with `%s`/`%(name)s` parameters. Never format client input into SQL; dynamic identifiers must come from allow-lists or model field names (see `update_set`, `settings` update).
* **One transaction per request.** The connection is already tenant-scoped; commit explicitly when the work is done. Anything uncommitted is rolled back.
* **Permissions at the door.** Every endpoint takes `Depends(require("<permission>"))` (or `require_user` for actions that record a human decision). New permissions go in `app/auth.py` and into the roles that should have them.
* **Business rules in the database** when they must hold for every client (state machine, derived totals, four-eyes); Python only orchestrates. Errors use `PVxxx` SQLSTATEs mapped in `app/errors.py`.
* **Stable error codes.** Raise `ApiError(status, detail, "CODE")`; never leak database messages (unknown errors become a generic 500).
* **Typing.** `mypy` is clean for `app/`; keep it that way.
* **Frontend.** ES modules in `app/static/js`, no build step. Build DOM with `h()`; never use `innerHTML`.

## Adding a feature: checklist

1. **Schema:** add a *new* Alembic revision (`migrations/versions/NNNN_name.py`) that runs a SQL file in `migrations/sql/`. Never edit an applied revision. Every new tenant table needs: `tenant_id ... DEFAULT current_tenant_id()`, composite foreign keys, RLS enabled + the `tenant_isolation` policy, explicit grants to `prov_app`, an audit trigger if it holds business data. `tests/test_tenancy.py::test_every_tenant_table_has_forced_policy` will fail otherwise.
2. **Service + router:** logic in `app/services`, HTTP in `app/routers`; add the router in `app/main.py`.
3. **Tests:** at least a happy path, a permission test, and a cross-tenant test; plus concurrency/idempotency tests where relevant.
4. **Docs:** update [API](API.md) and the OpenAPI summaries (a test requires a summary on every operation), [DATABASE](DATABASE.md) if the schema changed, and the CHANGELOG.
5. `ruff check . && mypy && pytest`.

## Creating a migration

```bash
python -m alembic revision -m "add widgets"     # edit the generated file; call run_sql_file("0002_01_widgets.sql")
python -m app.cli migrate
```
Downgrade functions that delete data must call `require_destructive_ok(...)`.

## Debugging recipes

* *"Why did this value change?"* → UI Explorer, or `GET /provenance/{entity}/{pk}/history`; follow `request_id` to `GET /provenance/requests/{id}`.
* *"What does the database think the tenant is?"* → inside a `tenant_session`, `SELECT prov.current_tenant_id()`.
* *Webhook not arriving* → *Webhooks → delivery log*; for local receivers set `WEBHOOK_ALLOW_PRIVATE_URLS=true` and `WEBHOOK_ALLOW_HTTP=true` (development only; refused in production).
* *Reset local data* → `python scripts/dev_postgres.py destroy`, then `init`, `setup`, `seed`.
