"""PostgreSQL access layer.

One pooled connection per request, logged in as `prov_app`. The tenant, the acting user and the
request id are set with `prov.set_context(...)` as the first statement of every transaction and
are transaction-local, so:

* row-level security filters every statement to the caller's tenant;
* the audit triggers know who is acting;
* nothing survives COMMIT/ROLLBACK, so pooled connections (and PgBouncer in transaction mode)
  can never carry one request's identity into the next.

`Db` re-applies the context lazily whenever a new transaction starts, so handlers may commit and
keep reading.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from functools import partial
from typing import Any

import psycopg
from psycopg import pq
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb, set_json_dumps, set_json_loads
from psycopg_pool import ConnectionPool

from app.config import get_settings

log = logging.getLogger("app.db")

Row = dict[str, Any]
Params = dict[str, Any] | Sequence[Any] | None


def json_default(o: Any) -> Any:
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    raise TypeError(f"not JSON serialisable: {type(o)}")


def dumps(value: Any) -> str:
    return json.dumps(value, default=json_default, separators=(",", ":"))


# jsonb in: Decimal and datetime aware. jsonb out: numbers with a fraction become Decimal so that
# money read back from the audit log is exact (1099.99 stays 1099.99, not a binary float).
set_json_dumps(dumps)
set_json_loads(partial(json.loads, parse_float=Decimal))


def jsonb(value: Any) -> Jsonb:
    return Jsonb(value)


def utc(value: datetime) -> datetime:
    """Normalise to an aware UTC datetime (naive input is taken to be UTC)."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _clean(row: Any) -> Row:
    for key, value in row.items():
        if isinstance(value, datetime) and value.tzinfo is not None:
            row[key] = value.astimezone(UTC)
    return row


_pool: ConnectionPool | None = None


def init_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        s = get_settings()
        if not s.database_url:
            raise RuntimeError("DATABASE_URL is not set. Run `python -m app.cli init` to create a .env file.")
        options = (
            f"-c search_path=prov -c statement_timeout={s.db_statement_timeout_ms} "
            f"-c lock_timeout={s.db_lock_timeout_ms} "
            f"-c idle_in_transaction_session_timeout={s.db_idle_in_transaction_timeout_ms}"
        )
        _pool = ConnectionPool(
            conninfo=s.database_url,
            min_size=s.db_pool_min,
            max_size=s.db_pool_max,
            timeout=s.db_pool_timeout_seconds,
            reconnect_timeout=s.db_reconnect_timeout_seconds,
            max_lifetime=1800,
            kwargs={
                "row_factory": dict_row,
                "options": options,
                "application_name": "provenance-cloud",
                "prepare_threshold": 5 if s.db_prepared_statements else None,
            },
            check=ConnectionPool.check_connection,  # drop connections the server closed
            open=False,
            name="provenance",
        )
        _pool.open(wait=True, timeout=s.db_pool_timeout_seconds)
        log.info("postgres pool opened min=%s max=%s", s.db_pool_min, s.db_pool_max)
    return _pool


def close_pool() -> None:
    global _pool, _platform_pool
    if _pool is not None:
        _pool.close()
        _pool = None
    if _platform_pool is not None:
        _platform_pool.close()
        _platform_pool = None


# ---- platform console pool (role prov_platform: no tenant tables, platform tables + narrow functions) ----
_platform_pool: ConnectionPool | None = None


def platform_enabled() -> bool:
    return bool(get_settings().database_platform_url)


def init_platform_pool() -> ConnectionPool:
    global _platform_pool
    if _platform_pool is None:
        s = get_settings()
        if not s.database_platform_url:
            raise RuntimeError("DATABASE_PLATFORM_URL is not set; the platform console is disabled.")
        _platform_pool = ConnectionPool(
            conninfo=s.database_platform_url, min_size=1, max_size=4, timeout=s.db_pool_timeout_seconds,
            reconnect_timeout=s.db_reconnect_timeout_seconds, max_lifetime=1800,
            kwargs={"row_factory": dict_row, "application_name": "provenance-platform",
                    "options": f"-c search_path=prov -c statement_timeout={s.db_statement_timeout_ms} "
                               f"-c lock_timeout={s.db_lock_timeout_ms}"},
            check=ConnectionPool.check_connection, open=False, name="platform")
        _platform_pool.open(wait=True, timeout=s.db_pool_timeout_seconds)
    return _platform_pool


@contextmanager
def platform_session() -> Iterator[Db]:
    with init_platform_pool().connection() as conn:
        try:
            yield Db(conn, Context(None, None, None, None), contextual=False)
        finally:
            if not conn.closed:
                conn.rollback()


def pool_stats() -> dict[str, int]:
    return dict(_pool.get_stats()) if _pool is not None else {}


@dataclass(frozen=True)
class Context:
    tenant_id: int | None
    user_id: int | None
    actor: str | None
    request_id: str | None


class Db:
    """Thin helper around one connection: dict rows, explicit commits, context per transaction."""

    def __init__(self, conn: psycopg.Connection, ctx: Context, contextual: bool = True):
        self.conn = conn
        self.ctx = ctx
        self.contextual = contextual  # False for the platform role, which has no tenant context at all

    def _begin(self) -> None:
        if self.contextual and self.conn.info.transaction_status == pq.TransactionStatus.IDLE:
            self.conn.execute(
                "SELECT prov.set_context(%s, %s, %s, %s)",
                (self.ctx.tenant_id, self.ctx.user_id, self.ctx.actor, self.ctx.request_id),
            )

    def use(self, ctx: Context) -> None:
        """Switch identity. Only allowed between transactions."""
        if self.conn.info.transaction_status != pq.TransactionStatus.IDLE:
            raise RuntimeError("cannot switch context inside a transaction")
        self.ctx = ctx

    def all(self, sql: str, params: Params = None) -> list[Row]:
        self._begin()
        return [_clean(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql: str, params: Params = None) -> Row | None:
        self._begin()
        row = self.conn.execute(sql, params).fetchone()
        return _clean(row) if row else None

    def scalar(self, sql: str, params: Params = None) -> Any:
        row = self.one(sql, params)
        return next(iter(row.values())) if row else None

    def execute(self, sql: str, params: Params = None) -> int:
        self._begin()
        return self.conn.execute(sql, params).rowcount

    def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None:
        self._begin()
        with self.conn.cursor() as cur:
            cur.executemany(sql, rows)

    def insert(self, sql: str, params: Params, returning: str) -> Any:
        """Run `INSERT ... RETURNING <col>` and return the new value."""
        return self.scalar(f"{sql} RETURNING {returning}", params)

    @contextmanager
    def savepoint(self) -> Iterator[None]:
        """A nested transaction. In PostgreSQL an error aborts the whole transaction unless the
        failing statement ran inside a savepoint, so per-item error handling needs one."""
        self._begin()
        with self.conn.transaction():
            yield

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()


@contextmanager
def session(tenant_id: int | None, user_id: int | None, actor: str | None, request_id: str | None) -> Iterator[Db]:
    """Borrow a connection scoped to one tenant and actor. Uncommitted work is rolled back."""
    with init_pool().connection() as conn:
        try:
            yield Db(conn, Context(tenant_id, user_id, actor, request_id))
        finally:
            # The pool would also roll back on return; doing it here keeps the intent explicit
            # and guarantees no half-finished transaction outlives the request.
            if not conn.closed:
                conn.rollback()


def tenant_session(tenant_id: int, user_id: int | None, actor: str | None, request_id: str | None) -> Any:
    return session(tenant_id, user_id, actor, request_id)


def system_session() -> Any:
    """No tenant: row-level security hides every tenant-owned row. Only the privileged entry
    points (auth lookups, sign-up, worker tenant list) are usable."""
    return session(None, None, "system", None)
