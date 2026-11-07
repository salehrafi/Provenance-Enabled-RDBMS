"""Oracle access layer.

Every request gets a pooled PROV_APP connection with the Oracle application context
(PROV_CTX) set to the caller's tenant and user. VPD policies use that context to filter
rows, and the audit triggers use it to record who made each change.
"""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Iterator

import oracledb

from app.config import get_settings

log = logging.getLogger("app.db")

oracledb.defaults.fetch_lobs = False  # CLOBs come back as str
oracledb.defaults.fetch_decimals = True  # NUMBER -> Decimal, never float

_pool: oracledb.ConnectionPool | None = None


def _session_callback(conn: oracledb.Connection, requested_tag: str | None) -> None:
    settings = get_settings()
    with conn.cursor() as cur:
        cur.execute(f"ALTER SESSION SET CURRENT_SCHEMA = {settings.db_schema}")
        cur.execute("ALTER SESSION SET TIME_ZONE = '+00:00'")


def init_pool() -> oracledb.ConnectionPool:
    global _pool
    if _pool is None:
        s = get_settings()
        _pool = oracledb.create_pool(
            user=s.db_app_user,
            password=s.db_app_password,
            dsn=s.db_dsn,
            min=s.db_pool_min,
            max=s.db_pool_max,
            increment=1,
            session_callback=_session_callback,
            getmode=oracledb.POOL_GETMODE_TIMEDWAIT,
            wait_timeout=10_000,
        )
        log.info("oracle pool created dsn=%s user=%s", s.db_dsn, s.db_app_user)
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close(force=True)
        _pool = None


def _convert(value: Any) -> Any:
    # All timestamps are stored as UTC without a zone; make that explicit for clients.
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def to_db_time(value: datetime) -> datetime:
    """Convert an aware datetime to the naive-UTC form stored in the database."""
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _prepare(cur: oracledb.Cursor, params: dict | None) -> dict:
    """Bind datetimes as TIMESTAMP (python-oracledb defaults to DATE, dropping microseconds)."""
    if not params:
        return {}
    params = {k: to_db_time(v) if isinstance(v, datetime) else v for k, v in params.items()}
    sizes = {k: oracledb.DB_TYPE_TIMESTAMP for k, v in params.items() if isinstance(v, datetime)}
    if sizes:
        cur.setinputsizes(**sizes)
    return params


class Db:
    """Thin helper around a connection: dict rows, explicit commits."""

    def __init__(self, conn: oracledb.Connection):
        self.conn = conn

    def _rows(self, cur: oracledb.Cursor) -> list[dict[str, Any]]:
        cols = [d[0].lower() for d in cur.description]
        return [{c: _convert(v) for c, v in zip(cols, row)} for row in cur.fetchall()]

    def all(self, sql: str, params: dict | None = None) -> list[dict[str, Any]]:
        with self.conn.cursor() as cur:
            cur.execute(sql, _prepare(cur, params))
            return self._rows(cur)

    def one(self, sql: str, params: dict | None = None) -> dict[str, Any] | None:
        rows = self.all(sql, params)
        return rows[0] if rows else None

    def scalar(self, sql: str, params: dict | None = None) -> Any:
        with self.conn.cursor() as cur:
            cur.execute(sql, _prepare(cur, params))
            row = cur.fetchone()
            return _convert(row[0]) if row else None

    def execute(self, sql: str, params: dict | None = None) -> int:
        with self.conn.cursor() as cur:
            cur.execute(sql, _prepare(cur, params))
            return cur.rowcount

    def insert(self, sql: str, params: dict, returning: str) -> int:
        """Run an INSERT ... RETURNING <col> INTO :new_id and return the new id."""
        with self.conn.cursor() as cur:
            new_id = cur.var(oracledb.DB_TYPE_NUMBER)
            cur.execute(f"{sql} RETURNING {returning} INTO :new_id", {**_prepare(cur, params), "new_id": new_id})
            return int(new_id.getvalue()[0])

    def callproc(self, name: str, params: list | None = None) -> list:
        with self.conn.cursor() as cur:
            return cur.callproc(name, params or [])

    def cursor(self) -> oracledb.Cursor:
        return self.conn.cursor()

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()


def parse_json(value: Any) -> Any:
    # python-oracledb may already decode IS JSON columns (depends on query shape)
    if value is None or isinstance(value, (dict, list)):
        return value
    # parse_float=Decimal keeps money exact (1099.99 stays 1099.99, not a binary float)
    return json.loads(value, parse_float=Decimal) if value else None


@contextmanager
def tenant_session(
    tenant_id: int | None,
    user_id: int | None,
    username: str,
    request_id: str | None,
) -> Iterator[Db]:
    """Acquire a pooled connection scoped to one tenant and actor.

    Uncommitted work is rolled back and the context is cleared before the connection goes
    back to the pool, so state can never leak between requests or tenants.
    """
    pool = init_pool()
    conn = pool.acquire()
    try:
        with conn.cursor() as cur:
            cur.callproc("ctx_pkg.set_ctx", [tenant_id, user_id, username, request_id])
        yield Db(conn)
    finally:
        try:
            conn.rollback()
            with conn.cursor() as cur:
                cur.callproc("ctx_pkg.clear_ctx")
        except oracledb.Error:
            log.exception("failed to reset session before release")
        pool.release(conn)


@contextmanager
def system_session() -> Iterator[Db]:
    """Connection with no tenant context: only non-VPD tables (tenants, app_users) are visible."""
    with tenant_session(None, None, "system", None) as db:
        yield db
