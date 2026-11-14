"""Helpers shared by migration scripts."""

from __future__ import annotations

import os
from pathlib import Path

from alembic import op

SQL_DIR = Path(__file__).parent / "sql"


def run_sql(sql: str) -> None:
    """Execute raw SQL on the migration connection.

    Goes straight to the psycopg connection instead of SQLAlchemy's text(), which would try to
    treat `:name` fragments inside PL/pgSQL bodies as bind parameters.
    """
    raw = op.get_bind().connection.dbapi_connection
    assert raw is not None
    raw.execute(sql)  # no parameters -> simple query protocol -> several statements allowed


def run_sql_file(name: str) -> None:
    run_sql((SQL_DIR / name).read_text(encoding="utf-8"))


def require_destructive_ok(what: str) -> None:
    """Downgrades that delete data only run when explicitly allowed."""
    if os.environ.get("ALLOW_DESTRUCTIVE_MIGRATION") != "yes":
        raise RuntimeError(
            f"Refusing to {what}: this permanently deletes data. Take a backup, then re-run with "
            "ALLOW_DESTRUCTIVE_MIGRATION=yes if that is really what you want."
        )
