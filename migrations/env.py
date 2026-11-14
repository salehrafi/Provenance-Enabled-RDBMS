"""Alembic environment: runs migrations as the schema owner (DATABASE_OWNER_URL)."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool, text

from app.config import get_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def _url() -> str:
    url = get_settings().database_owner_url
    if not url:
        raise RuntimeError("DATABASE_OWNER_URL is not set (needed for migrations only)")
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        # One migration at a time across all deployers.
        connection.execute(text("SELECT pg_advisory_lock(727001)"))
        connection.execute(text("SET search_path = prov"))
        connection.commit()
        context.configure(connection=connection, target_metadata=None,
                          version_table="schema_version", version_table_schema="prov",
                          transaction_per_migration=True)
        with context.begin_transaction():
            context.run_migrations()
        connection.execute(text("SELECT pg_advisory_unlock(727001)"))
        connection.commit()


if context.is_offline_mode():
    raise RuntimeError("Offline (SQL script) mode is not supported: migrations execute PL/pgSQL files directly.")
run_migrations_online()
