"""Initial PostgreSQL schema: ledger, audit chain, governance, integration, row-level security.

Revision ID: 0001
Revises:
Create Date: 2026-11-13
"""

from migrations.helpers import require_destructive_ok, run_sql, run_sql_file

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

FILES = ("0001_01_core.sql", "0001_02_audit.sql", "0001_03_platform.sql", "0001_04_security.sql")


def upgrade() -> None:
    for name in FILES:
        run_sql_file(name)


def downgrade() -> None:
    require_destructive_ok("drop every table in schema prov")
    # schema_version lives in the same schema, so drop objects individually instead of the schema.
    run_sql(
        """
        DO $$
        DECLARE r record;
        BEGIN
          FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'prov' AND tablename <> 'schema_version' LOOP
            EXECUTE format('DROP TABLE IF EXISTS prov.%I CASCADE', r.tablename);
          END LOOP;
          FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'prov' LOOP
            EXECUTE format('DROP FUNCTION IF EXISTS %s CASCADE', r.sig);
          END LOOP;
        END $$;
        """
    )
