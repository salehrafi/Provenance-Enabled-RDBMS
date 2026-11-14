"""Global administration and break-glass access: platform operators, platform audit chain, grants, guards.

Requires the database role prov_platform (created by `python -m app.cli bootstrap`).

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-14
"""

from migrations.helpers import require_destructive_ok, run_sql, run_sql_file

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    run_sql(
        """
        DO $$ BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'prov_platform') THEN
            RAISE EXCEPTION 'Role prov_platform does not exist. Run "python -m app.cli bootstrap" first.';
          END IF;
        END $$;
        """
    )
    run_sql_file("0003_01_platform.sql")


def downgrade() -> None:
    require_destructive_ok("drop platform operators, break-glass grants and the platform audit chain")
    run_sql(
        """
        DROP TABLE IF EXISTS prov.break_glass_grants, prov.platform_checkpoints, prov.platform_audit_log,
                             prov.platform_chain_head, prov.platform_users CASCADE;
        DROP FUNCTION IF EXISTS prov.platform_keep_one_super_admin(), prov.platform_audit_preimage(text, bigint, text, bigint, text, text, bigint, text, inet, text, text, timestamptz, jsonb),
          prov.platform_audit_seal(), prov.platform_audit_guard(),
          prov.platform_audit_append(text, bigint, text, text, bigint, text, text, text, text, jsonb),
          prov.platform_audit_verify(bigint, integer), prov.break_glass_guard(), prov.break_glass_insert_guard(),
          prov.break_glass_notify(), prov.breakglass_check(bigint, bigint, text), prov.breakglass_begin(bigint, bigint, text),
          prov.breakglass_list_users(bigint, bigint), prov.breakglass_recover_user(bigint, bigint, bigint, text, text, text),
          prov.platform_org_overview(), prov.platform_security_signals(integer), prov.platform_system_metrics(),
          prov.platform_set_tenant_status(bigint, text, text, text, text) CASCADE;
        ALTER TABLE prov.tenants DROP COLUMN IF EXISTS status_reason, DROP COLUMN IF EXISTS status;
        """
    )
