"""Security activity log: append-only record of sign-ins, changes and sensitive reads, with client IP.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-14
"""

from migrations.helpers import require_destructive_ok, run_sql, run_sql_file

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    run_sql_file("0002_01_activity_log.sql")


def downgrade() -> None:
    require_destructive_ok("drop the activity log (every recorded sign-in and action)")
    run_sql("DROP TABLE IF EXISTS prov.activity_log CASCADE")
