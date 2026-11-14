# Architecture decision records

| # | Decision |
|---|---|
| [0001](0001-postgresql-over-oracle.md) | PostgreSQL instead of Oracle |
| [0002](0002-rls-with-transaction-local-context.md) | Row-level security with a transaction-local tenant context |
| [0003](0003-commit-time-sealing-and-signed-checkpoints.md) | Seal the audit chain at commit; sign checkpoints outside the database |
| [0004](0004-modular-monolith.md) | Modular monolith, one database, one worker process |
| [0005](0005-plain-sql-with-psycopg.md) | Plain SQL with psycopg 3 instead of an ORM |
| [0006](0006-no-build-frontend.md) | Dependency-free ES-module frontend served by the API |
| [0007](0007-outbox-leases-at-least-once.md) | Transactional outbox with leased, at-least-once webhook delivery |
| [0008](0008-permissions-roles-and-key-scopes.md) | Permissions as the unit of authorization |
| [0009](0009-platform-admin-and-break-glass.md) | Platform administration without default data access; two-person break-glass |

Format: context, decision, consequences. When a decision changes, add a new numbered record that supersedes the old one; do not rewrite history.
