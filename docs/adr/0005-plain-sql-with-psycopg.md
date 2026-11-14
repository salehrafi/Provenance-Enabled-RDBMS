# ADR 0005: Plain SQL with psycopg 3 instead of an ORM

Status: accepted · Date: 2026-11-13

## Context
The product is database behaviour: triggers, RLS, locks, jsonb, `ON CONFLICT`, savepoints, `FOR UPDATE SKIP LOCKED`. ORMs abstract exactly the features we need to control.

## Decision
Use psycopg 3 with a connection pool and dict rows. Queries are SQL with bound parameters; Pydantic models validate requests. SQLAlchemy is a dependency of Alembic only.

## Consequences
* Full control of transactions, locking and the tenant-context protocol; it is easy to read what reaches the database.
* Responsibility for parameterisation sits with us: dynamic identifiers come only from allow-lists, enforced by review and tests (injection attempts, wildcard escaping).
* No automatic schema-model sync; migrations are hand-written SQL files executed by Alembic.
