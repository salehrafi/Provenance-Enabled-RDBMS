# ADR 0002: Row-level security with a transaction-local tenant context

Status: accepted · Date: 2026-11-13

## Context
Tenant isolation must fail closed, survive application bugs, work with connection pooling, and not depend on every query remembering `WHERE tenant_id = ...`.

## Decision
* Every tenant table gets `tenant_id DEFAULT current_tenant_id()` and an RLS policy `USING / WITH CHECK (tenant_id = (SELECT current_tenant_id()))`.
* The API sets the context with `set_config('app.tenant_id', ..., true)` as the first statement of each transaction. Transaction-local means it vanishes on COMMIT/ROLLBACK, so a pooled (or PgBouncer transaction-mode) connection cannot carry it to another request.
* The runtime role is `NOSUPERUSER NOBYPASSRLS` and owns nothing; migrations run as a separate owner role.
* Authentication needs lookups before the tenant is known. These go through four narrow `SECURITY DEFINER` functions (exact-key lookups, pinned `search_path`) instead of exempting tables from RLS.
* Composite `(tenant_id, id)` foreign keys prevent cross-tenant references even if RLS is bypassed.

## Consequences
* A missing context yields zero rows (tested), not an error that could be swallowed.
* RLS does **not** defend against arbitrary SQL execution as the runtime role, which can set the tenant itself. This is a stated limitation (SECURITY.md); customers needing stronger isolation should use separate databases.
* A test asserts every table with `tenant_id` has RLS enabled and a policy.
* Small planner cost from the policy; `(SELECT current_tenant_id())` lets PostgreSQL evaluate it once per statement.
