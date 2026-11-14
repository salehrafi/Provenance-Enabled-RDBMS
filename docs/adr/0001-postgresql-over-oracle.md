# ADR 0001: PostgreSQL instead of Oracle

Status: accepted · Date: 2026-11-13

## Context
Version 2 used Oracle 19c: VPD for tenancy, `DBMS_CRYPTO` and PL/SQL packages for the audit chain, Flashback Query for history, and application contexts for request identity. VPD needs Enterprise Edition, the licence is commercial, the local install is heavy (SYSDBA OS authentication and a pluggable database), and there is no practical way to run it in CI or give a new developer a one-command setup.

## Decision
Use **PostgreSQL 16** as the only database. Rebuild rather than translate: row-level security replaces VPD, `set_config(..., is_local)` replaces the application context, PL/pgSQL triggers and `sha256()` replace the PL/SQL packages, and reconstruction from the audit log replaces Flashback.

## Consequences
* Free, ubiquitous, available as a managed service everywhere, runs as a CI service container.
* Tenancy, auditing and approval rules stay in the database (the property worth keeping from v2) and are now tested against the real engine in every build.
* Flashback's ability to read the physical past of any table is gone; reconstruction covers only changes captured by our triggers (documented in DATABASE.md).
* Existing Oracle data needs the documented export/import procedure; the old hash chain cannot be continued (MIGRATING_FROM_ORACLE.md).
