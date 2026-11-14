# ADR 0004: Modular monolith, one database, one worker process

Status: accepted · Date: 2026-11-13

## Context
The product's guarantees (audit chain, tenant isolation, transactional outbox) depend on one transactional boundary. The team is small and the load profile is OLTP-style.

## Decision
One FastAPI codebase organised as modules (routers → services → SQL), one PostgreSQL database, and one worker that is the same code run as a separate process. Scale horizontally by adding stateless API replicas and workers; workers coordinate with leases and `SKIP LOCKED`.

## Consequences
* Simple to run, test (one real database) and reason about. No distributed transactions, no service mesh.
* The per-organization chain head is a deliberate serialisation point; very large single tenants will need partitioning or sharding later (DATABASE.md, "Growth and partitioning").
* Module boundaries (services never import routers; routers hold little SQL beyond simple reads) keep extraction possible if a component such as webhook delivery needs to scale separately.
