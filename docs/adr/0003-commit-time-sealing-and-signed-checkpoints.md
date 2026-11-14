# ADR 0003: Seal the audit chain at commit; sign checkpoints outside the database

Status: accepted · Date: 2026-11-13

## Context
v2 appended to the hash chain inside each trigger while holding a per-tenant head-row lock for the rest of the transaction. That serialises all writers of an organization for the duration of their transactions and can deadlock with ordinary row locks. Separately, a hash chain alone cannot expose an attacker who recomputes every hash.

## Decision
1. Capture triggers insert **unsealed** audit rows (`chain_seq NULL`). A **deferred constraint trigger** seals each row at COMMIT: lock the head, `chain_seq = head + 1`, strictly increasing `changed_at`, `row_hash = SHA-256(JSON-array preimage)`, advance the head.
2. The preimage is a JSON array with epoch-microsecond timestamps, so it is unambiguous and independent of time zone.
3. A worker verifies the whole chain on a schedule and, only if it passes, signs `(tenant, chain_seq, row_hash, time)` with an **Ed25519 key the database never holds**. The checkpoint is stored, emitted as an `audit.checkpoint` event, and optionally appended to a file on storage the DBAs cannot write.
4. `audit_log`, checkpoints and external events are append-only by trigger and by privilege.

## Consequences
* The head lock is held only during commit; `chain_seq` is commit order, so as-of-time and as-of-sequence agree. Measured about 3,000 audited transactions per second per organization on a laptop.
* Detects edit, delete, reorder, truncation, unsealed inserts and, **with checkpoints**, a full rewrite. It does not defend against theft of the signing key, and a customer must actually keep copies of checkpoints for the strongest guarantee.
* Rows are briefly unsealed inside the writing transaction; no other session can see them.
* Superusers can disable triggers: for that actor the design relies on detection, not prevention.
