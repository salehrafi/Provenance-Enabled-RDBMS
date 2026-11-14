# Migrating from the Oracle version (v2)

Version 3 is a rebuild, not an in-place upgrade. There is **no mechanical SQL translation**: the schema, tenancy, hashing and history model changed. Read this whole page before touching production data.

## What carries over and what cannot

| v2 (Oracle) | v3 (PostgreSQL) | Migration |
|---|---|---|
| Business tables (customers, products, orders, items, payments) | Same tables, new types | Re-create records through the API (see below) |
| `audit_log` hash chain (DBMS_CRYPTO, `|`-joined preimage, Oracle timestamps) | Different preimage (JSON array), epoch-microsecond timestamps, commit-time sealing | **Cannot be continued.** The old chain stays verifiable *as an archive* with the old code; it is imported as external history, not as part of the new chain |
| Oracle VPD tenants | Row-level security | Re-created by creating organizations |
| Users and password hashes (Argon2) | `users` | Argon2 hashes are compatible; export/import with a script, or require a password reset |
| Webhook secrets (plain text in v2) | AES-256-GCM encrypted | Create new webhooks; rotate secrets |
| Oracle Flashback queries | Event-sourced `as-of` | Replaced; history before cutover comes from the imported audit history |

## Safe procedure

**0. Freeze and back up.** Take an Oracle Data Pump export and keep the `PROV_OWNER` schema read-only from here on. This is your rollback.

**1. Verify the old chain *before* exporting.** With v2 still running, call its `POST /api/v1/audit/verify` for every tenant (the v2 source is git commit `46ec882`; check it out to run it). Do not migrate history you cannot vouch for; if verification fails, stop and investigate, and record the failure.

**2. Export (Oracle side).** For each table export current rows as CSV, and the audit log as JSON Lines. In SQL*Plus:

```sql
SET PAGESIZE 0 LINESIZE 32767 LONG 1000000 FEEDBACK OFF TRIMSPOOL ON
SPOOL history.jsonl
SELECT JSON_OBJECT('id' VALUE 'oracle-audit-' || audit_id, 'tenant' VALUE tenant_id,
                   'entity' VALUE entity, 'record_pk' VALUE record_pk, 'operation' VALUE operation,
                   'old_values' VALUE old_values FORMAT JSON, 'new_values' VALUE new_values FORMAT JSON,
                   'changed_at' VALUE TO_CHAR(changed_at, 'YYYY-MM-DD"T"HH24:MI:SS.FF6"Z"'), 'actor' VALUE actor)
  FROM audit_log WHERE tenant_id = :tenant ORDER BY chain_seq;
SPOOL OFF
```

One file per tenant. Keep the original `row_hash`/`prev_hash` columns in a separate archive export; they are your proof of the old chain.

**3. Stand up v3** in staging ([DEPLOYMENT](DEPLOYMENT.md)); create the organization, then in *Integrations → Sources* register a source `legacy-oracle` (capture method **MANUAL**, trust **MEDIUM**) and an API key with `events:write`.

**4. Dry-run the import** (validates every line, sends nothing):
```bash
python scripts/import_legacy_history.py history.jsonl --url https://staging... --source legacy-oracle --api-key prv_... --dry-run
```

**5. Import.** Idempotent and resumable: each line's id (`oracle-audit-<id>`) is unique, so rerunning after an interruption reports already-present lines instead of duplicating.
```bash
python scripts/import_legacy_history.py history.jsonl --url ... --source legacy-oracle --api-key prv_...
```
It exits non-zero unless **created + already-present = lines in the file** and nothing failed. Each imported change is itself written into the v3 hash chain, with the original author preserved in the event (`legacyactor`).

**6. Load current business data** through the normal API (`POST /customers`, `/products`, `/orders` …) or CSV import against the `legacy-oracle` source, and keep the mapping from old to new ids in your migration notes. New ids are assigned by v3.

**7. Validate.**
1. **Counts:** lines in the file = imported + duplicates (the script checks this).
2. **State:** export current Oracle rows to CSV and run *Integrations → Reconciliation → Reconcile a file* (or `POST /reconciliations/upload`) per entity with `complete=true`. Expect zero MISMATCH/MISSING/UNEXPECTED. Investigate every difference.
3. **Chain:** `python -m app.cli verify` must report every organization `ok`.
4. Spot-check a few records in *Explorer → External records* against the Oracle archive.

**8. Cut over** only when validation is clean: point senders at v3, keep v2 read-only for a retention period.

## Rollback

* **Before cutover:** discard the staging database (or restore the pre-import backup: `scripts/backup.sh` before step 5, `pg_restore`/PITR to return). v2 was never modified, so nothing to undo there.
* **After cutover:** imported history is immutable by design (that is the point), so you cannot "undelete" it. Roll back by switching senders back to v2 (still intact and read-only), restoring v3 from the pre-cutover backup if you need a clean slate, and reconciling the gap with `POST /reconciliations`.
* Never edit v3 audit tables to "fix" an import. Import a corrective event instead, or restore from backup.

## Limits

* The Oracle chain's hashes are not re-validated inside v3; keep the Oracle export and the old verification code as the archive proof.
* Business tables are re-created, not copied row-for-row, so primary keys change.
* Row counts in the tens of millions need a batch job rather than the API; talk to your DBA about a direct `COPY` into a staging table and a controlled backfill, and keep the same verification steps.
