# Integration guide

Goal: connect a data source, ingest events, explore provenance, reconstruct history and verify integrity, in about fifteen minutes.

## 1. Register the source

A *source* is an upstream system. **An admin** registers it and decides how much to trust it; the sender can never claim its own trust level.

| Field | Meaning |
|---|---|
| `code` | lowercase id, becomes the CloudEvents `source` (`legacy-shop`) |
| `capture_method` | `CDC` (log-based), `TRIGGER`, `API`, `POLLING`, `CSV_IMPORT`, `MANUAL` |
| `trust_level` | `HIGH` (captured at the database), `MEDIUM`, `LOW` (best effort/manual) |

UI: *Integrations → Sources*. API: `POST /api/v1/sources`. Pausing a source rejects new events with `409 SOURCE_PAUSED`.

## 2. Create an API key

*Integrations → API keys* (or `POST /api-keys`). Give it the **fewest scopes** it needs (a connector usually needs only `events:write`), and an expiry. The key is shown once.

## 3. Send events

Events are [CloudEvents 1.0](https://cloudevents.io) in structured JSON. Use `subject = "<entity>/<external id>"` and Debezium-style `data` to make records reconstructable and reconcilable.

```bash
curl -X POST $BASE/api/v1/events \
  -H "Authorization: Bearer $PROV_API_KEY" -H "Content-Type: application/json" \
  -d '{"specversion":"1.0","id":"legacy-evt-88421","source":"legacy-shop","type":"order.updated",
       "subject":"order/10045","time":"2026-11-07T10:12:03Z",
       "data":{"op":"u","before":{"status":"NEW","total":"1500.00"},"after":{"status":"NEW","total":"1200.00"}}}'
```

| Behaviour | Detail |
|---|---|
| Idempotent | `(source, id)` is unique. A resend returns **200** with `duplicate: true` and `identical: true|false` (false means you reused an id for different content, which is a bug on your side). The first send returns **201**. |
| Choose stable ids | Derive `id` from something that does not change on retry (a CDC LSN, a row version, an outbox id). The SDKs retry automatically and safely when the id and `time` are stable; **pass an explicit `time`**, otherwise a retry is a different event body. |
| `data.op` | `c` create, `u` update, `d` delete. `after` is the **complete** record after the change; a delete needs no `after`. |
| Out of order | Fine. State is resolved by `time` (when it happened), not arrival order. |
| Batch | `POST /events:batch` takes up to 500 events; each succeeds or fails independently (`results[i].status` = `created`/`duplicate`/`invalid`/`rejected`). |
| Limits | 256 KiB per event; 6 MiB per request. |
| Errors | `422 SOURCE_UNKNOWN`, `409 SOURCE_PAUSED`, `422 INVALID_SUBJECT`, `413`, `429` (back off per `Retry-After`). |

Every accepted event is itself written to the hash-chained audit log (attributed to `apikey:<name>`) and published to your webhooks as `external_event.created`.

### Python
```python
from datetime import datetime, timezone
from provenance_cloud import Client
pc = Client("https://provenance.example.com", api_key="prv_...")
pc.send_event(source="legacy-shop", id="legacy-evt-88421", type="order.updated", subject="order/10045",
              time=datetime(2026, 11, 7, 10, 12, 3, tzinfo=timezone.utc),
              data={"op": "u", "before": {"total": "1500.00"}, "after": {"total": "1200.00"}})
```

### TypeScript
```ts
import { Client } from "@provenance-cloud/client";
const pc = new Client("https://provenance.example.com", process.env.PROV_API_KEY!);
await pc.sendEvent({ id: "legacy-evt-88421", source: "legacy-shop", type: "order.updated", subject: "order/10045",
  time: "2026-11-07T10:12:03Z", data: { op: "u", before: { total: "1500.00" }, after: { total: "1200.00" } } });
```

### Systems with no API: CSV snapshots
*Integrations → CSV import*, or `POST /imports` (multipart: `file`, `source`, `entity`, `complete`, `dry_run`). One row per record with an `external_id` column plus any fields. We compare with the latest state we hold and record **only the differences**: created, updated (with before/after), and, if `complete=true`, deleted. Re-uploading the same file records nothing. Use **dry run** first.

## 4. Explore provenance

* **Explorer → External records**: pick the source and entity, set the *As of* time, open a record to see every version with the audit record that proves it.
* API: `GET /sources/{id}/records/{entity}/{external_id}/history | as-of?at=&known_at= | compare?t1=&t2=`.
* `at` = when it was true in the source; `known_at` = only use events we had received by then (*"what did we believe on the 3rd?"*).

## 5. Reconcile

Send the upstream system's *current* records and learn where it disagrees with the evidence we hold.

```bash
curl -X POST $BASE/api/v1/reconciliations -H "Authorization: Bearer $PROV_API_KEY" -H "Content-Type: application/json" \
  -d '{"source":"legacy-shop","entity":"order","complete":true,
       "records":[{"external_id":"10045","fields":{"total":"1200.00","status":"SHIPPED"}}]}'
```

| Outcome | Meaning |
|---|---|
| `MISMATCH` | a field differs, or we recorded a delete the upstream still shows |
| `MISSING` | upstream has it, we never received an event (a lost event) |
| `UNEXPECTED` | (`complete: true` only) we hold a live record upstream no longer lists |

Any discrepancy raises an `RC001` alert and a `reconciliation.completed` event. Numbers compare numerically (`"1200.00"` equals `1200`).

## 6. Receiving webhooks

*Webhooks → Add endpoint* (or `POST /webhooks`). Pick event types (`order.*`, `alert.raised`, `audit.checkpoint`, `*`). The signing secret is shown once.

Each delivery is a `POST` with JSON `{id, type, created_at, tenant_id, request_id, entity, entity_id, data}` and headers:

| Header | Use |
|---|---|
| `webhook-id` | stable per delivery **across retries**: deduplicate on it |
| `webhook-timestamp` | unix seconds: reject if older than ~5 min (replay protection) |
| `webhook-signature` | `v1,base64(HMAC-SHA256(base64decode(secret), "{id}.{timestamp}.{body}"))` |
| `X-Provenance-Event` | the event type |

Respond `2xx` quickly. Anything else (or a timeout, 5 s) is retried with exponential backoff (15 s doubling, ±20 %, capped at 6 h) up to 12 attempts, about 8 hours in total,, then marked `DEAD` and a `WH001` alert is raised. The UI's **delivery log** shows status, HTTP code, response snippet, duration and next attempt, with a *Retry* button and *Send test event*.

```python
from provenance_cloud import verify_webhook
verify_webhook(SECRET, request.headers, request.body)   # raises on bad signature or stale timestamp
```

Requirements for your endpoint: HTTPS, public address, no redirects. Delivery is **at-least-once**, and ordering is not guaranteed.

### Keep your own integrity checkpoints
Subscribe to `audit.checkpoint`. Each event carries `{chain_seq, row_hash, created_at, signature, key_id}`. Store them somewhere the database operators cannot modify. Later, `POST /audit/verify` with `{"checkpoints": [...]}` proves the history still matches what you saved. This is the one step that turns "tamper-evident against the application" into "tamper-evident against a hostile database administrator".

## 7. Verify and reconstruct

* *Audit & integrity → Verify now*, or `POST /audit/verify`.
* *Explorer*: any record, drag through its versions, or ask the server for its state at a time.
* `GET /provenance/requests/{id}`: everything one API call changed, including database-derived changes.

## Sandbox

New organizations can click **Load sample data** (dashboard or *Settings → Sandbox*) or call `POST /sandbox/sample-data`: three customers, four products, two orders (one paid and discounted so the deep-discount rule fires), a source `sample-shop` with a three-event history for `order/10045`, all labelled `[sample]` and written through the normal audited paths. There is no separate sandbox environment; use a second organization for experiments.

## Migrating history from another system
See [MIGRATING_FROM_ORACLE](MIGRATING_FROM_ORACLE.md): the same procedure (`scripts/import_legacy_history.py`) imports any JSONL change history.
