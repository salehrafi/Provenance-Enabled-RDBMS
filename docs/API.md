# REST API

Base URL: `/api/v1`. Interactive docs: `/docs` (Swagger UI), `/redoc`, machine-readable spec: `/openapi.json`. The OpenAPI document is generated from the code, and a test asserts every operation has a summary and that every non-public operation rejects unauthenticated calls.

## Versioning and compatibility

* The version is in the path (`/api/v1`). Within a major version we only make **additive** changes: new endpoints, new optional request fields, new response fields, new enum values for *outputs*. Clients must ignore unknown response fields.
* Breaking changes ship as `/api/v2` alongside `/api/v1`, with the old version supported for at least 12 months and `Deprecation`/`Sunset` headers on affected responses (policy; no v2 exists yet).
* Request bodies reject unknown fields (`422`), so a typo is an error, not a silently ignored option.

## Authentication

| Caller | Header | Obtained from |
|---|---|---|
| Person | `Authorization: Bearer <access token>` (15 min) | `POST /auth/login` or `/auth/signup`; renew with `POST /auth/refresh` |
| System | `Authorization: Bearer prv_<id>_<secret>` | *Integrations → API keys* or `POST /api-keys` (shown once) |

`POST /auth/refresh` accepts the refresh token from the `prov_refresh` cookie (browser) or `{"refresh_token": "..."}` (other clients) and **rotates** it; always store the new one. Reusing an old refresh token revokes the whole session family.

API-key scopes: `events:write`, `events:read`, `audit:read`, `audit:verify`, `audit:export`.

## Conventions

**Errors** are `application/problem+json` (RFC 9457) with a stable `code`:

```json
{ "type": "about:blank", "title": "Conflict", "status": 409,
  "detail": "Invalid order status transition: CREATED -> SHIPPED",
  "instance": "/api/v1/orders/12/status", "code": "ORDER_INVALID_TRANSITION",
  "request_id": "9f2c…" }
```

Validation errors use `code: VALIDATION_ERROR` and add `errors: [{field, message}]`. Branch on `code`, show `detail`, quote `request_id` to support. Common codes: `UNAUTHENTICATED`, `TOKEN_EXPIRED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `RATE_LIMITED` (with `Retry-After`), `RETRY` (deadlock/lock timeout: repeat the call), `ORDER_INVALID_TRANSITION`, `ORDER_ITEMS_LOCKED`, `FOUR_EYES`, `STALE_REQUEST`, `SOURCE_UNKNOWN`, `SOURCE_PAUSED`, `IDEMPOTENCY_KEY_REUSED`, `PAYLOAD_TOO_LARGE`, `INVALID_WEBHOOK_URL`.

**Pagination**
* Offset pages (catalogue): `?limit=` (≤ 200) `&offset=` → `{items, total, limit, offset}`.
* Keyset (audit log, events): `?limit=` (≤ 500) plus `before_seq` / `cursor` / `before_id`; the response carries `next_*` (null at the end). Keyset pages stay correct while data is being written.

**Filtering**: documented per endpoint (e.g. `/audit?entity=&operation=&actor=&since=&until=&request_id=`, `/orders?status=&customer_id=`). Text filters are literal substrings (wildcards escaped).

**Time**: ISO 8601; naive values are treated as UTC; responses are UTC with offset.

**Idempotency**: send `Idempotency-Key: <8–200 printable chars>` on `POST /orders`, `/orders/{id}/payments`, `/customers`, `/products`. A repeat with the same key and body returns the original response with `Idempotent-Replayed: true`; the same key with a different body is `422 IDEMPOTENCY_KEY_REUSED`. Keys are per organization and kept 48 hours. Event ingestion is idempotent by `(source, id)` without a header.

**Tracing**: send `X-Request-ID` (≤ 64 chars `[A-Za-z0-9._-]`) or one is generated; it is echoed in the response, in error bodies, in logs, and recorded on every audit row the request caused, so `GET /provenance/requests/{id}` shows everything a call changed.

**Rate limits**: logins per address and account; API keys per key (`API_KEY_RATE_LIMIT_PER_MINUTE`, default 600); users per user. `429` with `Retry-After`.

## Endpoint map

| Area | Endpoints |
|---|---|
| Auth | `POST /auth/signup` `login` `refresh` `logout` `logout-all` `password`, `GET /auth/me` |
| Organization | `GET/POST /users`, `PATCH /users/{id}`, `GET /roles`, `GET/PATCH /settings`, `PATCH /organization` |
| Catalogue | `GET/POST /customers`, `GET/PATCH/DELETE /customers/{id}`, same for `/products` |
| Orders | `GET/POST /orders`, `GET /orders/{id}`, `POST/PUT/DELETE /orders/{id}/items[/{product_id}]`, `POST /orders/{id}/payments`, `POST /orders/{id}/status` |
| Provenance | `GET /provenance/{entity}/{pk}/history` `as-of?at=` `compare?t1=&t2=`, `GET /provenance/orders/{id}/explain` `lineage`, `GET /provenance/requests/{request_id}`, `GET /provenance/entities` |
| Audit & integrity | `GET /audit`, `GET /audit/{id}`, `GET /audit/export?format=csv\|json`, `POST /audit/verify`, `GET/POST /audit/checkpoints` |
| Ingestion | `POST /events`, `POST /events:batch`, `GET /ingested-events`, `POST /reconciliations` |
| Sources & records | `GET/POST /sources`, `PATCH /sources/{id}`, `GET /sources/{id}/events` `entities`, `GET /sources/{id}/records/{entity}` and `.../{external_id}/history\|as-of\|compare` |
| CSV | `POST /imports`, `POST /reconciliations/upload`, `GET /reconciliations[/{id}]` |
| Governance | `GET /alerts`, `PATCH /alerts/{id}`, `POST /alerts/run`, `GET /alerts/rules`, `GET /approvals`, `POST /approvals/{id}/approve\|reject` |
| Webhooks | `GET/POST /webhooks`, `PATCH/DELETE /webhooks/{id}`, `POST /webhooks/{id}/test` `rotate-secret`, `GET /webhooks/{id}/deliveries`, `POST /webhooks/deliveries/{id}/retry`, `GET /events`, `GET /event-types` |
| Keys | `GET/POST /api-keys`, `DELETE /api-keys/{key_id}` |
| Activity log (admins) | `GET /activity?actor=&action=&ip=&outcome=&method=&status_code=&request_id=&since=&until=&before_id=`, `GET /activity/{id}`, `GET /activity/export?format=csv\|json` (same filters), `GET /activity/summary`, `GET /activity/actions` |
| Sandbox | `POST /sandbox/sample-data` |
| Platform console (operators, separate API) | `/api/platform/v1`: `auth/login`, `auth/mfa/enroll`, `auth/step-up`, `auth/logout`, `me`, `health`, `organizations`, `organizations/{id}/suspend\|reactivate`, `security/signals`, `operators`, `break-glass` (request, approve, reject, activate, revoke, close, `data/{table}`, `history/{entity}/{pk}`, `users`, `users/{id}/{action}`), `audit`, `audit/export`, `audit/verify`, `audit/checkpoints`. See [PLATFORM_ADMIN](PLATFORM_ADMIN.md). |
| Ops (outside `/api/v1`) | `GET /health`, `GET /ready`, `GET /metrics` |

## Examples

**Explain an order total**
```bash
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/v1/provenance/orders/42/explain | jq '.summary, .checks'
```
```json
"Order 42 total is 1549.99 USD because it has 2 line(s) summing to 1549.99. Replaying 3 recorded change(s) reproduces that total."
{ "total_matches_lines": true, "replay_matches_total": true, "sum_of_lines": 1549.99, … }
```

**Rebuild an order as it was**
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/provenance/order/42/as-of?at=2026-11-01T09:00:00Z"
# → { existed, state: {status, total_amount…}, items: [...], payments: [...], based_on: {chain_seq, row_hash…} }
```

**Compare an external record at two times (and as we knew it)**
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/sources/3/records/order/10045/as-of?at=2026-11-05T00:00:00Z&known_at=2026-11-06T00:00:00Z"
```

**Verify integrity, including checkpoints you saved**
```bash
curl -s -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"checkpoints":[{"chain_seq":120,"row_hash":"…","created_at":"2026-11-13T10:00:00Z","signature":"…"}]}' \
  $BASE/api/v1/audit/verify
# → { "ok": false, "first_bad_seq": 120, "reason": "External checkpoint at record 120 does not match the chain (history was rewritten)" }
```

**Approve a price change (second admin)**
```bash
curl -s -X POST -H "Authorization: Bearer $ADMIN2" -H "Content-Type: application/json" \
  -d '{"note":"Supplier invoice attached"}' $BASE/api/v1/approvals/5/approve
```

## Webhook event types

`<entity>.created|updated|deleted` for `customer`, `product`, `order`, `order_item`, `payment`, `external_event`, `change_request`, `user`, `api_key`, `webhook`, `source`, `settings`, `organization`; plus `order.status_changed`, `change_request.submitted|approved|rejected`, `alert.raised`, `reconciliation.completed`, `audit.checkpoint`, `audit.integrity_failed`, `security.refresh_token_reuse`, `webhook.test`. The authoritative list is `GET /event-types`. Delivery format: [INTEGRATION_GUIDE](INTEGRATION_GUIDE.md#receiving-webhooks).

## SDKs

Python (`sdk/python`, `pip install ./sdk/python`) and TypeScript (`sdk/typescript`, Node 20+, zero dependencies). Both implement: send one/many events with retry, backoff and `Retry-After`; iterate ingested events; reconcile; verify audit; history and as-of; **webhook signature verification**. They are not published to PyPI/npm.
