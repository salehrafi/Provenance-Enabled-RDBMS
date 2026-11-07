# Provenance Cloud: Full Documentation

This document explains the whole project in simple English. It is written for a new developer, a tester, or a business user who wants to understand what the system does and how to use it.

---

## Table of contents

1. [What is this project?](#1-what-is-this-project)
2. [Key ideas](#2-key-ideas)
3. [Architecture](#3-architecture)
4. [Project folder structure](#4-project-folder-structure)
5. [Setup and running](#5-setup-and-running)
6. [Demo users and data](#6-demo-users-and-data)
7. [Users, roles and login](#7-users-roles-and-login)
8. [Business rules](#8-business-rules)
9. [Provenance features](#9-provenance-features)
10. [Audit log and tamper detection](#10-audit-log-and-tamper-detection)
11. [Alerts and approvals](#11-alerts-and-approvals)
12. [Integrations (connecting other systems)](#12-integrations-connecting-other-systems)
13. [Webhooks](#13-webhooks)
14. [API reference](#14-api-reference)
15. [Errors](#15-errors)
16. [Configuration](#16-configuration)
17. [Database](#17-database)
18. [Testing](#18-testing)
19. [Security design](#19-security-design)
20. [Known limits](#20-known-limits)
21. [Glossary](#21-glossary)

---

## 1. What is this project?

Provenance Cloud is a web service for online shops and other businesses. It does two jobs:

1. **Runs a small e-commerce back office.** You can manage customers, products, orders, payments and order status.
2. **Keeps proof of every change.** Each change is written to an audit log, and the log is protected by a hash chain. So you can always answer:
   - **Why** is an order total what it is?
   - **Who** changed a price, and **when**?
   - **What** did the system look like last Tuesday?
   - **Was** the history changed afterwards?

The word "provenance" means the history or origin of a piece of data. That is the main idea of the project.

It also accepts data from other systems (a legacy shop, an ERP, a CSV export). It records that data as evidence too, and it can compare the other system's data with what it holds.

---

## 2. Key ideas

| Term | Simple meaning |
|---|---|
| **Tenant** | One customer organization, for example "Acme Electronics". Each tenant sees only its own data. |
| **Provenance** | The history of how a piece of data came to be. |
| **Audit log** | A list of every change: old value, new value, who did it, when. |
| **Hash chain** | Each audit row stores a fingerprint (SHA-256) of its content plus the fingerprint of the row before it. If anyone edits a row later, the chain breaks and we can see where. |
| **Trigger** | A rule inside the database that runs automatically when a row changes. We use triggers to write the audit log, so the application cannot skip it. |
| **VPD (Virtual Private Database)** | An Oracle feature that adds a hidden filter to every query, so a tenant only sees its own rows. |
| **Event** | A message saying "something changed". Events are stored in an outbox and sent to webhooks. |
| **Source** | An upstream system that sends data to us (for example "legacy-pos"). |
| **API key** | A secret token that a machine uses to call the API. |
| **Reconciliation** | Comparing another system's current data with our recorded evidence, and listing the differences. |
| **Maker-checker** | A rule where one person proposes a risky change and a different person approves it. |

---

## 3. Architecture

```
  Browser (web UI)            Other systems (legacy shop, ERP, CSV files)
        |                                   |
        | HTTPS + login token               | HTTPS + API key, or CSV upload
        v                                   v
  +--------------------------------------------------+
  |  FastAPI application (Python)                    |
  |  - checks login / API key and role               |
  |  - rate limits                                   |
  |  - sets the tenant and user on the database      |
  +--------------------------------------------------+
        |
        | one pooled connection per request
        v
  +--------------------------------------------------+
  |  Oracle database (pluggable database ORCLPDB)    |
  |  - tables with tenant_id                         |
  |  - VPD policy: "only this tenant's rows"         |
  |  - triggers: write audit log, keep order totals  |
  |  - audit_log: hash chained, append only          |
  |  - outbox_events: events for webhooks            |
  +--------------------------------------------------+
        ^
        | every 2 seconds (dispatch) and every 60 seconds (rules)
  +--------------------------------------------------+
  |  Background worker (a thread inside the app)     |
  |  - sends webhooks, retries failed ones           |
  |  - runs data quality and anomaly rules           |
  +--------------------------------------------------+
```

**Two database users**

- `PROV_OWNER` owns all tables, triggers and packages. It is used only by setup scripts and migrations.
- `PROV_APP` is what the application uses at runtime. It can read and write business tables, but it can only **read** the audit log. Only triggers can write audit rows. So even the application cannot forge history.

---

## 4. Project folder structure

```
Provenance-Enabled-RDBMS/
├── app/                      The application
│   ├── main.py               Starts the app, middleware, health checks, routes
│   ├── config.py             All settings (read from .env)
│   ├── db.py                 Oracle connection pool and tenant context
│   ├── security.py           Passwords, login tokens, API key helpers
│   ├── apiauth.py            API key check and scopes (for machines)
│   ├── deps.py               Login check and role check (for people)
│   ├── errors.py             Error responses (RFC 9457 format)
│   ├── ratelimit.py          Rate limiter (memory, or Redis)
│   ├── common.py             Small shared helpers
│   ├── schemas.py            Request shapes for most endpoints
│   ├── workers.py            Background worker thread
│   ├── migrate.py            Runs database migrations
│   ├── routers/              API endpoints, grouped by topic
│   │   ├── auth.py           Sign up, login, refresh, me
│   │   ├── users.py          Team members and settings
│   │   ├── catalog.py        Customers and products
│   │   ├── orders.py         Orders, items, payments, status
│   │   ├── audit.py          Audit log, export, verify, provenance
│   │   ├── governance.py     Alerts, approvals, webhooks, events, dashboard
│   │   ├── integration.py    Sources, API keys, CSV imports, reconciliation upload
│   │   ├── ingest.py         Event ingestion (API key), batch, reconciliation
│   │   └── dev.py            Local webhook receiver (development only)
│   ├── services/             The real logic
│   │   ├── provenance.py     Explain, history, time travel, lineage
│   │   ├── rules.py          Data quality and anomaly rules
│   │   ├── webhooks.py       Signing, delivery, retries
│   │   ├── ingestion.py      Recording one external event
│   │   ├── reconcile.py      Comparing snapshots with evidence
│   │   └── imports.py        CSV snapshot import
│   └── static/               The web UI (plain HTML, CSS, JavaScript)
├── db/
│   ├── bootstrap/            Creates and drops the two database users
│   └── migrations/           Database changes, in order (001 to 006)
├── scripts/
│   ├── setup_db.py           One command to set up the database
│   ├── seed.py               Loads demo data
│   └── tamper_demo.py        Shows that tampering is detected
├── tests/                    54 automatic tests
├── docs/                     This documentation
├── legacy/                   The first course version (Flask + SQLite), kept for reference
├── requirements.txt          Python packages
├── pytest.ini                Test settings
├── .env.example              Template for settings
└── README.md                 Short overview
```

---

## 5. Setup and running

### What you need

- Windows (commands below use PowerShell paths; they work on other systems with small changes)
- Oracle Database 19c or newer, with a pluggable database (the project uses `ORCLPDB`)
- SQL*Plus with OS login (`/ as sysdba`) on the machine
- Python 3.12 or newer
- Optional: Redis, only if you run several servers

### Steps

**1. Create the Python environment and install packages**

```bash
uv venv .venv --python 3.12
uv pip install --python .venv/Scripts/python.exe -r requirements.txt
```

**2. Create the database users and tables**

```bash
.venv/Scripts/python.exe scripts/setup_db.py
```

This creates a `.env` file with random secrets (if it does not exist), creates the two database users, and runs all migrations.

**3. Load demo data (optional, recommended for trying things out)**

```bash
.venv/Scripts/python.exe scripts/seed.py
```

**4. Start the server**

```bash
.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**5. Open the app**

- Web UI: http://127.0.0.1:8000
- API documentation (interactive): http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/health
- Readiness check (also tests the database): http://127.0.0.1:8000/ready

### Resetting everything

```bash
.venv/Scripts/python.exe scripts/setup_db.py --reset
.venv/Scripts/python.exe scripts/seed.py
```

**Warning:** `--reset` deletes all data in the project's two database users. Use it only on a test machine.

### Running the tests

```bash
.venv/Scripts/python.exe -m pytest
```

---

## 6. Demo users and data

After `seed.py`, these users exist. All of them use the password stored as `DEMO_PASSWORD` in your `.env` file.

| Email | Organization | Role | Can do |
|---|---|---|---|
| admin@acme.example.com | Acme Electronics | admin | Everything |
| approver@acme.example.com | Acme Electronics | admin | Approve price changes, manage everything |
| staff@acme.example.com | Acme Electronics | staff | Create and edit orders, customers, products |
| viewer@acme.example.com | Acme Electronics | viewer | Read only |
| admin@globex.example.com | Globex Retail | admin | Everything, but only for Globex (a separate organization) |

The demo data shows:

- Six orders, with payments, shipping and one refund.
- A price change that needed approval, and one that was made directly in the database (flagged by an alert).
- A legacy point-of-sale integration that sent events in a batch, plus a reconciliation with differences.
- A nightly warehouse CSV that was imported twice, showing that only changes are recorded.

---

## 7. Users, roles and login

### Roles

- **viewer**: can read data and audit logs.
- **staff**: viewer rights, plus create and change customers, products, orders and payments. Can upload CSV files.
- **admin**: staff rights, plus manage users, settings, webhooks, API keys, sources, and approve change requests.

### Login flow

1. Sign up with `POST /api/v1/auth/signup`. This creates a new organization and its first admin.
2. Log in with `POST /api/v1/auth/login` (email and password).
3. You get an `access_token` (valid 30 minutes by default) and a `refresh_token` (valid 7 days).
4. Send the access token in the header: `Authorization: Bearer <token>`.
5. When the access token expires, call `POST /api/v1/auth/refresh` with the refresh token.

Login attempts are rate limited (10 per minute per IP address by default).

Deactivated users are rejected immediately, even if their token has not expired yet, because every request checks the user in the database.

---

## 8. Business rules

These rules are enforced by the **database**, so they apply no matter which program writes the data.

### Order status

Only these moves are allowed:

```
CREATED ──► PAID ──► SHIPPED ──► DELIVERED
   │          │          │            │
   ▼          ▼          ▼            ▼
CANCELLED  REFUNDED   REFUNDED     REFUNDED
```

Any other move (for example SHIPPED back to CREATED) fails with an error.

### Order items

- Items can be added, changed or removed **only while the order is CREATED**. After payment they are locked.
- The order total is calculated by the database, from quantity × unit price of all items. You cannot set it directly.
- If you do not give a unit price, the current catalogue price is used. You can override the price (for example a discount). The override is flagged by a rule later.

### Payments

- Payments are allowed only on CREATED orders.
- A payment cannot be bigger than the balance still due.
- When the captured payments cover the total, the order moves to PAID automatically.
- Marking an order REFUNDED also marks its captured payments as REFUNDED.

### Product prices and approvals

- A price change smaller than the approval threshold (default **20%**) is applied right away.
- A bigger change is **not applied**. The API replies with status `202 Accepted` and creates a change request.
- Another admin (not the person who asked) must approve it. The approval updates the price and the audit record remembers the approval number.
- The threshold can be changed in Settings.

### Customers

- Email addresses are unique inside each organization.
- A customer who has orders cannot be deleted.

---

## 9. Provenance features

These are the questions the system can answer. All of them read from the audit log.

### Explain an order total (`GET /api/v1/provenance/orders/{id}/explain`)

Tells you the total in plain English, step by step. For example:

> Order 4 total is 1549.99 USD because it has 2 lines summing to 1549.99. Replaying 3 recorded changes reproduces that total.

It also checks each price against the catalogue price at order time, and shows whether replaying the audit log gives the same total as the stored total.

### History of one record (`GET /api/v1/provenance/{entity}/{id}/history`)

Every version of a record, with the changed fields, the person who made the change, and the time. Entities are: `customer`, `product`, `order`, `order_item`, `payment`, `external_event`.

### Lineage graph (`GET /api/v1/provenance/orders/{id}/lineage`)

A graph of everything connected to an order: the customer, items, products, payments, approvals and alerts. It also lists which change caused which other change, for example "order total was recalculated after an item change".

### Request trace (`GET /api/v1/provenance/requests/{request_id}`)

Every change one API request made, including changes made automatically by triggers in the same transaction. Each response has an `X-Request-ID` header, which you can use here.

### Time travel (`GET /api/v1/provenance/{entity}/{id}/as-of?at=...`)

Shows a record as it was at any moment in the past. It works by replaying the audit log, so it covers all history.

### Compare two moments (`GET /api/v1/provenance/{entity}/{id}/compare?t1=...&t2=...`)

Shows what changed between two times.

### Flashback (`GET /api/v1/provenance/{entity}/{id}/flashback?minutes_ago=...`)

Reads the live table as it was a few minutes ago, using Oracle's own undo data. It only reaches back as far as the database undo retention (15 minutes on the project's database). For older history, use `as-of`.

---

## 10. Audit log and tamper detection

### What is recorded

Every insert, update and delete on a business table creates one audit row. Each row contains:

- The entity and record ID
- The operation (INSERT, UPDATE or DELETE)
- Old values and new values (as JSON)
- The actor: the person's email, or `apikey:<name>` for machines, or `db:<user>` if someone changed the database directly
- The request ID, for linking with API calls
- The database user that made the change
- The timestamp (UTC)
- `prev_hash` and `row_hash`, the chain fingerprints

If a change does not alter any value, nothing is written.

### How the hash chain works

```
row 1:  hash = SHA-256( content of row 1 + "genesis" )
row 2:  hash = SHA-256( content of row 2 + hash of row 1 )
row 3:  hash = SHA-256( content of row 3 + hash of row 2 )
```

Every organization has its own chain.

### Verify the chain

- In the UI: Dashboard → **Verify chain now**, or Audit log → **Verify chain**.
- By API: `POST /api/v1/audit/verify`.

The result says whether the chain is intact. If not, it names the first broken record and the reason.

### Search and export

- `GET /api/v1/audit` filters by entity, record, operation, actor, request ID and time. It uses "before_id" paging.
- `GET /api/v1/audit/export?format=csv` or `format=json` downloads up to 50,000 rows (staff and above).

### Try it yourself

```bash
.venv/Scripts/python.exe scripts/tamper_demo.py
```

The script changes one audit row directly in the database, as the database owner, and then runs verification. Verification reports the exact record that was changed.

---

## 11. Alerts and approvals

### Alerts

The rules run every 60 seconds automatically. Admins and staff can also run them now with `POST /api/v1/alerts/run`.

| Code | Severity | What it finds |
|---|---|---|
| DQ001 | High | Captured payments are bigger than the order total |
| DQ002 | Critical | An order is shipped or delivered but not fully paid |
| DQ003 | Medium | An order that is past CREATED has no items |
| DQ004 | Critical | The audit hash chain is broken |
| AN001 | Medium or High | A product price changed by 30% or more (Medium if approved) |
| AN002 | Medium | An item was sold far below the list price **at the time of the order** |
| AN003 | High | A refund of 1000 or more (default) |
| AN004 | Medium | The same record was changed many times in a short time (default 5 times in 10 minutes) |
| AN005 | High | A change was made directly in the database, bypassing the app |
| RC001 | High | A reconciliation found differences |

Each finding becomes one alert. The same finding is not raised twice. Alerts can be **acknowledged** or **resolved**, and each new alert sends an `alert.raised` event.

### Approvals

- List: `GET /api/v1/approvals`
- Approve: `POST /api/v1/approvals/{id}/approve` (admin, and not the person who asked)
- Reject: `POST /api/v1/approvals/{id}/reject` (admin, and not the person who asked)

The database also checks this rule (a constraint named `CK_CR_FOUR_EYES`), so it cannot be bypassed by a direct SQL update.

If the price has changed since the request was made, approval is refused, and the request must be rejected.

---

## 12. Integrations (connecting other systems)

There are three ways to send data in. All three record the data as evidence and attribute it to the source.

### Concept: sources and trust

Before a system can send data, an admin **registers it as a source**:

```json
{
  "code": "legacy-pos",
  "name": "Legacy point-of-sale",
  "capture_method": "CDC",
  "trust_level": "HIGH"
}
```

- `capture_method` says how the data is collected: `CDC` (reading database changes), `TRIGGER`, `API`, `CSV_IMPORT`, `POLLING` or `MANUAL`.
- `trust_level` is `HIGH`, `MEDIUM` or `LOW`.

**The sender cannot change these values.** Only an admin can. So a CSV file can never claim to be HIGH trust by itself.

Sources can be paused. A paused source is refused until it is resumed.

### Option 1: API key and CloudEvents (for systems that can call an API)

1. An admin creates an API key with scopes `events:write` (send) and/or `events:read` (read back). The key looks like `prv_<id>_<secret>` and is shown **once**.
2. The system sends an event:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/events \
  -H "Authorization: Bearer prv_..." -H "Content-Type: application/json" \
  -d '{
    "specversion": "1.0",
    "id": "legacy-evt-88421",
    "source": "legacy-pos",
    "type": "order.updated",
    "subject": "order/10045",
    "time": "2026-11-07T10:12:03Z",
    "data": {"op": "u", "before": {"total": "1500.00"}, "after": {"total": "1200.00"}}
  }'
```

- `id` and `source` together identify an event. Sending the same event again is safe: the answer is `200` with `"duplicate": true`, and nothing new is stored.
- `subject` is `<entity>/<external id>`.
- `data.op` is `c` (create), `u` (update) or `d` (delete). The format follows Debezium, a common change-capture tool.
- Maximum event size: 32 KB.

**Batch:** `POST /api/v1/events:batch` takes an array of up to 500 events. Each event succeeds or fails on its own. The answer lists each result by its index.

**Read back:** `GET /api/v1/ingested-events` (needs `events:read`). Use the `cursor` parameter to get the next page.

### Option 2: CSV snapshot import (for systems that only export files)

A snapshot CSV has one row per record. The first column must be `external_id`. The other columns are the fields.

```csv
external_id,sku,on_hand,bin
W-1,LAP-14,40,A1
W-2,HP-PRO,120,A2
```

Upload it on the **Integrations** page, or call `POST /api/v1/imports` (multipart form with `file`, `source`, `entity`, `complete`, `dry_run`).

- The import compares each row with the latest recorded state.
- **Only real changes are recorded**: created, updated (with before and after values), and, when `complete=true`, deleted (rows that are missing from the new file).
- Uploading the same file twice records nothing new.
- `dry_run=true` shows what would be recorded, and writes nothing.
- Limits: 5 MB and 5,000 rows per file. Errors give the line number.

### Option 3: Reconciliation (checking another system's data)

Reconciliation asks: **does the other system's current data match the evidence we hold?**

- Send the other system's current records (by API: `POST /api/v1/reconciliations`; by file: `POST /api/v1/reconciliations/upload`).
- For each record we check the latest event we hold for it, and report:
  - **MISMATCH**: a field has a different value.
  - **MISSING**: the other system has it, but we never received an event for it.
  - **UNEXPECTED**: we hold a live record that the other system no longer has (only when `complete=true`).
  - **Matched**: everything agrees. Only the count is stored.
- Numbers compare by value, so `1200.00`, `1200` and `1200.0` are equal.
- Any discrepancy raises an **RC001** alert.
- Reconciliation does not record new events. It only reports.

### Making a request without a UI

Use the Integrations page to create keys, sources and imports. Everything is also available through the API. The `/docs` page lists every endpoint with example bodies.

---

## 13. Webhooks

A webhook is a URL on your side that we call when something happens.

### Create a webhook

`POST /api/v1/webhooks` with a URL and a list of event types. Event types can be exact (`order.created`), a whole group (`order.*`), or everything (`*`).

Examples of event types:

- `order.created`, `order.updated`, `order.status_changed`
- `product.updated`, `customer.created`, `payment.created`
- `alert.raised`, `change_request.created`, `change_request.approved`
- `external_event.created`, `reconciliation.completed`
- `webhook.test` (sent by the test button)

The signing secret is shown **once** when you create the webhook. Store it safely.

### What we send

A JSON body like this, with these headers:

```
webhook-id: msg_123            (same for every retry of this delivery)
webhook-timestamp: 1794000000  (Unix time in seconds)
webhook-signature: v1,<base64>
X-Provenance-Event: order.updated
```

### Verify the signature

The project follows the [Standard Webhooks](https://www.standardwebhooks.com/) specification. The signature is:

```
base64( HMAC_SHA256( key, "<webhook-id>.<webhook-timestamp>.<raw body>" ) )
```

where `key` is the secret without the `whsec_` prefix, decoded from base64. Most languages have a library for this. Use one if you can.

### Retries

If your server does not answer with 2xx, we retry with growing waits (about 10 s, 20 s, 40 s and so on). After 5 attempts (default) the delivery is marked **DEAD**. You can retry it from the Webhooks page or with `POST /api/v1/webhooks/deliveries/{id}/retry`.

### Security

Webhook URLs that point to private or internal addresses are blocked when `WEBHOOK_ALLOW_PRIVATE_URLS=false`. Turn this on in production, to prevent the server from being used to reach internal systems.

### Local testing

In development, the app has a built-in receiver at `POST /api/v1/dev/webhook-sink`. Create a webhook pointing to it, and you can see the deliveries in the Webhooks page.

---

## 14. API reference

All paths start with `/api/v1`. Full details with examples are at `/docs`.

Role abbreviations: **V** = viewer, **S** = staff, **A** = admin, **K** = API key with the scope shown.

### Authentication

| Method | Path | Who | Purpose |
|---|---|---|---|
| POST | /auth/signup | anyone | Create organization and admin |
| POST | /auth/login | anyone | Log in, get tokens |
| POST | /auth/token | anyone | Same as login, using form fields (for the "Authorize" button) |
| POST | /auth/refresh | anyone with refresh token | New token pair |
| GET | /auth/me | logged in | Current user and organization |

### Team and settings

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | /users | A | List team members |
| POST | /users | A | Invite a member |
| PATCH | /users/{id} | A | Change role, name or active status |
| GET | /settings | V | Thresholds and currency |
| PATCH | /settings | A | Change thresholds and currency |

### Customers and products

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | /customers | V | List and search customers |
| POST | /customers | S | Create |
| GET | /customers/{id} | V | Details with order count and lifetime value |
| PATCH | /customers/{id} | S | Update |
| DELETE | /customers/{id} | A | Delete (not if the customer has orders) |
| GET | /products | V | List, search, filter by active |
| POST | /products | S | Create |
| GET | /products/{id} | V | Details |
| PATCH | /products/{id} | S | Update. Big price changes return 202 and need approval |

### Orders

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | /orders | V | List, filter by status or customer |
| POST | /orders | S | Create, optionally with items |
| GET | /orders/{id} | V | Full details, items, payments, allowed next statuses |
| POST | /orders/{id}/items | S | Add an item |
| PUT | /orders/{id}/items/{product_id} | S | Change quantity or price |
| DELETE | /orders/{id}/items/{product_id} | S | Remove an item |
| POST | /orders/{id}/payments | S | Record a payment |
| POST | /orders/{id}/status | S | Change status (checked by the database) |

### Audit and provenance

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | /audit | V | Search the audit log |
| GET | /audit/export | S | Download as CSV or JSON |
| GET | /audit/{audit_id} | V | One audit row |
| POST | /audit/verify | V | Check the hash chain |
| GET | /provenance/orders/{id}/explain | V | Explain an order total |
| GET | /provenance/orders/{id}/lineage | V | Lineage graph |
| GET | /provenance/requests/{request_id} | V | Everything one request changed |
| GET | /provenance/{entity}/{id}/history | V | Full history of a record |
| GET | /provenance/{entity}/{id}/as-of | V | Record at a past time |
| GET | /provenance/{entity}/{id}/compare | V | Changes between two times |
| GET | /provenance/{entity}/{id}/flashback | V | Oracle Flashback (recent, minutes) |

### Alerts, approvals, events, dashboard

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | /alerts | V | List alerts (filter by status or severity) |
| GET | /alerts/rules | V | Rule list |
| POST | /alerts/run | S | Run all rules now |
| PATCH | /alerts/{id} | S | Acknowledge, resolve or reopen |
| GET | /approvals | V | List change requests |
| POST | /approvals/{id}/approve | A | Approve (not your own request) |
| POST | /approvals/{id}/reject | A | Reject (not your own request) |
| GET | /events | S | Recent outbox events |
| GET | /dashboard | V | Summary numbers and charts |

### Webhooks

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | /webhooks | A | List |
| POST | /webhooks | A | Create (secret shown once) |
| PATCH | /webhooks/{id} | A | Change URL, events, or pause |
| GET | /webhooks/{id}/deliveries | A | Delivery log |
| POST | /webhooks/{id}/test | A | Send a test event |
| POST | /webhooks/deliveries/{id}/retry | A | Retry a failed delivery |

### Integrations (for admins and staff, with a login)

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | /sources | V | List sources with event counts |
| POST | /sources | A | Register a source |
| GET | /sources/{id} | V | One source |
| PATCH | /sources/{id} | A | Pause or resume, change trust level |
| GET | /sources/{id}/events | V | Recent events from a source |
| GET | /api-keys | A | List keys (secrets are never shown) |
| POST | /api-keys | A | Create a key (shown once) |
| DELETE | /api-keys/{key_id} | A | Revoke a key |
| POST | /imports | S | Import a CSV snapshot |
| POST | /reconciliations/upload | S | Reconcile a CSV snapshot |
| GET | /reconciliations | V | Past reconciliation runs |
| GET | /reconciliations/{id} | V | One run with its discrepancies |

### Integrations (for machines, with an API key)

| Method | Path | Scope | Purpose |
|---|---|---|---|
| POST | /events | events:write | Send one CloudEvent |
| POST | /events:batch | events:write | Send up to 500 events |
| GET | /ingested-events | events:read | Read back events, with paging |
| POST | /reconciliations | events:write | Reconcile JSON records |

### Health

| Method | Path | Purpose |
|---|---|---|
| GET | /health | Is the app running? |
| GET | /ready | Can the app reach the database? Also shows which rate-limit backend is used |

---

## 15. Errors

Errors use the **RFC 9457 Problem Details** format, with the content type `application/problem+json`. A typical error looks like this:

```json
{
  "type": "about:blank",
  "title": "Conflict",
  "status": 409,
  "detail": "Invalid order status transition: PAID -> CREATED",
  "instance": "/api/v1/orders/2/status",
  "code": "ORA-20001"
}
```

| Field | Meaning |
|---|---|
| status | HTTP status code |
| title | Short name of the status |
| detail | Human-readable explanation |
| instance | The path that failed |
| code | (Extra) A stable code for business errors, such as `ORA-20001` |
| errors | (Extra) For validation errors: a list of problems with field names |

### Common status codes

| Code | Meaning |
|---|---|
| 200 | OK (or a duplicate event was recognized) |
| 201 | Created |
| 202 | Accepted, waiting for approval |
| 204 | Done, no body |
| 400 | Bad request |
| 401 | Not logged in, or the token or API key is invalid, expired or revoked |
| 403 | Logged in, but your role or scope is not enough |
| 404 | Not found (also used when a record belongs to another organization) |
| 409 | Conflict: business rule, duplicate, or paused source |
| 413 | Too large |
| 422 | Invalid data |
| 429 | Too many requests. The `Retry-After` header says how long to wait |

---

## 16. Configuration

All settings are in the `.env` file. The file `.env.example` lists them. `scripts/setup_db.py` creates `.env` with random secrets the first time.

| Setting | Default | Meaning |
|---|---|---|
| ENVIRONMENT | development | `production` turns off the development webhook receiver |
| DB_DSN | localhost:1521/orclpdb | Oracle connection address |
| DB_APP_USER / DB_APP_PASSWORD | PROV_APP | Runtime database user |
| DB_OWNER_USER / DB_OWNER_PASSWORD | PROV_OWNER | Owner user, for migrations only |
| DB_POOL_MIN / DB_POOL_MAX | 2 / 10 | Connection pool size |
| JWT_SECRET | (generated) | Secret for login tokens. **Keep it private** |
| ACCESS_TOKEN_MINUTES | 30 | How long a login token lasts |
| REFRESH_TOKEN_DAYS | 7 | How long a refresh token lasts |
| LOGIN_RATE_LIMIT_PER_MINUTE | 10 | Login attempts per IP per minute |
| API_KEY_RATE_LIMIT_PER_MINUTE | 600 | Requests per API key per minute |
| REDIS_URL | (empty) | Example: `redis://localhost:6379/0`. Shares rate limits across servers |
| WORKERS_ENABLED | true | Run the background worker in this process |
| DISPATCHER_INTERVAL_SECONDS | 2 | How often webhooks are sent |
| RULES_INTERVAL_SECONDS | 60 | How often rules run |
| WEBHOOK_TIMEOUT_SECONDS | 5 | Time to wait for a webhook answer |
| WEBHOOK_MAX_ATTEMPTS | 5 | Attempts before a delivery is DEAD |
| WEBHOOK_ALLOW_PRIVATE_URLS | true | Set to `false` in production |
| CORS_ORIGINS | (empty) | Allowed browser origins, if the UI is hosted elsewhere |
| DEMO_PASSWORD | (generated) | Password of the demo users |

**Production checklist**

- `ENVIRONMENT=production`
- `WEBHOOK_ALLOW_PRIVATE_URLS=false`
- A long, random `JWT_SECRET`
- A strong database password
- `REDIS_URL` if you run more than one server
- HTTPS in front of the app (for example a reverse proxy)

---

## 17. Database

### Migrations

Migrations are SQL files in `db/migrations/`, run in order. Each one runs once, and the runner records it in a table named `SCHEMA_MIGRATIONS`.

| File | What it adds |
|---|---|
| 001_core.sql | Context package, tenants, users, customers, products, orders, items, payments |
| 002_audit.sql | Outbox, audit log with hash chain, chain head, verification |
| 003_triggers.sql | Audit triggers, status rule, order total, item lock |
| 004_features.sql | Alerts, change requests (approvals), webhooks, tenant isolation (VPD), permissions |
| 005_integration.sql | API keys, sources, external events, the ingestion procedure |
| 006_reconciliation.sql | Reconciliation runs and their discrepancies |

To apply new migrations to an existing database, run `scripts/setup_db.py` (without `--reset`) or `python -m app.migrate`.

### Important tables

| Table | Holds |
|---|---|
| tenants | Organizations |
| app_users | People who log in |
| customers, products, orders, order_items, payments | Business data |
| audit_log | Every change, hash chained. The app can only read it |
| outbox_events | Events waiting for webhooks |
| webhooks, webhook_deliveries | Webhook setup and delivery attempts |
| alerts | Findings from the rules |
| change_requests | Approval requests |
| api_keys | API keys (only a hash of the secret is stored) |
| sources | Upstream systems |
| external_events | Events received from sources |
| reconciliations, reconciliation_items | Reconciliation results |

### Tenant isolation

Every tenant table has a `tenant_id` column. An Oracle VPD policy adds the filter `tenant_id = <current tenant>` to every query. If the connection has no tenant set, it sees no rows.

---

## 18. Testing

The project has **54 automatic tests**. They run against the real Oracle database, not a mock.

```bash
.venv/Scripts/python.exe -m pytest
```

Each test creates its own organization, so tests do not interfere with each other or with the demo data.

What is tested:

- Login, tokens, roles, deactivated users
- Tenant isolation, including a direct database check that a cross-tenant insert is refused
- Totals kept by the database, the status rule, item locks, payment limits
- Explain, history, request trace, lineage, time travel, Flashback
- The audit log cannot be changed by the app account
- Hash chain verification and CSV/JSON export
- Approvals, including the four-eyes rule in the database
- Alert rules and their false-positive protection
- Webhook delivery, signature and retries
- Event ingestion: idempotency, scopes, revoked keys, validation, batches
- Reconciliation and CSV imports
- Rate limiting, including the Redis version (run with a fake Redis)

---

## 19. Security design

| Protection | How it works |
|---|---|
| Passwords | Hashed with Argon2. Never stored in plain text |
| Login tokens | Short-lived JWT access tokens and longer refresh tokens |
| API keys | Only a SHA-256 hash of the secret is stored. Shown once |
| Brute force | Login and API keys are rate limited |
| Tenant isolation | Done inside the database (VPD), not just in the code |
| Audit integrity | App account can only read the audit log. Hash chain detects edits |
| Four-eyes approvals | Database constraint stops self-approval |
| SQL injection | All values are passed as bind variables. Column names come from fixed lists only |
| Webhook signatures | Standard Webhooks HMAC-SHA256 |
| SSRF protection | Webhook URLs can be blocked from reaching private addresses |
| Browser security | Content-Security-Policy, no inline scripts, frame blocking, nosniff header |
| Error details | Internal database errors are hidden from clients (returned as a generic message) |

---

## 20. Known limits

Be honest about these when you present the project.

- **Rate limiting** is per process unless `REDIS_URL` is set.
- **Flashback** only goes back as far as the undo retention (minutes). Use `as-of` for older history.
- **Webhook secrets** are stored as plain text in the database. In production, encrypt them (for example with Oracle TDE).
- **Single database.** The project is built for one Oracle database. It is not yet split across machines.
- **CSV files** are limited to 5 MB and 5,000 rows.
- **Events** are limited to 32 KB each.
- **No automatic reconciliation schedule.** Reconciliation runs when you call it or upload a file.
- **The development webhook receiver** is only meant for testing.
- **Payments** are recorded, not processed. There is no real card or bank integration.
- **No mobile app.** The UI works in a browser.

---

## 21. Glossary

- **Alert**: A finding from a rule that needs attention.
- **API key**: A secret token for a machine. Starts with `prv_`.
- **Approval (change request)**: A risky change waiting for a second admin.
- **Audit log**: The list of every change.
- **CDC (Change Data Capture)**: Collecting changes by reading a database's change log.
- **CloudEvents**: A standard format for event messages.
- **Evidence**: A recorded event or audit row that proves something happened.
- **Explain**: A plain-English account of how a value was built.
- **Hash chain**: Each record's fingerprint includes the previous record's fingerprint.
- **Idempotent**: Doing the same thing twice has the same result as doing it once.
- **Lineage**: The chain of things that led to a value.
- **Outbox**: A table of events waiting to be sent, written in the same transaction as the change.
- **Provenance**: The history and origin of data.
- **Reconciliation**: Comparing two sets of data to find differences.
- **Scope**: A permission given to an API key (for example `events:write`).
- **Snapshot**: The full list of records at one moment, sent by an upstream system.
- **Source**: An upstream system that sends us data.
- **Tenant**: One organization using the system.
- **Trust level**: How much we believe data from a source (HIGH, MEDIUM or LOW).
- **VPD (Virtual Private Database)**: An Oracle feature that filters rows per user or tenant.
- **Webhook**: A message we send to a URL of yours when something happens.
