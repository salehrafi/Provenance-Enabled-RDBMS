# Platform administration and break-glass access

The platform console (`/platform`, API under `/api/platform/v1`) is for the people who run Provenance Cloud, not for customers. It lets them manage organizations and watch system health and security signals **without** seeing customer business data. In a genuine emergency, a time-limited, two-person, MFA-protected **break-glass** procedure grants read-only access to one organization. Every step is recorded in a separate tamper-evident **platform audit chain**.

See [ADR 0009](adr/0009-platform-admin-and-break-glass.md) for the design rationale.

## Roles

| Role | Who | Can |
|---|---|---|
| **Platform Super Admin** (`super_admin`) | operators who run the service | everything a security officer can, plus suspend/reactivate organizations and manage operators |
| **Platform Security Officer** (`security_officer`) | oversight, compliance | view organizations, health and security signals; request, approve, reject and revoke break-glass; read and verify the platform audit chain |
| **Organization Admin** | the existing organization role `admin` | everything inside their own organization |
| **Organization User** | the existing roles `staff`, `auditor`, `viewer` | as before, inside their own organization |

Platform operators and organization users are separate populations: separate tables, separate credentials, separate token types signed with different keys. An organization token is rejected by the platform API and vice versa (tested). An organization user cannot be given a platform role, and a platform operator has no organization account by virtue of being an operator.

## What operators can and cannot see without break-glass

| Visible (metadata) | Never visible |
|---|---|
| organization name, status, plan, created date | customer, product, order, payment content |
| counts: users, customers, orders, external events, audit records | user names and emails, audit record contents |
| activity in the last 24 h, failed sign-ins, denied requests, last activity time | API key or webhook secrets, password hashes (never, even with break-glass) |
| failed/denied traffic by **IP address** (no identities) | |
| system health: outbox backlog, failing/dead webhooks, critical alert counts, worker status | |

This boundary is enforced by the **database**, not just the API: the platform console connects as role `prov_platform`, which has no privileges on any tenant table (a test asserts `SELECT` is refused on all of them). The metadata comes from `SECURITY DEFINER` functions that return counts and status only.

## Getting started

1. Make sure `DATABASE_PLATFORM_URL` is set (connection string for role `prov_platform`; `python -m app.cli init` writes it for development). Without it the console is disabled.
2. `python -m app.cli bootstrap` (creates the role) and `python -m app.cli migrate`.
3. Create the **first** super admin. This command only works while no active super admin exists; after that, operators are added in the console by a super admin, with MFA and an audit record:
   ```bash
   python -m app.cli create-platform-admin --email you@company.com --name "Your Name"
   ```
   It prints a one-time temporary password.
4. Open `/platform`, sign in, and enrol an authenticator app (any TOTP app: scan or type the secret shown, enter the code). MFA is mandatory; there is no way to skip it.

Operator passwords need at least 12 characters. Accounts are individual and must never be shared; every action is attributed to the operator who took it.

## MFA and "fresh MFA"

* Sign-in requires password + current TOTP code. A code is accepted once (replay protection) with ±30 s clock tolerance.
* Sensitive actions also require that the operator proved MFA within the last `PLATFORM_MFA_FRESH_MINUTES` (default 5): suspending an organization, managing operators, requesting, approving and activating break-glass, and account recovery. The console prompts for a code automatically; the API returns `403 MFA_STEP_UP_REQUIRED`, then call `POST /auth/step-up {"totp": "123456"}` for a new token.
* A super admin can force another operator to re-enrol (`reset-mfa`), never themselves.

## Break-glass: runbook

Use only when there is no other way: a legal request, an incident investigation, or account recovery for a verified owner. **Requester and approver must be different operators.**

1. **Request** (Organizations → *Break-glass…*, or `POST /break-glass`). State the scope, a reason of at least 20 characters, a ticket or case reference, and a duration of 5 to 240 minutes once activated.
   * `READ_ONLY`: read whitelisted tables of that one organization.
   * `ACCOUNT_RECOVERY`: additionally reset a user's password, reactivate a user, or sign a user out everywhere. Nothing else.
   * **Notify the organization** is on by default. Turn it off only for a documented legal hold; the database then requires a reason of at least 40 characters.
2. **Approve** (Break-glass → *Approve*): a *different* active, MFA-enrolled operator, with fresh MFA. The database refuses self-approval regardless of the API (`ck_bg_four_eyes` and a trigger). Approval is valid for **30 minutes**; after that the request lapses.
3. **Activate** (requester only, fresh MFA). The access window starts now and ends after the approved duration. The expiry is set by the database and can never be extended, not even by a superuser (`ck_bg_expiry`).
4. **Use** (*Open*): pick a table. Every view is recorded in the platform audit chain **before** the data is returned, and access is refused if that record cannot be written. Reads run as the normal application role under row-level security, inside a transaction the database forces to **read-only** (`breakglass_begin`). Only the requester can use the grant; the approver cannot.
5. **End** (*End*, requester) when done, or *Revoke* (any operator) at any time. If neither happens, the worker marks the grant `EXPIRED` and access already stops at the expiry instant regardless.

States: `PENDING → APPROVED → ACTIVE → CLOSED | REVOKED | EXPIRED` (also `PENDING → REJECTED | REVOKED`, `APPROVED → REVOKED | EXPIRED`). Any other transition, and any edit of the request details, is refused by the database.

### What the customer sees
Unless the request is under legal hold, the organization's own **Activity log** shows each state change (`breakglass.pending`, `breakglass.approved`, `breakglass.active`, `breakglass.closed`…), every data view (`breakglass.access`) and every recovery action (`breakglass.recovery.*`), attributed to `platform:<operator email>`. They also receive `security.break_glass` webhook events. Recovery changes to users appear in the organization's audit chain as `breakglass:<operator>#<grant id>`.

## Platform audit chain

`platform_audit_log` is a separate SHA-256 hash chain (sealed at commit, like the organization chains). It records **every** platform API request (including failed sign-ins and anonymous probes) with operator, action, outcome, target organization, IP address, user agent and request id, plus semantic events (`breakglass.*`, `organization.suspended`, `operator.created`, `platform.checkpoint`…).

* **Append-only:** `prov_platform` can only `SELECT` it; a trigger rejects `UPDATE`/`DELETE`/`TRUNCATE` for every role including the owner.
* **Signed checkpoints:** the worker (every `PLATFORM_CHECKPOINT_INTERVAL_SECONDS`) verifies the chain and signs its head with the Ed25519 checkpoint key, which the database never holds. Checkpoints are stored in `platform_checkpoints` **and** appended to the file at `PLATFORM_ANCHOR_PATH`.
* **Independent immutable storage:** point `PLATFORM_ANCHOR_PATH` at write-once storage that database administrators cannot modify: an S3 bucket with Object Lock (compliance mode) mounted via a FUSE driver, Azure immutable blob storage, a WORM appliance, or a log host with append-only permissions. The application only ever appends (`O_APPEND` + `fsync`); immutability comes from the storage.
* **Verify:** *Platform audit → Verify now* (or `POST /audit/verify`) checks every link, every stored checkpoint, every checkpoint in the anchor file, and any checkpoints you pass in. A test shows that rewriting the entire chain and deleting the stored checkpoints is still caught by the anchor.
* **Export:** *Export CSV* (`GET /audit/export`) with filters.

## Organization suspension

A super admin can suspend an organization (with a reason and fresh MFA). Its users cannot sign in or refresh sessions, existing access tokens and API keys are refused (`403 ORGANIZATION_SUSPENDED`), and the change is recorded in the organization's own audit chain and activity log. *Reactivate* restores access.

## Limitations

* **An attacker who can run arbitrary SQL as the application role** could set the tenant context directly; this is the same boundary as ordinary tenant isolation ([SECURITY](SECURITY.md#limitations-and-non-goals)). Break-glass hardens the *intended* path (database-checked grant, read-only transaction, mandatory logging), not a compromised API process.
* **A database superuser** can disable triggers. The hash chains plus signed checkpoints in independent storage are what make that detectable; keep the anchor on genuinely immutable storage and keep the signing key out of the database host.
* **TOTP is the only MFA factor.** No WebAuthn/hardware keys yet; no SSO for operators.
* **Customer notification is in-product** (activity log and webhooks). There is no email notification.
* **The legal-hold option is a policy decision.** It suppresses customer notification only; the platform chain always records the access.
* **The platform console is served from the same application.** For stronger separation, expose `/platform` and `/api/platform/` only on an internal network or behind a VPN at your reverse proxy.
