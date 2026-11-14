# ADR 0009: Platform administration without default data access; two-person break-glass

Status: accepted · Date: 2026-11-14

## Context
Running a multi-tenant service needs people who can manage organizations, watch health and respond to incidents. The usual shortcuts (a "superuser" flag on an ordinary account, a shared admin login, or an RLS-bypassing role) give those people silent, unlimited access to every customer's data, which defeats the tenant isolation the product is built on.

## Decision
1. **Separate identities.** Platform operators live in `platform_users`, with their own credentials, mandatory TOTP MFA (replay-protected), and their own token type signed with a derived key. Roles: `super_admin`, `security_officer`. Organization roles are unchanged.
2. **A third database role.** The console connects as `prov_platform`, which has *no* privileges on tenant tables. It reaches tenant information only through `SECURITY DEFINER` functions that return counts and status, or perform one audited recovery action. No role in the system has `BYPASSRLS`.
3. **Break-glass in the database.** `break_glass_grants` with triggers and constraints enforcing: four-eyes (approver ≠ requester, both active and MFA-enrolled), a fixed state machine, immutable request details, a 30-minute approval window, an expiry computed by the database and capped by a check constraint, no deletes.
4. **Reads through RLS, read-only.** Break-glass reads use the normal application role. `breakglass_begin()` re-validates the grant in the database, sets the tenant context, and switches the transaction to `READ ONLY`. Recovery uses one narrow function per action; there is never a general writable session.
5. **Log before access, fail closed.** The platform API writes the access record to the platform chain before returning data and refuses access if it cannot.
6. **A separate platform audit chain** (sealed at commit) with signed checkpoints also appended to an independent anchor file intended for WORM storage.
7. **Customer transparency by default**, via the organization's activity log and webhooks, with a constrained legal-hold exception.
8. **The first super admin comes from the CLI only while none exists**; afterwards operators are created in the console by a super admin, with MFA and an audit record.

## Consequences
* Operators can run the service day to day without seeing customer data, and the database (not only the API) enforces that.
* Emergency access is possible but slow by design (two people, MFA, ticket, time limit) and visible to the customer.
* More moving parts: a third role and connection string, a second audit chain, a worker job, an anchor to provision.
* Same residual risks as tenant isolation: arbitrary SQL as the application role, and database superusers. Detection relies on the chains and the independent anchor.
