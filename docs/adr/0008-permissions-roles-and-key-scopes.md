# ADR 0008: Permissions as the unit of authorization

Status: accepted · Date: 2026-11-13

## Context
v2 had three role ranks (viewer < staff < admin) and two API-key scopes. Auditors and machine clients need finer control.

## Decision
Endpoints declare one permission (for example `audit:verify`, `webhooks:manage`). Roles (`viewer`, `auditor`, `staff`, `admin`) are fixed sets of permissions. API keys carry a narrow subset of scopes that are also permissions; keys can never hold management permissions, and endpoints that record a human decision require a signed-in user. Roles are read from the database on every request.

## Consequences
* Adding a capability means adding a permission and choosing which roles and scopes get it. Auditors can export and verify evidence without being able to change data.
* Roles are not customer-configurable yet (custom roles are a possible later feature).
* Per-request role lookup costs one indexed read, in exchange for immediate effect of demotion and deactivation.
