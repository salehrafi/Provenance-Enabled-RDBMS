# Changelog

Format: [Keep a Changelog](https://keepachangelog.com). Versions follow SemVer; the HTTP API is versioned separately by path (`/api/v1`).

## [3.0.0] - 2026-11-13

A ground-up rebuild as a production-oriented SaaS. **Not upgradeable in place from 2.x**: see [MIGRATING_FROM_ORACLE](docs/MIGRATING_FROM_ORACLE.md).

### Changed
- **Database: Oracle to PostgreSQL 16.** Row-level security replaces VPD, a transaction-local `set_config` context replaces the Oracle application context, PL/pgSQL triggers replace PL/SQL packages, and reconstruction from the audit log replaces Flashback Query. Schema is managed by Alembic. ([ADR 0001](docs/adr/0001-postgresql-over-oracle.md), [0002](docs/adr/0002-rls-with-transaction-local-context.md))
- The audit hash chain is sealed **at commit** (no long-held head lock), uses an unambiguous JSON preimage and strictly increasing timestamps. ([ADR 0003](docs/adr/0003-commit-time-sealing-and-signed-checkpoints.md))
- Access tokens last 15 minutes and carry no role; the role is read from the database on every request.
- Webhook delivery uses leases and `SKIP LOCKED` (safe with many workers), backoff with jitter over about 8 hours, and resolves the target once and pins the vetted address (SSRF).
- Errors carry a stable `code` and `request_id` (RFC 9457).
- Frontend rebuilt on the v3 API while keeping the original look: flat, square-cornered green theme, Poppins, bordered grey sidebar with a green brand block, filled-green active states, top-bordered KPI cards. Light by default with an opt-in dark theme. Fully responsive: desktop, tablet (narrower sidebar, stacked grids) and phone (slide-in drawer, two-column KPIs, scrollable tables and graph). Strict CSP (no inline script).
- API: audit pagination is keyset on `chain_seq`; list endpoints return `{items: [...]}` envelopes.

### Added (platform)
- **Global administration**: separate platform operators (Super Admin, Security Officer) with mandatory TOTP MFA, their own token type and a database role (`prov_platform`) with no access to tenant tables. Organization overview, usage and security signals (metadata only), system health, organization suspension, operator management. Console at `/platform`; migration `0003`.
- **Break-glass**: time-limited (5-240 min), two-person, fresh-MFA emergency access to one organization; read-only in the database; account-recovery scope limited to password reset, reactivation and session revocation; expiry and four-eyes enforced by the database; customer notified via activity log and webhooks unless under a documented legal hold.
- **Platform audit chain**: separate SHA-256 chain of every platform request and action, signed checkpoints, independent append-only anchor file (`PLATFORM_ANCHOR_PATH`), verification and CSV export.
- `python -m app.cli create-platform-admin` for the first super admin only.

### Added (security)
- **Activity log**: append-only, admin-only record of sign-ins (including failures), sign-outs, token reuse, every change and sensitive reads, with client IP address, user agent, outcome and duration. Filter by person, action, IP address or CIDR block, result, method and time; export to CSV or JSON. New page *Organization → Activity log*; migration `0002`.

### Fixed (UI)
- Empty red error box on the sign-in card and in every form dialog (a flex rule overrode the `hidden` attribute).
- Stray `false`/`null` text under tables with no second page (Orders, Customers, Products, audit log).
- Explorer search row: the record field overlapped the button.
- Page reload during a refresh-token rotation no longer signs the user out.
- Static files revalidate on every load, so upgrades are not masked by cached scripts.

### Changed (policy)
- Minimum password length is now 6 characters (`MIN_PASSWORD` in `app/schemas.py`), down from 12.

### Added
- **Signed audit checkpoints** (Ed25519, key outside the database), published as `audit.checkpoint` events and to an optional anchor file; verification accepts checkpoints the customer kept.
- Refresh-token **rotation with reuse detection**, HttpOnly SameSite=Strict cookie, sign out everywhere, password change that revokes sessions.
- Role `auditor`; granular permissions; API-key scopes `audit:read`, `audit:verify`, `audit:export`; key expiry.
- `Idempotency-Key` support for create operations.
- Bitemporal reconstruction of external records (`at` / `known_at`), whole-order time travel, record comparison, order lineage graph, request tracing.
- Webhook delivery log (response snippet, duration), secret rotation, encrypted secrets (AES-256-GCM), dead-letter alerts (`WH001`).
- Sandbox sample data and an onboarding checklist.
- Worker as its own process (`python -m app.worker`), scheduled full-chain verification, housekeeping that never touches history.
- Prometheus metrics, JSON logs with request, tenant and actor, liveness and readiness probes.
- Dockerfile, Compose file, CI workflow, backup and verified-restore scripts, benchmark script.
- Python and TypeScript SDKs; legacy history importer.
- Documentation set and architecture decision records.
- 160+ integration tests against real PostgreSQL covering tenant isolation, tampering, concurrency, SSRF and idempotency.

### Removed
- The Oracle dependency and all PL/SQL.
- The `flashback` endpoint (replaced by `as-of`).
- The in-memory development webhook sink.
- Plain-text webhook secrets.

### Security
- No default secrets; production refuses to start with weak or missing configuration.
- Least-privilege roles: the runtime role cannot write history, create tenants, change plans, or call the sealing functions.

### Known limitations
See [SECURITY](docs/SECURITY.md#limitations-and-non-goals) and the status section of the [README](README.md#status-and-honest-limits).

## [2.0.0]
Oracle + FastAPI rebuild of the course project (git history before 2026-11-13, commit `46ec882`).

## [1.0.0]
Flask + SQLite course project (see `legacy/`).
