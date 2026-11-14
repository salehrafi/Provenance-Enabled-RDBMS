// Platform console: global administration and break-glass. Separate from the organization app: its own token
// (memory only, never stored), mandatory TOTP, and a TOTP prompt whenever an action needs a fresh MFA check.
import { h, icon, fmt, badge, card, pageHead, stat, table, empty, field, input, select, modal, formDialog, toast, fail,
  loading, errorBox, jsonBlock, codeBlock, copy, ApiError, confirmDialog } from "./lib.js";

const BASE = "/api/platform/v1";
const S = { token: null, me: null };
const app = document.getElementById("app");

async function call(method, path, body, { params, raw, retried } = {}) {
  let url = BASE + path;
  if (params) {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ""));
    if ([...q].length) url += "?" + q;
  }
  const headers = { Accept: "application/json" };
  if (S.token) headers.Authorization = `Bearer ${S.token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (raw && r.ok) return r;
  const data = r.status === 204 ? null : (r.headers.get("content-type") || "").includes("json") ? await r.json() : await r.text();
  if (r.status === 401 && S.token && path !== "/auth/login") { S.token = null; S.me = null; toast("Your platform session ended."); login(); throw new ApiError(401, data); }
  if (r.status === 403 && data?.code === "MFA_STEP_UP_REQUIRED" && !retried) {
    await stepUp();
    return call(method, path, body, { params, raw, retried: true });
  }
  if (!r.ok) throw new ApiError(r.status, typeof data === "object" ? data : { detail: data });
  return data;
}
const get = (p, params) => call("GET", p, undefined, { params });
const post = (p, b) => call("POST", p, b ?? {});

function stepUp() {
  return new Promise((resolve, reject) => {
    const code = input({ inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: "6", required: true, placeholder: "123456" });
    let done = false;
    formDialog("Confirm with your authenticator", [h("p", { class: "muted" }, "This action needs a fresh TOTP check. Enter the current code from your authenticator app."), field("Code", code)],
      "Confirm", async (close) => {
        const r = await call("POST", "/auth/step-up", { totp: code.value }, { retried: true });
        S.token = r.access_token; done = true; close(); resolve();
      });
    // If the dialog is dismissed without a code, the original action fails with its own message.
    const watch = setInterval(() => { if (!document.querySelector(".scrim")) { clearInterval(watch); if (!done) reject(new ApiError(403, { detail: "Action cancelled: TOTP confirmation is required", code: "MFA_STEP_UP_REQUIRED" })); } }, 300);
  });
}

// ---------------------------------------------------------------- sign-in and enrolment
function authShell(title, sub, form) {
  app.replaceChildren(h("main", { class: "auth", id: "main" },
    h("section", { class: "auth-hero" }, h("div", { class: "brand" }, h("div", { class: "logo", "aria-hidden": "true" }, "◆"), "Provenance Cloud"),
      h("h1", null, "Platform console"),
      h("ul", null, h("li", null, "Restricted to platform operators. Every action is recorded in the tamper-evident platform audit chain."),
        h("li", null, "No access to customer business data by default. Emergency access needs a second operator's approval and expires automatically."),
        h("li", null, "Multi-factor authentication is mandatory."))),
    h("section", { class: "auth-form" }, h("div", { class: "auth-card" }, h("div", null, h("h1", null, title), h("p", { class: "muted", style: "margin-top:4px" }, sub)), form))));
}

function login() {
  const email = input({ type: "email", required: true, autocomplete: "username" });
  const pw = input({ type: "password", required: true, autocomplete: "current-password" });
  const code = input({ inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", placeholder: "6-digit code (if enrolled)" });
  const err = h("div", { class: "alert bad", role: "alert", hidden: true });
  const btn = h("button", { class: "btn primary", type: "submit", style: "width:100%" }, "Sign in");
  authShell("Operator sign-in", "Use your own operator account. Accounts are never shared.", h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault(); err.hidden = true; btn.disabled = true;
    try {
      const r = await call("POST", "/auth/login", { email: email.value, password: pw.value, totp: code.value || null });
      if (r.mfa_setup_required) return enroll(r);
      S.token = r.access_token; S.me = r.operator; boot();
    } catch (x) { err.hidden = false; err.textContent = x.message; btn.disabled = false; }
  } }, field("Email", email), field("Password", pw), field("Authenticator code", code), err, btn));
  email.focus();
}

function enroll(r) {
  const code = input({ inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", required: true, placeholder: "123456" });
  const err = h("div", { class: "alert bad", role: "alert", hidden: true });
  authShell("Set up multi-factor authentication", "Required before you can use the console.", h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault(); err.hidden = true;
    try { const t = await call("POST", "/auth/mfa/enroll", { setup_token: r.setup_token, code: code.value }); S.token = t.access_token; S.me = t.operator; toast("MFA enrolled", "ok"); boot(); }
    catch (x) { err.hidden = false; err.textContent = x.message; }
  } },
  h("ol", { class: "small", style: "margin:0;padding-left:18px" }, h("li", null, "Open an authenticator app (any TOTP app)."),
    h("li", null, "Add an account with this secret key, or paste the setup link:"), h("li", null, "Enter the 6-digit code it shows.")),
  codeBlock(r.secret), h("details", null, h("summary", { class: "small" }, "Setup link (otpauth://)"), codeBlock(r.otpauth_uri)),
  field("Code from the app", code), err, h("button", { class: "btn primary", type: "submit", style: "width:100%" }, "Verify and continue")));
  code.focus();
}

// ---------------------------------------------------------------- shell and routing
const NAV = [["/", "Overview", "home"], ["/organizations", "Organizations", "users"], ["/security", "Security signals", "alert"],
  ["/break-glass", "Break-glass", "lock"], ["/audit", "Platform audit", "shield"], ["/operators", "Operators", "settings", "super_admin"]];
const ROUTES = { "/": overview, "/organizations": organizations, "/security": security, "/break-glass": breakGlass, "/audit": audit, "/operators": operators };

function shell() {
  const side = h("aside", { class: "side", id: "side", "aria-label": "Platform" },
    h("div", { class: "brand" }, h("div", { class: "logo", "aria-hidden": "true" }, "◆"), "Platform console"),
    h("nav", { class: "nav" }, h("div", { class: "nav-group" }, "Global administration"),
      NAV.filter(([, , , role]) => !role || S.me.role === role).map(([p, label, ico]) => h("a", { href: "#" + p, dataset: { path: p }, onclick: () => { side.classList.remove("open"); veil.classList.remove("open"); } }, icon(ico, 17), label))),
    h("div", { class: "side-foot" }, h("div", { class: "who" }, S.me.full_name), h("div", null, S.me.email),
      h("div", null, badge(S.me.role.replace("_", " "), "info")),
      h("div", { class: "row" }, h("a", { href: "/" }, "Organization app"), "·", h("a", { href: "#", onclick: async (e) => { e.preventDefault(); try { await post("/auth/logout"); } catch { /* ends anyway */ } S.token = null; login(); } }, "Sign out"))));
  const veil = h("div", { class: "scrim-nav", onclick: () => { side.classList.remove("open"); veil.classList.remove("open"); } });
  const top = h("header", { class: "top" }, h("button", { class: "menu-btn", "aria-label": "Open menu", onclick: () => { side.classList.add("open"); veil.classList.add("open"); } }, icon("menu", 20)),
    h("div", { class: "brand" }, h("div", { class: "logo" }, "◆"), "Platform"), h("div", { class: "grow" }), h("div", { class: "crumbs", id: "crumbs" }));
  app.replaceChildren(h("div", { class: "app" }, side, veil, h("div", { class: "main" }, top, h("main", { class: "page", id: "main", tabindex: "-1" }))));
}

async function route() {
  if (!S.token) return;
  const path = location.hash.slice(1).split("?")[0] || "/";
  const view = ROUTES[path] || overview;
  for (const a of document.querySelectorAll(".nav a")) a.toggleAttribute("aria-current", a.dataset.path === path), a.hasAttribute("aria-current") && a.setAttribute("aria-current", "page");
  const main = document.getElementById("main");
  document.getElementById("crumbs").textContent = (NAV.find(([p]) => p === path) || NAV[0])[1];
  main.replaceChildren(h("div", { class: "card" }, loading(4)));
  try { main.replaceChildren(await view()); } catch (e) { if (S.token) main.replaceChildren(errorBox(e)); }
}
const rerender = () => route();

async function boot() { shell(); route(); }
window.addEventListener("hashchange", route);

// ---------------------------------------------------------------- views
async function overview() {
  const [hl, bg] = await Promise.all([get("/health"), get("/break-glass")]);
  const m = hl.metrics, pa = hl.platform_audit;
  const waiting = bg.items.filter((g) => g.status === "PENDING" && g.requested_by !== S.me.platform_user_id);
  return h("div", { class: "stack" },
    pageHead("Overview", "System health, usage and security metadata. No customer business data is shown here."),
    h("div", { class: "grid g4" }, stat("Organizations", fmt.n(m.organizations), `${m.suspended_organizations} suspended`, "users"),
      stat("Users", fmt.n(m.users), null, "users"), stat("Audit records", fmt.n(m.audit_records), `${fmt.n(m.activity_24h)} activity events (24 h)`, "shield"),
      stat("Critical alerts", fmt.n(m.open_critical_alerts), "open, all organizations", "alert")),
    h("div", { class: "grid g2" },
      card("Delivery and processing", h("dl", { class: "kv" }, h("dt", null, "Outbox backlog"), h("dd", null, fmt.n(m.outbox_pending)),
        h("dt", null, "Failing webhooks"), h("dd", null, fmt.n(m.deliveries_failing)), h("dt", null, "Dead-lettered"), h("dd", null, fmt.n(m.deliveries_dead)),
        h("dt", null, "Worker"), h("dd", null, hl.worker?.dispatch ? `last run ${fmt.ago(hl.worker.dispatch * 1000)}` : "not running in this process"))),
      card("Platform audit chain", h("dl", { class: "kv" }, h("dt", null, "Records"), h("dd", null, fmt.n(pa.records)),
        h("dt", null, "Latest checkpoint"), h("dd", null, pa.latest_checkpoint ? `#${pa.latest_checkpoint.seq} · ${fmt.ago(pa.latest_checkpoint.created_at)}` : "none yet"),
        h("dt", null, "Independent anchor"), h("dd", null, pa.anchor_configured ? badge("configured", "ok") : badge("not configured", "warn"))))),
    card("Break-glass", h("dl", { class: "kv" }, h("dt", null, "Active now"), h("dd", null, fmt.n(m.active_break_glass)), h("dt", null, "Awaiting decision"),
      h("dd", null, waiting.length ? h("a", { href: "#/break-glass" }, `${waiting.length} request(s) need a second operator`) : "none"))));
}

async function organizations() {
  const { items } = await get("/organizations");
  const isSuper = S.me.role === "super_admin";
  return h("div", { class: "stack" }, pageHead("Organizations", "Usage and security counts only. Opening an organization's data requires an approved break-glass grant."),
    card(null, table([
      { label: "Organization", render: (o) => h("span", null, h("strong", null, o.name), h("div", { class: "small muted" }, `#${o.tenant_id} · created ${fmt.date(o.created_at)}`)) },
      { label: "Status", render: (o) => h("span", null, badge(o.status, o.status === "ACTIVE" ? "ok" : "bad"), o.active_break_glass ? [" ", badge("break-glass active", "warn")] : null) },
      { label: "Users", right: true, render: (o) => `${o.active_users}/${o.users}` },
      { label: "Records", right: true, render: (o) => h("span", { class: "small" }, `${fmt.n(o.orders)} orders · ${fmt.n(o.external_events)} events · ${fmt.n(o.audit_records)} audit`) },
      { label: "Security (24 h)", render: (o) => h("span", { class: "small" }, badge(`${o.failed_logins_24h} failed sign-ins`, o.failed_logins_24h ? "warn" : "plain"), " ", badge(`${o.denied_24h} denied`, o.denied_24h ? "warn" : "plain")) },
      { label: "Last activity", render: (o) => fmt.ago(o.last_activity_at) },
      { label: "", right: true, render: (o) => h("span", { class: "row end" },
        isSuper && (o.status === "ACTIVE"
          ? h("button", { class: "btn sm danger", onclick: () => suspendDialog(o) }, "Suspend")
          : h("button", { class: "btn sm", onclick: async () => { if (await confirmDialog(`Reactivate ${o.name}?`, "Its users and API keys work again immediately.", "Reactivate")) { try { await post(`/organizations/${o.tenant_id}/reactivate`); toast("Reactivated", "ok"); rerender(); } catch (e) { fail(e); } } } }, "Reactivate")),
        h("button", { class: "btn sm", onclick: () => requestDialog(o) }, "Break-glass…")) }],
    items, { empty: empty("No organizations yet", null, null, "users") }), { flush: true }));
}

function suspendDialog(o) {
  const reason = input({ required: true, minlength: "10", maxlength: "500", placeholder: "Why, with a ticket reference" });
  formDialog(`Suspend ${o.name}`, [h("p", null, "Every sign-in and API key of this organization stops working until it is reactivated. The organization's own audit trail records who did this."), field("Reason", reason)],
    "Suspend organization", async (close) => { await post(`/organizations/${o.tenant_id}/suspend`, { reason: reason.value }); close(); toast("Suspended", "ok"); rerender(); });
}

async function security() {
  const { items, hours } = await get("/security/signals", { hours: 24 });
  return h("div", { class: "stack" }, pageHead("Security signals", `Denied requests and failed sign-ins by organization and IP address, last ${hours} hours. Identities and content are not shown.`),
    card(null, table([{ label: "Organization", render: (r) => `${r.tenant_name} (#${r.tenant_id})` }, { label: "IP address", render: (r) => h("span", { class: "mono" }, r.ip_address) },
      { label: "Failed sign-ins", right: true, render: (r) => r.failed_logins ? badge(String(r.failed_logins), "warn") : "0" }, { label: "Denied", right: true, key: "denied" },
      { label: "Last seen", render: (r) => fmt.ago(r.last_seen) }], items, { empty: empty("Quiet", "No denied or failed traffic in this window.", null, "shield") }), { flush: true }));
}

// ---------------------------------------------------------------- break-glass
const BG_TONE = { PENDING: "warn", APPROVED: "info", ACTIVE: "bad", REJECTED: "plain", EXPIRED: "plain", REVOKED: "plain", CLOSED: "plain" };

function requestDialog(org) {
  const scope = select([["READ_ONLY", "Read-only investigation"], ["ACCOUNT_RECOVERY", "Account recovery"]], "READ_ONLY", {});
  const reason = h("textarea", { required: true, minlength: "20", maxlength: "2000", placeholder: "What happened, who asked, why access is necessary", style: "font-family:inherit" });
  const ticket = input({ required: true, minlength: "3", maxlength: "100", placeholder: "INC-1234 / LEGAL-77" });
  const minutes = select([["15", "15 minutes"], ["30", "30 minutes"], ["60", "1 hour"], ["120", "2 hours"], ["240", "4 hours (maximum)"]], "30", {});
  const notify = input({ type: "checkbox", checked: true });
  formDialog(`Request break-glass access: ${org.name}`, [
    h("div", { class: "alert warn" }, icon("alert"), "Emergency use only. A different operator must approve. Access is read-only, expires automatically, and every step is recorded."),
    field("Scope", scope, "Account recovery allows password reset, reactivation and session revocation for this organization's users; nothing else."),
    field("Reason", reason), field("Ticket or case reference", ticket), field("Duration once activated", minutes),
    h("label", { class: "row", style: "font-weight:400" }, notify, "Notify the organization (shown in their activity log and sent to their webhooks)"),
    h("div", { class: "hint" }, "Untick only for a documented legal hold; the reason must then be at least 40 characters.")],
  "Submit request", async (close) => {
    await post("/break-glass", { tenant_id: org.tenant_id, scope: scope.value, reason: reason.value, ticket_ref: ticket.value, duration_minutes: Number(minutes.value), notify_customer: notify.checked });
    close(); toast("Request submitted. Another operator must approve it.", "ok"); location.hash = "#/break-glass";
  }, { wide: true });
}

async function breakGlass() {
  const { items } = await get("/break-glass");
  const me = S.me.platform_user_id;
  const act = (fn, msg) => async () => { try { await fn(); toast(msg, "ok"); rerender(); } catch (e) { fail(e); } };
  const note = (title, label, fn) => () => { const n = input({ maxlength: "500" }); formDialog(title, [field(label, n)], title, async (close) => { await fn(n.value || null); close(); rerender(); }); };
  return h("div", { class: "stack" },
    pageHead("Break-glass access", "Emergency, time-limited access to one organization. Requester and approver must be different operators; MFA is re-checked; the organization is notified unless under legal hold."),
    card(null, table([
      { label: "#", render: (g) => `#${g.grant_id}` },
      { label: "Organization", render: (g) => h("span", null, h("strong", null, g.tenant_name || `#${g.tenant_id}`), h("div", { class: "small muted" }, `${g.scope.replace("_", " ").toLowerCase()} · ${g.ticket_ref}`)) },
      { label: "Status", render: (g) => h("span", null, badge(g.status, BG_TONE[g.status]), g.is_live ? h("div", { class: "small" }, `until ${fmt.date(g.expires_at)}`) : null, !g.notify_customer ? h("div", null, badge("legal hold", "warn")) : null) },
      { label: "Requested by", render: (g) => h("span", { class: "small" }, g.requested_by_email, h("div", { class: "muted" }, fmt.ago(g.requested_at))) },
      { label: "Decided by", render: (g) => h("span", { class: "small" }, g.decided_by_email || "–") },
      { label: "", right: true, render: (g) => h("span", { class: "row end" },
        g.status === "PENDING" && g.requested_by !== me && [h("button", { class: "btn sm primary", onclick: note("Approve", "Note (what you verified)", (n) => post(`/break-glass/${g.grant_id}/approve`, { note: n })) }, "Approve"),
          h("button", { class: "btn sm danger", onclick: note("Reject", "Reason", (n) => post(`/break-glass/${g.grant_id}/reject`, { note: n })) }, "Reject")],
        g.status === "PENDING" && g.requested_by === me && h("span", { class: "small muted" }, "awaiting another operator"),
        g.status === "APPROVED" && g.requested_by === me && h("button", { class: "btn sm primary", onclick: act(() => post(`/break-glass/${g.grant_id}/activate`), "Access window started") }, "Activate"),
        g.is_live && g.requested_by === me && h("button", { class: "btn sm primary", onclick: () => accessConsole(g) }, "Open"),
        g.is_live && g.requested_by === me && h("button", { class: "btn sm", onclick: note("End access", "Summary of what was done", (n) => post(`/break-glass/${g.grant_id}/close`, { note: n })) }, "End"),
        ["PENDING", "APPROVED", "ACTIVE"].includes(g.status) && h("button", { class: "btn sm danger", onclick: note("Revoke", "Reason", (n) => post(`/break-glass/${g.grant_id}/revoke`, { note: n })) }, "Revoke")) }],
    items, { onRow: (g) => modal(`Break-glass #${g.grant_id}`, jsonBlock(g), { wide: true, footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Close")] }),
      empty: empty("No requests", "Start one from Organizations when emergency access is genuinely required.", null, "lock") }), { flush: true }));
}

const TABLES = ["customers", "orders", "order_items", "products", "payments", "users", "audit_log", "activity_log", "alerts", "change_requests", "external_events", "sources", "webhooks"];

function accessConsole(g) {
  const out = h("div");
  const tbl = select(TABLES, "orders", {});
  const offset = { v: 0 };
  const load = async () => {
    out.replaceChildren(loading(3));
    try {
      const r = await get(`/break-glass/${g.grant_id}/data/${tbl.value}`, { limit: 50, offset: offset.v });
      const cols = r.items.length ? Object.keys(r.items[0]) : [];
      out.replaceChildren(r.items.length ? table(cols.map((c) => ({ label: c, render: (row) => h("span", { class: "small mono" }, fmt.short(fmt.value(row[c]), 60)) })), r.items)
        : empty("No rows", null, null, "list"),
      h("div", { class: "pager" }, h("span", { style: "flex:1" }, r.items.length ? `Read-only · rows ${offset.v + 1}–${offset.v + r.items.length}` : "Read-only · no rows"),
        h("button", { class: "btn sm", disabled: offset.v === 0, onclick: () => { offset.v = Math.max(0, offset.v - 50); load(); } }, "Previous"),
        h("button", { class: "btn sm", disabled: r.items.length < 50, onclick: () => { offset.v += 50; load(); } }, "Next")));
    } catch (e) { out.replaceChildren(errorBox(e)); }
  };
  tbl.addEventListener("change", () => { offset.v = 0; load(); });
  const recovery = g.scope === "ACCOUNT_RECOVERY" ? h("div", { class: "stack" }, h("h3", null, "Account recovery"), recoveryPanel(g)) : null;
  const left = h("span", { class: "badge bad" });
  const tick = () => { const s = Math.max(0, Math.round((new Date(g.expires_at) - Date.now()) / 1000)); left.textContent = s ? `expires in ${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}` : "expired"; };
  tick(); const timer = setInterval(tick, 1000);
  modal(`Break-glass #${g.grant_id}: ${g.tenant_name || g.tenant_id}`, h("div", { class: "stack" },
    h("div", { class: "alert warn" }, icon("alert"), h("div", null, "Every view is recorded in the platform audit chain", g.notify_customer ? " and shown to the organization. " : " (legal hold: not shown to the organization). ", left)),
    recovery, h("div", { class: "row" }, field("Table", tbl), h("button", { class: "btn", onclick: load }, icon("refresh", 15), "Load")), out),
  { wide: true, onClose: () => clearInterval(timer), footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Close")] });
  load();
}

function recoveryPanel(g) {
  const box = h("div", null, loading(2));
  get(`/break-glass/${g.grant_id}/users`).then(({ items }) => box.replaceChildren(table([
    { label: "User", render: (u) => h("span", null, h("strong", null, u.full_name), h("div", { class: "small muted" }, u.email)) },
    { label: "Role", render: (u) => u.role }, { label: "Status", render: (u) => badge(u.is_active ? "active" : "deactivated", u.is_active ? "ok" : "bad") },
    { label: "", right: true, render: (u) => h("span", { class: "row end" },
      h("button", { class: "btn sm", onclick: () => recover(g, u, "reset-password") }, "Reset password"),
      !u.is_active && h("button", { class: "btn sm", onclick: () => recover(g, u, "reactivate") }, "Reactivate"),
      h("button", { class: "btn sm", onclick: () => recover(g, u, "revoke-sessions") }, "Sign out everywhere")) }], items))).catch((e) => box.replaceChildren(errorBox(e)));
  return box;
}

async function recover(g, u, action) {
  if (!(await confirmDialog(`${action.replace("-", " ")} for ${u.email}?`, "Recorded in the platform audit chain and in the organization's own audit trail.", "Proceed"))) return;
  try {
    const r = await post(`/break-glass/${g.grant_id}/users/${u.user_id}/${action}`);
    if (r.temporary_password) modal("Temporary password", h("div", { class: "stack" }, h("div", { class: "alert warn" }, icon("alert"), "Shown once. Give it to the verified account owner over a separate channel."), codeBlock(r.temporary_password)), { footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Done")] });
    else toast("Done", "ok");
  } catch (e) { fail(e); }
}

// ---------------------------------------------------------------- platform audit
async function audit() {
  const f = { actor: "", action: "", tenant_id: "" };
  const host = h("div"), verifyOut = h("div");
  const load = async () => {
    host.replaceChildren(loading(4));
    try {
      const r = await get("/audit", { ...f, limit: 100 });
      host.replaceChildren(table([{ label: "#", render: (a) => h("span", { class: "mono muted" }, a.seq) }, { label: "When", render: (a) => h("span", { class: "small" }, fmt.date(a.occurred_at)) },
        { label: "Operator", render: (a) => h("span", { class: "small" }, a.actor) }, { label: "Action", render: (a) => h("span", null, h("strong", null, a.action), a.target_tenant_id ? h("div", { class: "small muted" }, `organization #${a.target_tenant_id}`) : null) },
        { label: "Result", render: (a) => badge(a.outcome, a.outcome === "SUCCESS" ? "ok" : a.outcome === "DENIED" ? "warn" : "bad") },
        { label: "IP", render: (a) => h("span", { class: "mono small" }, a.ip_address || "–") }], r.items,
      { onRow: (a) => modal(`Platform audit #${a.seq}`, jsonBlock(a), { wide: true, footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Close")] }), empty: empty("No records match", null, null, "list") }));
    } catch (e) { host.replaceChildren(errorBox(e)); }
  };
  const t = (k, ph) => input({ type: "search", placeholder: ph, oninput: (e) => { f[k] = e.target.value.trim(); clearTimeout(f.t); f.t = setTimeout(load, 300); } });
  const verify = async () => {
    verifyOut.replaceChildren(loading(1));
    try {
      const v = await post("/audit/verify", { checkpoints: [] });
      verifyOut.replaceChildren(h("div", { class: `alert ${v.ok ? "ok" : "bad"}` }, icon(v.ok ? "shield" : "alert"),
        v.ok ? `Intact: ${fmt.n(v.checked)} records, ${v.checkpoints.stored} stored and ${v.checkpoints.anchor} anchored checkpoint(s) match.` : `Tampering detected at record ${v.first_bad_seq}: ${v.reason}`));
    } catch (e) { verifyOut.replaceChildren(errorBox(e)); }
  };
  const exportCsv = async () => {
    try { const r = await call("GET", "/audit/export", undefined, { params: f, raw: true }); const a = h("a", { href: URL.createObjectURL(await r.blob()), download: "platform-audit.csv" }); document.body.append(a); a.click(); a.remove(); }
    catch (e) { fail(e); }
  };
  load();
  return h("div", { class: "stack" }, pageHead("Platform audit chain", "Every operator request, approval, access and action, linked by SHA-256 and anchored by signed checkpoints.",
    [h("button", { class: "btn primary", onclick: verify }, icon("shield", 16), "Verify now"), h("button", { class: "btn", onclick: async () => { try { const r = await post("/audit/checkpoints"); toast(r.seq ? `Checkpoint #${r.seq} signed` : (r.message || r.reason), r.ok === false ? "bad" : "ok"); } catch (e) { fail(e); } } }, "Sign checkpoint"),
      h("button", { class: "btn", onclick: exportCsv }, icon("download", 15), "Export CSV")]),
  verifyOut, h("div", { class: "card" }, h("div", { class: "filters" }, field("Operator", t("actor", "email")), field("Action", t("action", "e.g. breakglass")), field("Organization id", t("tenant_id", "#"))), host));
}

// ---------------------------------------------------------------- operators
async function operators() {
  const { items } = await get("/operators");
  const me = S.me.platform_user_id;
  const act = (fn, msg) => async () => { try { await fn(); toast(msg, "ok"); rerender(); } catch (e) { fail(e); } };
  return h("div", { class: "stack" }, pageHead("Operators", "Individual accounts only, with mandatory MFA. You cannot change your own role or status.",
    h("button", { class: "btn primary", onclick: addOperator }, icon("plus", 16), "Add operator")),
  card(null, table([{ label: "Operator", render: (o) => h("span", null, h("strong", null, o.full_name), o.platform_user_id === me ? " (you)" : "", h("div", { class: "small muted" }, o.email)) },
    { label: "Role", render: (o) => o.platform_user_id === me ? badge(o.role.replace("_", " "), "info") : select([["super_admin", "Super admin"], ["security_officer", "Security officer"]], o.role, { "aria-label": `Role of ${o.email}`, onchange: async (e) => { try { await call("PATCH", `/operators/${o.platform_user_id}`, { role: e.target.value }); toast("Role changed", "ok"); } catch (x) { fail(x); rerender(); } } }) },
    { label: "MFA", render: (o) => badge(o.mfa_enabled ? "enrolled" : "pending", o.mfa_enabled ? "ok" : "warn") },
    { label: "Status", render: (o) => badge(o.is_active ? "active" : "deactivated", o.is_active ? "ok" : "bad") }, { label: "Last sign-in", render: (o) => fmt.ago(o.last_login_at) },
    { label: "", right: true, render: (o) => o.platform_user_id !== me && h("span", { class: "row end" },
      h("button", { class: "btn sm", onclick: act(() => call("PATCH", `/operators/${o.platform_user_id}`, { is_active: !o.is_active }), "Updated") }, o.is_active ? "Deactivate" : "Reactivate"),
      h("button", { class: "btn sm", onclick: act(() => post(`/operators/${o.platform_user_id}/reset-mfa`), "MFA reset; they must enrol again") }, "Reset MFA")) }], items), { flush: true }));
}

function addOperator() {
  const email = input({ type: "email", required: true }), name = input({ required: true, minlength: "2", maxlength: "120" });
  const role = select([["security_officer", "Security officer"], ["super_admin", "Super admin"]], "security_officer", {});
  formDialog("Add operator", [field("Email", email), field("Full name", name), field("Role", role)], "Add operator", async (close) => {
    const r = await post("/operators", { email: email.value, full_name: name.value, role: role.value });
    close();
    modal("Temporary password", h("div", { class: "stack" }, h("div", { class: "alert warn" }, icon("alert"), r.note), codeBlock(r.temporary_password)), { onClose: rerender, footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Done")] });
  });
}

login();
