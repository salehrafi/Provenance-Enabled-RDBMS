// Alerts, approvals, integrations, webhooks, team, settings.
import { h, icon, get, post, patch, del, api, state, can, fmt, badge, hash, card, pageHead, table, empty, field, input, select, modal, formDialog,
  confirmDialog, toast, fail, tabs, loading, errorBox, jsonBlock, codeBlock, copy, navigate, rerender, ApiError, stat } from "./lib.js";

const act = (fn, msg) => async () => { try { await fn(); if (msg) toast(msg, "ok"); rerender(); } catch (e) { fail(e); } };

// ================================================================ alerts
export async function alerts(_p, q) {
  const f = { status: q.status ?? "OPEN", severity: "" };
  const host = h("div");
  const load = async () => {
    host.replaceChildren(loading(4));
    try {
      const [{ items }, rules] = await Promise.all([get("/alerts", { status: f.status, severity: f.severity }), get("/alerts/rules")]);
      const names = Object.fromEntries(rules.items.map((r) => [r.code, r.name]));
      host.replaceChildren(table([
        { label: "Severity", render: (a) => badge(a.severity) }, { label: "Finding", render: (a) => h("span", null, h("strong", null, a.title), h("div", { class: "small muted" }, `${a.rule_code} · ${names[a.rule_code] || ""}`)) },
        { label: "Status", render: (a) => badge(a.status) }, { label: "Raised", render: (a) => fmt.ago(a.created_at) },
        { label: "", right: true, render: (a) => can("alerts:manage") && h("span", { class: "row end" },
          a.status === "OPEN" && h("button", { class: "btn sm", onclick: act(() => patch(`/alerts/${a.alert_id}`, { status: "ACKNOWLEDGED" })) }, "Acknowledge"),
          a.status !== "RESOLVED" && h("button", { class: "btn sm", onclick: act(() => patch(`/alerts/${a.alert_id}`, { status: "RESOLVED" })) }, "Resolve"),
          a.status === "RESOLVED" && h("button", { class: "btn sm", onclick: act(() => patch(`/alerts/${a.alert_id}`, { status: "OPEN" })) }, "Reopen")) }],
      items, { onRow: (a) => modal(a.title, h("div", { class: "stack" }, a.entity && h("a", { href: `#/explorer/${a.entity}/${encodeURIComponent(a.entity_id)}` }, `Open ${a.entity} ${a.entity_id} in the explorer`), jsonBlock(a.details)), { wide: true, footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Close")] }),
        empty: empty("Nothing to review", f.status === "OPEN" ? "No open alerts. Rules run every minute." : "No alerts match.", null, "check") }));
    } catch (e) { host.replaceChildren(errorBox(e)); }
  };
  load();
  return h("div", { class: "stack" }, pageHead("Alerts", "Data-quality and anomaly rules run continuously over your orders and audit log.",
    can("alerts:manage") && h("button", { class: "btn", onclick: async (e) => { e.target.disabled = true; try { const r = await post("/alerts/run"); toast(`${r.new_alerts} new alert(s)`, r.new_alerts ? "" : "ok"); load(); } catch (x) { fail(x); } e.target.disabled = false; } }, icon("refresh", 16), "Run checks now")),
  h("div", { class: "card" }, h("div", { class: "filters" },
    field("Status", select([["", "All"], "OPEN", "ACKNOWLEDGED", "RESOLVED"], f.status, { onchange: (e) => { f.status = e.target.value; load(); } })),
    field("Severity", select([["", "All"], "CRITICAL", "HIGH", "MEDIUM", "LOW"], "", { onchange: (e) => { f.severity = e.target.value; load(); } }))), host));
}

// ================================================================ approvals
export async function approvals() {
  const { items } = await get("/approvals");
  const money = (v) => fmt.money(v);
  return h("div", { class: "stack" }, pageHead("Approvals", "Maker-checker: a price change above the threshold is applied only after a different admin approves it. The database itself refuses self-approval."),
    card(null, table([
      { label: "Change", render: (r) => h("span", null, h("strong", null, r.product_name || `${r.entity} ${r.entity_id}`), h("div", { class: "small muted" }, r.change_type.replace("_", " ").toLowerCase())) },
      { label: "From → to", render: (r) => r.payload?.old_price !== undefined ? h("span", { class: "num" }, `${money(r.payload.old_price)} → ${money(r.payload.new_price)} `, h("span", { class: "muted small" }, `(${r.payload.change_pct}%)`)) : "–" },
      { label: "Requested by", render: (r) => h("span", null, r.requested_by, h("div", { class: "small muted" }, fmt.ago(r.requested_at), r.reason ? ` · “${r.reason}”` : "")) },
      { label: "Status", render: (r) => h("span", null, badge(r.status), r.reviewed_by && h("div", { class: "small muted" }, `by ${r.reviewed_by}`)) },
      { label: "", right: true, render: (r) => r.can_review ? h("span", { class: "row end" },
        h("button", { class: "btn sm primary", onclick: () => review(r, "approve") }, "Approve"), h("button", { class: "btn sm danger", onclick: () => review(r, "reject") }, "Reject"))
        : r.status === "PENDING" ? h("span", { class: "small muted" }, "Awaiting another admin") : null }],
    items, { empty: empty("No change requests", "When someone changes a price by more than the threshold, it appears here for approval.", null, "check") }), { flush: true }));
}

function review(r, verb) {
  const note = input({ maxlength: "500", placeholder: "Optional note" });
  formDialog(`${verb === "approve" ? "Approve" : "Reject"} change`, [h("p", null, verb === "approve" ? "The new price is applied immediately and the audit record links back to this approval." : "The price stays as it is."), field("Note", note)],
    verb === "approve" ? "Approve" : "Reject", async (close) => { await post(`/approvals/${r.change_request_id}/${verb}`, { note: note.value || null }); close(); toast(verb === "approve" ? "Approved and applied" : "Rejected", "ok"); rerender(); });
}

// ================================================================ integrations
export async function integrations(p) {
  return h("div", { class: "stack" }, pageHead("Integrations", "Connect the systems that hold your data. Each event becomes tamper-evident evidence, attributed to its source and trust level."),
    tabs([["sources", "Sources"], ["keys", "API keys"], ["import", "CSV import"], ["reconcile", "Reconciliation"]], p.tab || "sources", async (t) => ({ sources, keys, import: importTab, reconcile })[t]()));
}

const CAPTURE = [["CDC", "CDC (change data capture)"], ["TRIGGER", "Database trigger"], ["API", "API"], ["POLLING", "Polling"], ["CSV_IMPORT", "CSV import"], ["MANUAL", "Manual entry"]];

async function sources() {
  const { items } = await get("/sources");
  const first = items[0]?.code || "my-system";
  return h("div", { class: "stack" },
    card("Registered sources", table([
      { label: "Source", render: (s) => h("span", null, h("strong", null, s.name), h("div", { class: "small muted mono" }, s.code)) },
      { label: "Capture", render: (s) => s.capture_method }, { label: "Trust", render: (s) => badge(s.trust_level, s.trust_level === "HIGH" ? "ok" : s.trust_level === "LOW" ? "warn" : "info") },
      { label: "Status", render: (s) => badge(s.status) }, { label: "Events", right: true, render: (s) => fmt.n(s.event_count) }, { label: "Last event", render: (s) => fmt.ago(s.last_event_at) },
      { label: "", right: true, render: (s) => can("sources:manage") && h("button", { class: "btn sm", onclick: act(() => patch(`/sources/${s.source_id}`, { status: s.status === "ACTIVE" ? "PAUSED" : "ACTIVE" })) }, s.status === "ACTIVE" ? "Pause" : "Resume") }],
    items, { empty: empty("No sources yet", "A source is an upstream system, such as your shop, ERP or a CDC pipeline. Its trust level is set here by an admin, never by the sender.", can("sources:manage") && h("button", { class: "btn primary", onclick: sourceDialog }, "Register a source"), "plug") }),
    { flush: true, actions: can("sources:manage") && items.length > 0 && h("button", { class: "btn sm primary", onclick: sourceDialog }, icon("plus", 14), "Register source") }),
    card("Send your first event", h("div", { class: "stack" }, h("p", { class: "muted" }, "Create an API key with the ", h("code", null, "events:write"), " scope, then:"),
      codeBlock(curlExample(first)))));
}

function curlExample(code) {
  return `curl -X POST ${location.origin}/api/v1/events \\
  -H "Authorization: Bearer $PROV_API_KEY" -H "Content-Type: application/json" \\
  -d '{"specversion":"1.0","id":"evt-0001","source":"${code}","type":"order.updated",
       "subject":"order/10045","time":"${new Date().toISOString()}",
       "data":{"op":"u","before":{"total":"1500.00"},"after":{"total":"1200.00"}}}'`;
}

function sourceDialog() {
  const code = input({ required: true, pattern: "[a-z0-9][a-z0-9._-]{1,59}", placeholder: "legacy-shop" }), name = input({ required: true, maxlength: "120", placeholder: "Legacy shop" });
  const method = select(CAPTURE, "CDC", {}), trust = select([["HIGH", "High: captured at the database"], ["MEDIUM", "Medium"], ["LOW", "Low: best effort or manual"]], "MEDIUM", {});
  formDialog("Register a source", [field("Code", code, "Lowercase letters, digits, . _ -. Used as the CloudEvents source."), field("Name", name), field("How is data captured?", method), field("How much do you trust it?", trust, "Copied onto every event. Senders cannot change it.")],
    "Register", async (close) => { await post("/sources", { code: code.value, name: name.value, capture_method: method.value, trust_level: trust.value }); close(); toast("Source registered", "ok"); rerender(); });
}

async function keys() {
  const { items, scopes } = await get("/api-keys");
  return card("API keys", table([
    { label: "Name", render: (k) => h("span", null, h("strong", null, k.name), h("div", { class: "small muted mono" }, `prv_${k.key_id}_…`)) },
    { label: "Scopes", render: (k) => h("span", { class: "row" }, k.scopes.map((s) => badge(s, "plain"))) },
    { label: "Last used", render: (k) => fmt.ago(k.last_used_at) }, { label: "Expires", render: (k) => k.expires_at ? fmt.date(k.expires_at) : "Never" },
    { label: "Status", render: (k) => k.revoked_at ? badge("revoked", "bad") : badge("active", "ok") },
    { label: "", right: true, render: (k) => !k.revoked_at && can("apikeys:manage") && h("button", { class: "btn sm danger", onclick: async () => { if (await confirmDialog("Revoke this key?", `Systems using “${k.name}” stop working immediately.`, "Revoke", true)) act(() => del(`/api-keys/${k.key_id}`), "Key revoked")(); } }, "Revoke") }],
  items, { empty: empty("No API keys", "Create a key so a system can send events or read data.", can("apikeys:manage") && h("button", { class: "btn primary", onclick: () => keyDialog(scopes) }, "Create API key"), "lock") }),
  { flush: true, actions: can("apikeys:manage") && items.length > 0 && h("button", { class: "btn sm primary", onclick: () => keyDialog(scopes) }, icon("plus", 14), "Create key") });
}

function keyDialog(scopes) {
  const name = input({ required: true, maxlength: "100", placeholder: "legacy-connector" });
  const boxes = Object.entries(scopes).map(([s, d]) => ({ s, el: input({ type: "checkbox", checked: s.startsWith("events:") }), d }));
  const exp = select([["", "Never expires"], ["30", "30 days"], ["90", "90 days"], ["365", "1 year"]], "90", {});
  formDialog("Create API key", [field("Name", name), h("div", null, h("div", { class: "lbl" }, "Scopes"), h("div", { class: "stack", style: "gap:6px;margin-top:6px" }, boxes.map((b) => h("label", { class: "row", style: "font-weight:400" }, b.el, h("code", null, b.s), h("span", { class: "muted small" }, b.d))))), field("Expiry", exp, "Keys with an expiry limit the damage of a leak.")],
    "Create key", async (close) => {
      const chosen = boxes.filter((b) => b.el.checked).map((b) => b.s);
      if (!chosen.length) throw new ApiError(422, { detail: "Choose at least one scope." });
      const r = await post("/api-keys", { name: name.value, scopes: chosen, ...(exp.value ? { expires_in_days: Number(exp.value) } : {}) });
      close();
      modal("Copy your key now", h("div", { class: "stack" }, h("div", { class: "alert warn" }, icon("alert"), "This is the only time the key is shown. We store only a hash."), codeBlock(r.api_key),
        h("div", { class: "lbl" }, "Try it"), codeBlock(`export PROV_API_KEY=${r.api_key}\n` + curlExample("your-source-code"))), { wide: true, onClose: rerender, footer: (c) => [h("button", { class: "btn primary", onclick: c }, "I've saved it")] });
    });
}

async function importTab() {
  const { items } = await get("/sources");
  if (!items.length) return h("div", { class: "card" }, empty("Register a source first", "CSV snapshots are recorded against a source.", h("a", { class: "btn primary", href: "#/integrations/sources" }, "Go to sources"), "plug"));
  const src = select(items.map((s) => [s.code, `${s.name} (${s.code})`]), items[0].code, {}), ent = input({ required: true, pattern: "[a-z][a-z0-9_]{0,29}", value: "customer" });
  const file = input({ type: "file", accept: ".csv,text/csv", required: true }), complete = input({ type: "checkbox" }), dry = input({ type: "checkbox", checked: true });
  const out = h("div");
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    const fd = new FormData(); fd.append("file", file.files[0]); fd.append("source", src.value); fd.append("entity", ent.value); fd.append("complete", complete.checked); fd.append("dry_run", dry.checked);
    out.replaceChildren(loading(2));
    try {
      const r = await api("POST", "/imports", fd);
      out.replaceChildren(h("div", { class: "stack" }, h("div", { class: `alert ${r.dry_run ? "info" : "ok"}` }, icon("check"), r.dry_run ? "Preview only. Nothing was recorded. " : "Recorded. ", `${r.created} created · ${r.updated} updated · ${r.deleted} deleted · ${r.unchanged} unchanged`),
        r.changes.length ? table([{ label: "Record", key: "external_id" }, { label: "Change", render: (c) => badge(c.change, c.change === "created" ? "ok" : c.change === "deleted" ? "bad" : "info") }, { label: "Fields", render: (c) => (c.changed_fields || Object.keys(c.after || {})).join(", ") }], r.changes) : null));
    } catch (x) { out.replaceChildren(errorBox(x)); }
  } }, h("div", { class: "form cols" }, field("Source", src), field("Entity", ent, "What each row is, e.g. customer or order")),
  field("Snapshot file (CSV)", file, "Needs an external_id column; every other column is a field. Only differences from what we hold are recorded."),
  h("label", { class: "row", style: "font-weight:400" }, dry, "Preview only (dry run)"), h("label", { class: "row", style: "font-weight:400" }, complete, "This file is the complete set: rows missing from it are recorded as deleted"),
  h("div", null, h("button", { class: "btn primary", type: "submit" }, "Run import")));
  return h("div", { class: "stack" }, card("Import a CSV snapshot", form), out);
}

async function reconcile() {
  const [runs, srcs] = await Promise.all([get("/reconciliations"), get("/sources")]);
  const upload = srcs.items.length && can("imports:write") && (() => {
    const src = select(srcs.items.map((s) => [s.code, s.name]), srcs.items[0].code, {}), ent = input({ required: true, value: "customer" }), file = input({ type: "file", accept: ".csv", required: true }), complete = input({ type: "checkbox" });
    return h("button", { class: "btn sm primary", onclick: () => formDialog("Reconcile a CSV snapshot", [field("Source", src), field("Entity", ent), field("CSV (external_id + fields to compare)", file), h("label", { class: "row", style: "font-weight:400" }, complete, "Complete snapshot (detect records the upstream no longer has)")], "Reconcile", async (close) => {
      const fd = new FormData(); fd.append("file", file.files[0]); fd.append("source", src.value); fd.append("entity", ent.value); fd.append("complete", complete.checked);
      const r = await api("POST", "/reconciliations/upload", fd); close(); toast(`${r.matched} matched, ${r.mismatched + r.missing + r.unexpected} issue(s)`, r.mismatched + r.missing + r.unexpected ? "" : "ok"); rerender();
    }) }, icon("plus", 14), "Reconcile a file");
  })();
  return card("Reconciliation runs", table([{ label: "Run", render: (r) => `#${r.recon_id}` }, { label: "Source / entity", render: (r) => `${r.source} / ${r.entity}` }, { label: "When", render: (r) => fmt.ago(r.created_at) },
    { label: "Matched", right: true, key: "matched" }, { label: "Mismatch", right: true, render: (r) => r.mismatched ? badge(r.mismatched, "warn") : 0 }, { label: "Missing", right: true, render: (r) => r.missing ? badge(r.missing, "bad") : 0 },
    { label: "Unexpected", right: true, render: (r) => r.unexpected ? badge(r.unexpected, "info") : 0 }], runs.items,
  { onRow: async (r) => { try { const d = await get(`/reconciliations/${r.recon_id}`); modal(`Reconciliation #${r.recon_id}`, d.issues.length ? table([{ label: "Record", key: "external_id" }, { label: "Outcome", render: (i) => badge(i.outcome) }, { label: "Details", render: (i) => h("code", null, fmt.short(JSON.stringify(i.details), 120)) }], d.issues) : empty("Everything matched", null, null, "check"), { wide: true, footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Close")] }); } catch (e) { fail(e); } },
    empty: empty("No reconciliations yet", "Send your system's current records (API or CSV) and we compare them with the evidence we hold, flagging what disagrees.", null, "diff") }),
  { flush: true, actions: upload || null, sub: "MISMATCH: a field differs · MISSING: upstream has it, we never saw it · UNEXPECTED: we hold it, upstream does not" });
}

// ================================================================ webhooks
export async function webhooks() {
  const { items } = await get("/webhooks");
  return h("div", { class: "stack" }, pageHead("Webhooks", "Signed, retried deliveries of every event: Standard Webhooks signatures, exponential backoff, and a dead-letter state you can inspect and retry.",
    h("button", { class: "btn primary", onclick: webhookDialog }, icon("plus", 16), "Add endpoint")),
  card(null, table([{ label: "Endpoint", render: (w) => h("span", null, h("strong", null, w.url), h("div", { class: "small muted" }, w.description || "")) },
    { label: "Events", render: (w) => h("span", { class: "mono small" }, w.event_types.join(", ")) }, { label: "Status", render: (w) => w.is_active ? badge("ACTIVE") : badge("PAUSED") },
    { label: "Delivered", right: true, key: "delivered" }, { label: "Failing", right: true, render: (w) => (w.failing ? badge(w.failing, "bad") : 0) }], items,
  { onRow: deliveriesDialog, empty: empty("No endpoints", "Add an HTTPS URL to receive events such as order.status_changed, alert.raised and audit.checkpoint.", h("button", { class: "btn primary", onclick: webhookDialog }, "Add endpoint"), "webhook") }), { flush: true }));
}

function webhookDialog() {
  const url = input({ type: "url", required: true, placeholder: "https://example.com/hooks/provenance" }), types = input({ value: "*", required: true }), desc = input({ maxlength: "200" });
  formDialog("Add webhook endpoint", [field("URL", url, "HTTPS only. Private and internal addresses are refused."), field("Event types", types, "Comma-separated, e.g. order.*, alert.raised, audit.checkpoint. * means everything."), field("Description", desc)],
    "Add endpoint", async (close) => {
      const r = await post("/webhooks", { url: url.value, event_types: types.value.split(",").map((s) => s.trim()).filter(Boolean), description: desc.value || null });
      close();
      modal("Signing secret", h("div", { class: "stack" }, h("div", { class: "alert warn" }, icon("alert"), "Shown once. Use it to verify the webhook-signature header."), codeBlock(r.secret), verifySnippet()), { wide: true, onClose: rerender, footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Done")] });
    });
}

const verifySnippet = () => codeBlock(`# Python: verify a delivery (Standard Webhooks)
import base64, hashlib, hmac, time
def verify(secret, headers, body: bytes):
    msg_id, ts, sigs = headers["webhook-id"], headers["webhook-timestamp"], headers["webhook-signature"]
    if abs(time.time() - int(ts)) > 300: raise ValueError("stale")           # reject replays
    key = base64.b64decode(secret.removeprefix("whsec_"))
    mac = base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
    if not any(hmac.compare_digest(mac, s.split(",", 1)[1]) for s in sigs.split(" ")): raise ValueError("bad signature")
    # dedupe on msg_id: deliveries are at-least-once`);

async function deliveriesDialog(w) {
  const body = h("div", { class: "stack" }, loading(3));
  const load = async () => {
    const d = (await get(`/webhooks/${w.webhook_id}/deliveries`, { limit: 100 })).items;
    body.replaceChildren(table([{ label: "Event", render: (x) => h("span", null, x.event_type, h("div", { class: "small muted" }, fmt.date(x.created_at))) }, { label: "Status", render: (x) => badge(x.status) },
      { label: "Attempts", right: true, key: "attempts" }, { label: "Result", render: (x) => h("span", { class: "small" }, x.response_code ? `HTTP ${x.response_code}` : "", x.last_error && h("div", { class: "muted" }, fmt.short(x.last_error, 60)), x.status === "FAILED" && h("div", { class: "muted" }, `next try ${fmt.ago(x.next_attempt_at).replace("ago", "").trim() || "soon"}`)) },
      { label: "", right: true, render: (x) => (x.status === "FAILED" || x.status === "DEAD") && h("button", { class: "btn sm", onclick: act(async () => { await post(`/webhooks/deliveries/${x.delivery_id}/retry`); await load(); }, "Queued for retry") }, "Retry") }], d,
    { empty: empty("No deliveries yet", "Send a test event to see one.", null, "webhook") }));
  };
  load().catch((e) => body.replaceChildren(errorBox(e)));
  modal(w.url, h("div", { class: "stack" }, h("div", { class: "row" },
    h("button", { class: "btn sm", onclick: async () => { try { await post(`/webhooks/${w.webhook_id}/test`); toast("Test event queued. The worker sends it within seconds.", "ok"); setTimeout(load, 4000); } catch (e) { fail(e); } } }, "Send test event"),
    h("button", { class: "btn sm", onclick: act(() => patch(`/webhooks/${w.webhook_id}`, { is_active: !w.is_active })) }, w.is_active ? "Pause" : "Resume"),
    h("button", { class: "btn sm", onclick: async () => { if (await confirmDialog("Rotate the signing secret?", "The old secret stops working immediately. Update your receiver first or deliveries will fail verification.", "Rotate")) { try { const r = await post(`/webhooks/${w.webhook_id}/rotate-secret`); modal("New signing secret", codeBlock(r.secret), { footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Done")] }); } catch (e) { fail(e); } } } }, "Rotate secret"),
    h("button", { class: "btn sm danger", onclick: async () => { if (await confirmDialog("Delete this endpoint?", "Its delivery history is deleted too.", "Delete", true)) act(() => del(`/webhooks/${w.webhook_id}`), "Deleted")(); } }, "Delete")),
  h("h3", null, "Delivery log"), body), { wide: true, footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Close")] });
}

// ================================================================ team
const ROLE_TEXT = { admin: "Everything, including users, keys, webhooks and approvals.", staff: "Create and edit customers, products and orders; manage alerts; export audit.", auditor: "Read everything, verify integrity and export evidence. Cannot change data.", viewer: "Read-only access to business data and history." };

export async function team() {
  const { items } = await get("/users");
  const me = state.me.user_id;
  return h("div", { class: "stack" }, pageHead("Team", "Who can see and change what. Role changes and deactivations take effect immediately, including for sessions already signed in.", h("button", { class: "btn primary", onclick: userDialog }, icon("plus", 16), "Add user")),
    card(null, table([{ label: "Name", render: (u) => h("span", null, h("strong", null, u.full_name), u.user_id === me && " (you)", h("div", { class: "small muted" }, u.email)) },
      { label: "Role", render: (u) => u.user_id === me ? badge(u.role, "brand") : select(["admin", "staff", "auditor", "viewer"], u.role, { "aria-label": `Role of ${u.full_name}`, onchange: act((e) => patch(`/users/${u.user_id}`, { role: e.target.value }), "Role updated") }) },
      { label: "Status", render: (u) => (u.is_active ? badge("ACTIVE") : badge("deactivated", "bad")) }, { label: "Last sign-in", render: (u) => fmt.ago(u.last_login_at) },
      { label: "", right: true, render: (u) => u.user_id !== me && h("button", { class: `btn sm ${u.is_active ? "danger" : ""}`, onclick: async () => { if (!u.is_active || await confirmDialog(`Deactivate ${u.full_name}?`, "They are signed out everywhere immediately.", "Deactivate", true)) act(() => patch(`/users/${u.user_id}`, { is_active: !u.is_active }))(); } }, u.is_active ? "Deactivate" : "Reactivate") }], items), { flush: true }),
    card("Roles", h("dl", { class: "kv" }, Object.entries(ROLE_TEXT).flatMap(([r, t]) => [h("dt", null, badge(r, "plain")), h("dd", null, t)]))));
}

function userDialog() {
  const email = input({ type: "email", required: true }), name = input({ required: true, maxlength: "120" }), pw = input({ type: "text", required: true, minlength: "6", autocomplete: "off", value: crypto.randomUUID().replace(/-/g, "").slice(0, 16) + "Aa1" });
  const role = select([["viewer", "Viewer"], ["auditor", "Auditor"], ["staff", "Staff"], ["admin", "Admin"]], "viewer", {});
  formDialog("Add a user", [field("Email", email), field("Full name", name), field("Role", role), field("Temporary password", pw, "Share it securely. They should change it after signing in.")], "Add user", async (close) => {
    await post("/users", { email: email.value, full_name: name.value, password: pw.value, role: role.value }); close(); toast("User added", "ok"); rerender();
  });
}

// ================================================================ settings
export async function settings() {
  const s = await get("/settings");
  const org = state.me.tenant, canEdit = can("settings:manage");
  const f = {}, mk = (k, label, hint, attrs = {}) => { f[k] = input({ type: "number", step: "any", min: "0", value: s[k], disabled: !canEdit, ...attrs }); return field(label, f[k], hint); };
  const cur = input({ value: s.currency, maxlength: "3", pattern: "[A-Z]{3}", disabled: !canEdit });
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault();
    try { await patch("/settings", { currency: cur.value, approval_price_change_pct: f.approval_price_change_pct.value, price_change_alert_pct: f.price_change_alert_pct.value, discount_alert_pct: f.discount_alert_pct.value,
      large_refund_amount: f.large_refund_amount.value, rapid_change_count: Number(f.rapid_change_count.value), rapid_change_minutes: Number(f.rapid_change_minutes.value) }); toast("Settings saved", "ok"); state.currency = cur.value; } catch (x) { fail(x); }
  } }, h("div", { class: "form cols" }, field("Currency (ISO code)", cur), mk("approval_price_change_pct", "Price change needing approval (%)", "At or above this, a second admin must approve."),
    mk("price_change_alert_pct", "Price change alert (%)"), mk("discount_alert_pct", "Deep discount alert (%)", "Compared with list price at order time."),
    mk("large_refund_amount", "Large refund alert (amount)"), mk("rapid_change_count", "Rapid edits: count", null, { step: "1", min: "2" }), mk("rapid_change_minutes", "Rapid edits: within minutes", null, { step: "1", min: "1" })),
  canEdit && h("div", null, h("button", { class: "btn primary", type: "submit" }, "Save settings")));
  const pw = () => { const a = input({ type: "password", required: true, autocomplete: "current-password" }), b = input({ type: "password", required: true, minlength: "6", autocomplete: "new-password" });
    formDialog("Change password", [field("Current password", a), field("New password", b, "At least 6 characters. Signs out all other sessions.")], "Change password", async (close) => {
      const r = await post("/auth/password", { current_password: a.value, new_password: b.value }); state.token = r.access_token; close(); toast("Password changed", "ok"); }); };
  return h("div", { class: "stack" }, pageHead("Settings", org.name),
    card("Thresholds", form, { sub: "Control when changes need approval and when rules raise alerts" }),
    card("Your account", h("div", { class: "row" }, h("button", { class: "btn", onclick: pw }, icon("lock", 16), "Change password"),
      h("button", { class: "btn", onclick: async () => { if (await confirmDialog("Sign out everywhere?", "Every device, including this one, is signed out.", "Sign out everywhere")) { try { await post("/auth/logout-all"); state.token = null; state.me = null; location.reload(); } catch (e) { fail(e); } } } }, icon("logout", 16), "Sign out everywhere"))),
    canEdit && card("Rename organization", (() => { const n = input({ value: org.name, required: true, minlength: "2", maxlength: "120" });
      return h("form", { class: "row", onsubmit: async (e) => { e.preventDefault(); try { await patch("/organization", { name: n.value }); toast("Renamed. Reload to see it everywhere.", "ok"); } catch (x) { fail(x); } } }, h("div", { style: "flex:1;max-width:360px" }, n), h("button", { class: "btn", type: "submit" }, "Rename")); })()),
    canEdit && card("Sandbox", h("div", { class: "row" }, h("button", { class: "btn", onclick: async () => { try { const r = await post("/sandbox/sample-data"); toast(r.message, "ok"); } catch (e) { fail(e); } } }, "Load sample data"),
      h("span", { class: "small muted" }, "Adds [sample] customers, products, orders and events through the normal audited paths."))),
    card("Developers", h("div", { class: "stack" }, h("p", { class: "muted" }, "Everything in this app is available over the versioned REST API."),
      h("div", { class: "row" }, h("a", { class: "btn", href: "/docs", target: "_blank", rel: "noopener" }, icon("file", 16), "Interactive API docs"), h("a", { class: "btn", href: "/openapi.json", target: "_blank", rel: "noopener" }, "OpenAPI spec")))));
}


// ================================================================ activity log
const OUTCOME_TONE = { SUCCESS: "ok", DENIED: "warn", FAILURE: "bad" };

export async function activity() {
  const f = { actor: "", action: "", ip: "", outcome: "", method: "", since: "", until: "" };
  const rows = [], host = h("div"), more = h("div", { class: "pager" });
  let cursor = null;
  const [sum, acts] = await Promise.all([get("/activity/summary"), get("/activity/actions")]);
  const params = () => ({ actor: f.actor, action: f.action, ip: f.ip, outcome: f.outcome, method: f.method,
    since: f.since && new Date(f.since).toISOString(), until: f.until && new Date(f.until).toISOString() });
  const load = async (reset) => {
    if (reset) { rows.length = 0; cursor = null; host.replaceChildren(loading(5)); }
    try {
      const r = await get("/activity", { ...params(), limit: 50, before_id: cursor });
      rows.push(...r.items); cursor = r.next_before_id;
      host.replaceChildren(table([
        { label: "When", render: (a) => h("span", { title: fmt.date(a.occurred_at), class: "small" }, fmt.date(a.occurred_at)) },
        { label: "Who", render: (a) => h("span", { class: "small" }, fmt.short(a.actor, 30)) },
        { label: "Action", render: (a) => h("span", null, h("strong", null, a.action), h("div", { class: "small muted mono" }, `${a.method} ${a.path}`)) },
        { label: "Result", render: (a) => h("span", null, badge(a.outcome, OUTCOME_TONE[a.outcome]), " ", h("span", { class: "small muted" }, a.status_code)) },
        { label: "IP address", render: (a) => a.ip_address ? h("span", { class: "mono small" }, a.ip_address) : h("span", { class: "muted" }, "–") }],
      rows, { onRow: detail, caption: "Activity log",
        empty: empty("No activity matches", "Sign-ins, changes and exports in your organization appear here.", null, "list") }));
      more.replaceChildren(h("span", { style: "flex:1" }, `${rows.length} shown`), cursor && h("button", { class: "btn sm", onclick: () => load(false) }, "Load older"));
    } catch (e) { host.replaceChildren(errorBox(e)); }
  };
  const exp = (format) => async () => {
    try {
      const r = await api("GET", "/activity/export", undefined, { params: { ...params(), format }, raw: true });
      if (!r.ok) throw new ApiError(r.status, await r.json());
      const a = h("a", { href: URL.createObjectURL(await r.blob()), download: `activity-log.${format}` });
      document.body.append(a); a.click(); a.remove();
    } catch (e) { fail(e); }
  };
  const debounced = () => { clearTimeout(f.t); f.t = setTimeout(() => load(true), 300); };
  const text = (key, ph, extra = {}) => input({ type: "search", placeholder: ph, ...extra, oninput: (e) => { f[key] = e.target.value.trim(); debounced(); } });
  const listId = "activity-actions";
  load(true);
  return h("div", { class: "stack" },
    pageHead("Activity log", "Who did what, from which IP address, and whether it worked. Append-only: nobody can edit or delete these records. Visible to admins only."),
    h("div", { class: "grid g4" },
      stat("Events (24 h)", fmt.n(sum.total), null, "list"), stat("Sign-ins (24 h)", fmt.n(sum.logins), null, "lock"),
      stat("Failed sign-ins (24 h)", fmt.n(sum.failed_logins), sum.failed_logins ? "Check the IP addresses below" : "None", "alert"),
      stat("Denied requests (24 h)", fmt.n(sum.denied), `${fmt.n(sum.distinct_ips)} distinct IP address(es)`, "shield")),
    h("div", { class: "card" },
      h("datalist", { id: listId }, acts.items.map((a) => h("option", { value: a }))),
      h("div", { class: "filters" },
        field("Who", text("actor", "email or key name")),
        field("Action", text("action", "e.g. login_failed", { list: listId })),
        field("IP address", text("ip", "1.2.3.4 or 1.2.3.0/24")),
        field("Result", select([["", "All"], ["SUCCESS", "Success"], ["DENIED", "Denied"], ["FAILURE", "Failed"]], "", { onchange: (e) => { f.outcome = e.target.value; load(true); } })),
        field("Method", select([["", "All"], "POST", "PUT", "PATCH", "DELETE", "GET"], "", { onchange: (e) => { f.method = e.target.value; load(true); } })),
        field("From", input({ type: "datetime-local", onchange: (e) => { f.since = e.target.value; load(true); } })),
        field("To", input({ type: "datetime-local", onchange: (e) => { f.until = e.target.value; load(true); } })),
        h("div", { class: "row" }, h("button", { class: "btn", onclick: exp("csv") }, icon("download", 15), "Export CSV"),
          h("button", { class: "btn", onclick: exp("json") }, icon("download", 15), "JSON"))),
      host, more));
}

function detail(a) {
  modal(`${a.action}`, h("div", { class: "stack" },
    h("div", { class: "row" }, badge(a.outcome, OUTCOME_TONE[a.outcome]), h("span", { class: "muted" }, `HTTP ${a.status_code} · ${a.duration_ms ?? "–"} ms`)),
    h("dl", { class: "kv small" },
      h("dt", null, "When"), h("dd", null, fmt.date(a.occurred_at)),
      h("dt", null, "Who"), h("dd", null, a.actor), h("dt", null, "API key"), h("dd", null, a.api_key_id || "–"),
      h("dt", null, "IP address"), h("dd", { class: "mono" }, a.ip_address || "unknown"),
      h("dt", null, "Request"), h("dd", { class: "mono" }, `${a.method} ${a.path}`),
      h("dt", null, "Route"), h("dd", { class: "mono" }, a.route),
      h("dt", null, "User agent"), h("dd", null, a.user_agent || "–"),
      h("dt", null, "Request id"), h("dd", null, a.request_id ? h("a", { href: `#/explorer?request=${a.request_id}` }, a.request_id) : "–")),
    Object.keys(a.details || {}).length ? jsonBlock(a.details) : null),
  { wide: true, footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Close")] });
}
