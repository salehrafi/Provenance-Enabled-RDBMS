// Provenance explorer (time travel, request trace, external records) and the audit explorer.
import { h, icon, get, post, api, state, can, fmt, badge, hash, card, pageHead, table, empty, field, input, select, modal, toast, fail,
  tabs, loading, errorBox, diffView, jsonBlock, codeBlock, copy, toLocalInput, navigate, ApiError } from "./lib.js";
import { verifyResult } from "./views_core.js";

// ================================================================ explorer
export async function explorer(params, query) {
  const ents = (await get("/provenance/entities")).items;
  const start = query.request ? "request" : "record";
  const host = h("div");
  const view = tabs([["record", "Record time travel"], ["request", "Request trace"], ["external", "External records"]], start, async (t) => {
    if (t === "record") return recordTab(ents, params);
    if (t === "request") return requestTab(query.request);
    return externalTab();
  });
  host.append(view);
  return h("div", { class: "stack" }, pageHead("Provenance explorer", "Ask where a value came from, who changed it, and what it looked like at any moment. Answers are rebuilt from the tamper-evident audit log."), host);
}

const grow = (f) => { f.classList.add("grow"); return f; };

function recordTab(ents, params) {
  const entity = select(ents.map((e) => [e.entity, `${e.entity}: ${e.label}`]), params.entity || "order", { "aria-label": "Entity" });
  const pk = input({ placeholder: "Record id, e.g. 42 (order lines: 42:7)", value: params.pk || "", "aria-label": "Record id" });
  const out = h("div");
  const go = async () => {
    if (!pk.value.trim()) return;
    history.replaceState(null, "", `#/explorer/${entity.value}/${encodeURIComponent(pk.value.trim())}`);
    out.replaceChildren(h("div", { class: "card" }, loading(4)));
    try { out.replaceChildren(await timeTravel(entity.value, pk.value.trim())); } catch (e) { out.replaceChildren(errorBox(e)); }
  };
  pk.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  if (params.pk) go();
  return h("div", { class: "stack" }, h("div", { class: "card" }, h("div", { class: "filters" },
    field("Entity", entity), grow(field("Record", pk)), h("button", { class: "btn primary", onclick: go }, icon("search", 16), "Rebuild history"))), out);
}

async function timeTravel(entity, pk) {
  const { history } = await get(`/provenance/${entity}/${encodeURIComponent(pk)}/history`);
  if (!history.length) return h("div", { class: "card" }, empty("No history for this record", "Check the entity and id. History exists only for records changed through Provenance Cloud.", null, "clock"));
  let sel = history.length - 1;
  const stateBox = h("div"), timeline = h("ol", { class: "timeline" }), slider = h("input", { type: "range", min: 0, max: history.length - 1, value: sel, "aria-label": "Move through the record's history" });
  const label = h("div", { class: "small muted" });
  const render = () => {
    const e = history[sel], cur = e.operation === "DELETE" ? null : e.new_values;
    label.textContent = `Version ${sel + 1} of ${history.length} · ${fmt.date(e.changed_at)}`;
    [...timeline.children].forEach((li, i) => li.classList.toggle("sel", i === sel));
    stateBox.replaceChildren(
      h("div", { class: "row", style: "margin-bottom:12px" }, badge(e.operation), h("strong", null, e.operation === "DELETE" ? "Record deleted" : "State after this change"), h("span", { class: "muted small" }, `by ${e.actor}`)),
      cur ? h("dl", { class: "kv" }, Object.entries(cur).flatMap(([k, v]) => [h("dt", null, k), h("dd", { class: "mono" }, fmt.value(v))])) : h("div", { class: "muted" }, "The record did not exist after this change."),
      h("h3", { style: "margin:18px 0 8px" }, "What changed"), diffView(e.changes),
      h("h3", { style: "margin:18px 0 8px" }, "Evidence"),
      h("dl", { class: "kv small" }, h("dt", null, "Chain position"), h("dd", null, `#${e.chain_seq}`), h("dt", null, "Record hash"), h("dd", null, hash(e.row_hash, 20)),
        h("dt", null, "Previous hash"), h("dd", null, hash(e.prev_hash, 20)), h("dt", null, "Database role"), h("dd", null, e.db_user),
        h("dt", null, "API request"), h("dd", null, e.request_id ? h("a", { href: `#/explorer?request=${e.request_id}` }, hash(e.request_id, 12)) : "–"),
        e.change_request_id && [h("dt", null, "Approval"), h("dd", null, `Change request #${e.change_request_id}`)]));
  };
  history.forEach((e, i) => timeline.append(h("li", { class: e.operation, tabindex: "0", onclick: () => { sel = i; slider.value = i; render(); },
    onkeydown: (ev) => { if (ev.key === "Enter") { sel = i; slider.value = i; render(); } } },
  h("span", { class: "dot" }), h("div", null, badge(e.operation), " ", h("strong", null, fmt.short(e.actor, 30))), h("div", { class: "meta" }, fmt.date(e.changed_at)))));
  slider.addEventListener("input", () => { sel = Number(slider.value); render(); });
  render();
  return h("div", { class: "stack" },
    card(`${entity} ${pk}`, h("div", { class: "stack" }, h("div", { class: "row" }, h("span", { class: "small muted" }, "Earliest"), h("div", { style: "flex:1" }, slider), h("span", { class: "small muted" }, "Latest")), label), { sub: "Drag to step through every version" }),
    h("div", { class: "grid g21" }, card("State at the selected version", stateBox), card("Changes", timeline)),
    pointInTime(entity, pk));
}

function pointInTime(entity, pk) {
  const t1 = input({ type: "datetime-local", step: "1", value: toLocalInput(new Date(Date.now() - 3600_000)) }), t2 = input({ type: "datetime-local", step: "1", value: toLocalInput() });
  const out = h("div");
  const run = (kind) => async () => {
    out.replaceChildren(loading(2));
    try {
      const a = new Date(t1.value).toISOString(), b = new Date(t2.value).toISOString();
      if (kind === "asof") {
        const r = await get(`/provenance/${entity}/${encodeURIComponent(pk)}/as-of`, { at: a });
        out.replaceChildren(h("div", { class: "stack" }, h("div", { class: `alert ${r.existed ? "info" : "warn"}` }, icon("clock"), r.existed ? `Rebuilt as of ${fmt.date(a)} from record #${r.based_on.chain_seq}.` : `Nothing existed at ${fmt.date(a)}.`),
          r.state && jsonBlock(r.state), r.items && h("div", null, h("h3", null, "Order lines then"), jsonBlock(r.items)), r.payments?.length ? h("div", null, h("h3", null, "Payments then"), jsonBlock(r.payments)) : null));
      } else {
        const r = await get(`/provenance/${entity}/${encodeURIComponent(pk)}/compare`, { t1: a, t2: b });
        out.replaceChildren(h("div", { class: "stack" }, diffView(r.changes), r.item_changes?.length ? h("div", null, h("h3", { style: "margin-bottom:8px" }, "Line changes"),
          r.item_changes.map((c) => h("div", { class: "small" }, badge(c.change, c.change === "added" ? "ok" : c.change === "removed" ? "bad" : "info"), ` product ${c.product_id}`, diffView(c.fields)))) : null,
        h("div", { class: "small muted" }, `${r.events_between.length} change(s) between the two moments.`)));
      }
    } catch (e) { out.replaceChildren(errorBox(e)); }
  };
  return card("Ask the server: what did it look like at…", h("div", { class: "stack" }, h("div", { class: "row" },
    field("From / at", t1), field("To", t2), h("button", { class: "btn", onclick: run("asof") }, "Rebuild at first moment"), h("button", { class: "btn", onclick: run("compare") }, icon("diff", 16), "Compare the two")), out),
  { sub: "Times are in your local time zone" });
}

function requestTab(initial) {
  const id = input({ placeholder: "Request id (the X-Request-ID response header)", value: initial || "", "aria-label": "Request id" });
  const out = h("div");
  const go = async () => {
    if (!id.value.trim()) return;
    out.replaceChildren(h("div", { class: "card" }, loading(3)));
    try {
      const r = await get(`/provenance/requests/${encodeURIComponent(id.value.trim())}`);
      out.replaceChildren(h("div", { class: "stack" },
        h("div", { class: "grid g3" }, h("div", { class: "card stat" }, h("div", { class: "label" }, "Actor"), h("div", { class: "value", style: "font-size:16px" }, r.actor)),
          h("div", { class: "card stat" }, h("div", { class: "label" }, "Changes caused"), h("div", { class: "value" }, r.change_count)), h("div", { class: "card stat" }, h("div", { class: "label" }, "Events emitted"), h("div", { class: "value" }, r.events.length))),
        card("Everything this request changed, in order", table([{ label: "#", render: (c) => c.chain_seq }, { label: "Change", render: (c) => h("span", null, badge(c.operation), " ", `${c.entity} ${c.record_pk}`) },
          { label: "Diff", render: (c) => diffView(c.changes) }], r.changes, { onRow: (c) => navigate(`/explorer/${c.entity}/${encodeURIComponent(c.record_pk)}`) }), { flush: true,
          sub: "Includes changes made by database triggers, such as recalculated totals" })));
    } catch (e) { out.replaceChildren(e instanceof ApiError && e.status === 404 ? h("div", { class: "card" }, empty("No such request", "Only requests that changed data are recorded.", null, "search")) : errorBox(e)); }
  };
  id.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  if (initial) go();
  return h("div", { class: "stack" }, h("div", { class: "card" }, h("div", { class: "filters" }, grow(field("Request", id)), h("button", { class: "btn primary", onclick: go }, icon("search", 16), "Trace"))), out);
}

async function externalTab() {
  const sources = (await get("/sources")).items;
  if (!sources.length) return h("div", { class: "card" }, empty("No external sources yet", "Register a source on the Integrations page, then send events to see their records here.", h("a", { class: "btn primary", href: "#/integrations/sources" }, "Set up a source"), "plug"));
  const src = select(sources.map((s) => [s.source_id, `${s.name} (${s.code})`]), sources[0].source_id, {}), ent = select([], "", {}), q = input({ placeholder: "Filter by id", type: "search" });
  const at = input({ type: "datetime-local", step: "1", value: toLocalInput() });
  const out = h("div");
  const loadEntities = async () => {
    const e = (await get(`/sources/${src.value}/entities`)).items;
    ent.replaceChildren(...e.map((x) => h("option", { value: x.entity }, `${x.entity} (${x.records})`)));
    await list();
  };
  const list = async () => {
    if (!ent.value) return out.replaceChildren(h("div", { class: "card" }, empty("No records yet", "Events with a subject like order/123 become records.", null, "box")));
    out.replaceChildren(h("div", { class: "card" }, loading(4)));
    try {
      const r = await get(`/sources/${src.value}/records/${ent.value}`, { at: new Date(at.value).toISOString(), search: q.value, limit: 100 });
      out.replaceChildren(card(`${r.items.length} record(s) as of ${fmt.date(at.value)}`, table([
        { label: "Record", render: (x) => h("strong", null, x.external_id) }, { label: "State", render: (x) => x.deleted ? badge("deleted", "bad") : h("code", null, fmt.short(JSON.stringify(x.state), 70)) },
        { label: "Versions", right: true, key: "event_count" }, { label: "Last change", render: (x) => fmt.ago(x.last_change) }], r.items, { onRow: (x) => recordModal(src.value, ent.value, x.external_id, r) }),
      { flush: true, sub: `Trust ${r.trust_level} · captured by ${r.capture_method}. Change the time to see the past.` }));
    } catch (e) { out.replaceChildren(errorBox(e)); }
  };
  src.addEventListener("change", loadEntities); ent.addEventListener("change", list); q.addEventListener("input", () => { clearTimeout(q.t); q.t = setTimeout(list, 250); }); at.addEventListener("change", list);
  loadEntities();
  return h("div", { class: "stack" }, h("div", { class: "card" }, h("div", { class: "filters" }, field("Source", src), field("Entity", ent), field("Filter", q), field("As of", at))), out);
}

async function recordModal(sourceId, entity, ext, listing) {
  try {
    const r = await get(`/sources/${sourceId}/records/${entity}/${encodeURIComponent(ext)}/history`);
    modal(`${entity} ${ext}`, h("div", { class: "stack" },
      h("div", { class: "row" }, badge(`trust ${r.trust_level}`, r.trust_level === "HIGH" ? "ok" : r.trust_level === "LOW" ? "warn" : "info"), badge(r.capture_method, "plain"), r.exists ? badge("exists", "ok") : badge("deleted", "bad")),
      h("ol", { class: "timeline" }, r.versions.slice().reverse().map((v) => h("li", { class: v.deleted ? "DELETE" : v.op === "c" ? "INSERT" : "UPDATE" }, h("span", { class: "dot" }),
        h("div", null, h("strong", null, v.type), " ", h("span", { class: "muted small" }, `occurred ${fmt.date(v.occurred_at)} · received ${fmt.ago(v.received_at)}`)),
        diffView(v.deleted ? [{ field: "record", old: "existed", new: "deleted" }] : v.changes),
        h("div", { class: "meta" }, "Evidence: audit record ", v.chain_seq ? `#${v.chain_seq} ` : "", hash(v.row_hash, 12)))))), { wide: true, footer: (close) => [h("button", { class: "btn primary", onclick: close }, "Close")] });
  } catch (e) { fail(e); }
}

// ================================================================ audit
export async function audit() {
  return h("div", { class: "stack" }, pageHead("Audit & integrity", "An append-only record of every change, linked by SHA-256 so any edit, deletion or re-ordering is detectable."),
    tabs([["log", "Audit log"], ["integrity", "Integrity & checkpoints"]], "log", (t) => (t === "log" ? auditLog() : integrity())));
}

function auditLog() {
  const f = { entity: "", operation: "", actor: "", since: "", until: "" };
  const rows = [], host = h("div"), more = h("div", { class: "pager" });
  let cursor = null;
  const ents = ["", "customer", "product", "order", "order_item", "payment", "external_event", "change_request", "user", "api_key", "webhook", "source", "settings", "organization"];
  const params = () => ({ entity: f.entity, operation: f.operation, actor: f.actor, since: f.since && new Date(f.since).toISOString(), until: f.until && new Date(f.until).toISOString() });
  const load = async (reset) => {
    if (reset) { rows.length = 0; cursor = null; host.replaceChildren(loading(5)); }
    try {
      const r = await get("/audit", { ...params(), limit: 50, before_seq: cursor });
      rows.push(...r.items); cursor = r.next_before_seq;
      host.replaceChildren(table([{ label: "#", render: (e) => h("span", { class: "mono muted" }, e.chain_seq) }, { label: "When", render: (e) => h("span", { title: fmt.date(e.changed_at) }, fmt.date(e.changed_at)) },
        { label: "Change", render: (e) => h("span", null, badge(e.operation), " ", h("strong", null, e.entity), " ", e.record_pk) }, { label: "Actor", render: (e) => h("span", { class: "small" }, fmt.short(e.actor, 28)) },
        { label: "Fields", render: (e) => h("span", { class: "small muted" }, e.changes.map((c) => c.field).join(", ") || "–") }, { label: "Hash", render: (e) => hash(e.row_hash, 10) }],
      rows, { onRow: (e) => detail(e), empty: empty("No matching records", "Try widening the filters.", null, "list") }));
      more.replaceChildren(h("span", { style: "flex:1" }, `${rows.length} loaded`), cursor && h("button", { class: "btn sm", onclick: () => load(false) }, "Load older"));
    } catch (e) { host.replaceChildren(errorBox(e)); }
  };
  const exp = (format) => async () => {
    const r = await api("GET", "/audit/export", undefined, { params: { ...params(), format }, raw: true });
    if (!r.ok) return fail(new ApiError(r.status, await r.json()));
    const a = h("a", { href: URL.createObjectURL(await r.blob()), download: `audit.${format}` }); document.body.append(a); a.click(); a.remove();
  };
  load(true);
  const inp = (key, type = "text", ph = "") => input({ type, placeholder: ph, oninput: (e) => { f[key] = e.target.value; clearTimeout(f.t); f.t = setTimeout(() => load(true), 300); } });
  return h("div", { class: "card" }, h("div", { class: "filters" },
    field("Entity", select(ents.map((x) => [x, x || "All"]), "", { onchange: (e) => { f.entity = e.target.value; load(true); } })),
    field("Operation", select(["", "INSERT", "UPDATE", "DELETE"].map((x) => [x, x || "All"]), "", { onchange: (e) => { f.operation = e.target.value; load(true); } })),
    field("Actor contains", inp("actor", "text", "email")), field("Since", inp("since", "datetime-local")), field("Until", inp("until", "datetime-local")),
    can("audit:export") && h("div", { class: "row" }, h("button", { class: "btn", onclick: exp("csv") }, icon("download", 15), "CSV"), h("button", { class: "btn", onclick: exp("json") }, icon("download", 15), "JSON"))),
  host, more);
}

function detail(e) {
  modal(`Audit record #${e.chain_seq}`, h("div", { class: "stack" },
    h("div", { class: "row" }, badge(e.operation), h("strong", null, `${e.entity} ${e.record_pk}`), h("a", { href: `#/explorer/${e.entity}/${encodeURIComponent(e.record_pk)}` }, "Open history")),
    diffView(e.changes),
    h("dl", { class: "kv small" }, h("dt", null, "When"), h("dd", null, fmt.date(e.changed_at)), h("dt", null, "Actor"), h("dd", null, e.actor), h("dt", null, "Database role"), h("dd", null, e.db_user),
      h("dt", null, "Request"), h("dd", null, e.request_id || "–"), h("dt", null, "Previous hash"), h("dd", { class: "mono" }, e.prev_hash), h("dt", null, "This hash"), h("dd", { class: "mono" }, e.row_hash))),
  { wide: true, footer: (c) => [h("button", { class: "btn primary", onclick: c }, "Close")] });
}

async function integrity() {
  const cps = await get("/audit/checkpoints", { limit: 50 });
  const out = h("div"), ext = h("textarea", { placeholder: '[{"chain_seq": 120, "row_hash": "…", "created_at": "…", "signature": "…"}]', "aria-label": "External checkpoints JSON" });
  const run = async (btn) => {
    btn.disabled = true; out.replaceChildren(loading(1));
    try {
      let checkpoints = [];
      if (ext.value.trim()) { try { checkpoints = JSON.parse(ext.value); } catch { throw new ApiError(422, { detail: "The external checkpoints are not valid JSON." }); } }
      out.replaceChildren(verifyResult(await post("/audit/verify", { checkpoints })));
    } catch (e) { out.replaceChildren(errorBox(e)); }
    btn.disabled = false;
  };
  const vb = h("button", { class: "btn primary", onclick: () => run(vb) }, icon("shield", 16), "Verify now");
  return h("div", { class: "stack" },
    h("div", { class: "grid g2" },
      card("Verify the chain", h("div", { class: "stack" }, h("p", { class: "muted" }, "Recomputes every SHA-256 link from the first record and checks each signed checkpoint. Paste checkpoints you saved elsewhere to catch a wholesale rewrite of history."),
        h("div", { class: "field" }, h("label", null, "Checkpoints kept outside this system (optional)"), ext), can("audit:verify") && vb, out)),
      card("What this does and does not prove", h("div", { class: "stack small" },
        h("p", null, h("strong", null, "Proves: "), "no record was edited, removed or re-ordered since it was written, unless the attacker also holds the signing key."),
        h("p", null, h("strong", null, "Does not prove: "), "that the original data was true, or that nothing happened before capture. A database superuser could rewrite the whole chain; signed checkpoints you keep outside this system are what expose that."),
        h("p", { class: "muted" }, "Keep a copy: subscribe a webhook to ", h("code", null, "audit.checkpoint"), "."),
        cps.signing_key && h("div", null, h("div", { class: "lbl" }, "Checkpoint signing key (Ed25519, public)"), h("span", { class: "hash", style: "word-break:break-all" }, cps.signing_key.public_key)))),
    ),
    card("Signed checkpoints", cps.items.length ? table([{ label: "Record", render: (c) => `#${c.chain_seq}` }, { label: "Hash", render: (c) => hash(c.row_hash, 16) }, { label: "Signed", render: (c) => fmt.date(c.created_at) },
      { label: "Key", render: (c) => h("span", { class: "mono small" }, c.key_id) }, { label: "", right: true, render: (c) => h("button", { class: "btn sm", onclick: () => copy(JSON.stringify({ chain_seq: c.chain_seq, row_hash: c.row_hash, created_at: c.created_at, signature: c.signature }), "Checkpoint copied") }, icon("copy", 14), "Copy") }], cps.items)
      : empty("No checkpoints yet", "The worker signs one every few minutes when the chain is intact.", can("audit:verify") && h("button", { class: "btn primary", onclick: async () => { try { const r = await post("/audit/checkpoints"); toast(r.ok === false ? `Refused: ${r.reason}` : "Checkpoint created", r.ok === false ? "bad" : "ok"); navigate("/audit"); } catch (e) { fail(e); } } }, "Create one now"), "shield"),
    { flush: true, actions: can("audit:verify") && cps.items.length > 0 && h("button", { class: "btn sm", onclick: async () => { try { const r = await post("/audit/checkpoints"); toast(r.message || "Checkpoint created", "ok"); } catch (e) { fail(e); } } }, "Create checkpoint") }));
}
