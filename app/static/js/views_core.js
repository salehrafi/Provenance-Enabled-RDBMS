// Dashboard, orders (with explain + lineage), customers, products.
import { h, svg, icon, get, post, patch, del, api, state, can, fmt, badge, hash, card, pageHead, stat, table, empty, field, input,
  select, formDialog, confirmDialog, toast, fail, tabs, loading, errorBox, diffView, pager, debounce, navigate, rerender, ApiError } from "./lib.js";

// ================================================================ dashboard
export async function dashboard() {
  const d = await get("/dashboard");
  state.currency = d.currency;
  const c = d.counts, cur = d.currency;
  const fresh = c.orders === 0 && c.external_events === 0;
  const verifyOut = h("div");
  const verifyBtn = h("button", { class: "btn", onclick: async () => {
    verifyBtn.disabled = true; verifyOut.replaceChildren(loading(1));
    try { verifyOut.replaceChildren(verifyResult(await post("/audit/verify"))); } catch (e) { verifyOut.replaceChildren(errorBox(e)); }
    verifyBtn.disabled = false;
  } }, icon("shield", 16), "Verify now");

  const days = d.revenue_by_day;
  const max = Math.max(1, ...days.map((x) => Number(x.amount)));
  const chart = days.length ? h("div", null,
    h("div", { class: "bars", role: "img", "aria-label": `Revenue for the last ${days.length} days` }, days.map((x) =>
      h("div", { class: "bar", style: `height:${Math.max(3, (Number(x.amount) / max) * 100)}%`, title: `${x.day}: ${fmt.money(x.amount, cur)} (${x.orders} orders)` }))),
    h("div", { class: "bar-labels" }, days.map((x) => h("span", null, x.day.slice(8))))) : empty("No revenue yet", "Paid orders appear here.", null, "cart");

  return h("div", { class: "stack" },
    pageHead("Dashboard", `${state.me.tenant.name}: what changed, what needs attention, and whether the record can be trusted.`),
    fresh && onboarding(c),
    h("div", { class: "grid g4" },
      stat("Revenue", fmt.money(c.revenue, cur), `${fmt.money(c.refunded, cur)} refunded`, "cart"),
      stat("Orders", fmt.n(c.orders), `${fmt.n(c.customers)} customers · ${fmt.n(c.active_products)} products`, "box"),
      h("a", { href: "#/alerts", style: "color:inherit;text-decoration:none" }, stat("Open alerts", fmt.n(c.open_alerts), c.open_alerts ? "Needs review" : "All clear", "bell")),
      h("a", { href: "#/approvals", style: "color:inherit;text-decoration:none" }, stat("Pending approvals", fmt.n(c.pending_approvals), "Four-eyes queue", "check"))),
    h("div", { class: "grid g21" },
      card("Revenue, last 14 days", chart),
      card("Audit integrity", h("div", { class: "stack" },
        h("dl", { class: "kv" }, h("dt", null, "Records in chain"), h("dd", { class: "num" }, fmt.n(c.audit_records)),
          h("dt", null, "Latest checkpoint"), h("dd", null, d.latest_checkpoint ? `#${d.latest_checkpoint.chain_seq} · ${fmt.ago(d.latest_checkpoint.created_at)}` : "None yet"),
          h("dt", null, "External sources"), h("dd", null, `${c.sources} active · ${fmt.n(c.external_events)} events`)),
        verifyOut, can("audit:verify") && verifyBtn))),
    h("div", { class: "grid g2" },
      card("Orders by status", d.orders_by_status.length ? table([{ label: "Status", render: (r) => badge(r.status) }, { label: "Orders", right: true, key: "n" },
        { label: "Value", right: true, render: (r) => fmt.money(r.amount, cur) }], d.orders_by_status) : empty("No orders", null, null, "cart"), { flush: true }),
      card("Recent activity", d.recent_activity.length ? table([
        { label: "When", render: (r) => h("span", { title: fmt.date(r.changed_at) }, fmt.ago(r.changed_at)) },
        { label: "Change", render: (r) => h("span", null, badge(r.operation), " ", `${r.entity} ${r.record_pk}`) },
        { label: "By", render: (r) => h("span", { class: "small" }, fmt.short(r.actor, 24)) }],
      d.recent_activity, { onRow: (r) => navigate(`/explorer/${r.entity}/${encodeURIComponent(r.record_pk)}`) }) : empty("Nothing yet", "Changes appear as they happen.", null, "clock"), { flush: true })));
}

function onboarding(c) {
  const steps = [
    ["Create your organization", "You are signed in as its first admin.", true, null],
    ["Register a data source", "Tell us which system sends events and how much to trust it.", c.sources > 0, "/integrations/sources"],
    ["Send your first event", "Create an API key and POST a CloudEvent. We show you the exact command.", c.external_events > 0, "/integrations/keys"],
    ["Explore provenance", "Open an order and choose Explain, or rebuild a record at a past time.", c.orders > 0, "/explorer"],
    ["Verify integrity", "Check the hash chain and keep a signed checkpoint outside this system.", false, "/audit"],
  ];
  return card("Get started", h("div", { class: "stack" },
    h("div", { class: "steps-list" }, steps.map(([t, s, done, link], i) => h("div", { class: `onb ${done ? "done" : ""}` },
      h("div", { class: "n" }, done ? icon("check", 14) : i + 1),
      h("div", null, h("strong", null, link ? h("a", { href: "#" + link }, t) : t), h("div", { class: "small muted" }, s))))),
    can("settings:manage") && h("div", { class: "row" },
      h("button", { class: "btn primary", onclick: async (e) => {
        e.target.disabled = true;
        try { const r = await post("/sandbox/sample-data"); toast(r.message, "ok"); rerender(); } catch (x) { fail(x); e.target.disabled = false; }
      } }, "Load sample data"), h("span", { class: "small muted" }, "Adds clearly labelled [sample] records so you can explore right away."))));
}

export function verifyResult(v) {
  const cp = v.checkpoints || {};
  return h("div", { class: `alert ${v.ok ? "ok" : "bad"}`, role: "status" }, icon(v.ok ? "shield" : "alert"), h("div", null,
    h("strong", null, v.ok ? "Chain intact. " : "Tampering detected. "),
    v.ok ? `${fmt.n(v.checked)} records verified${cp.checked ? `, ${cp.checked} signed checkpoint(s) match` : ""}.`
      : `Record ${v.first_bad_seq}: ${v.reason}`));
}

// ================================================================ orders
const STATUSES = ["", "CREATED", "PAID", "SHIPPED", "DELIVERED", "CANCELLED", "REFUNDED"];

export async function orders(_p, q) {
  const f = { status: q.status || "", offset: Number(q.offset || 0) };
  const limit = 25;
  const host = h("div");
  const load = async () => {
    host.replaceChildren(loading(5));
    try {
      const r = await get("/orders", { status: f.status, limit, offset: f.offset });
      const cur = state.currency;
      host.replaceChildren(table([
        { label: "Order", render: (o) => h("strong", null, `#${o.order_id}`) }, { label: "Customer", key: "customer_name" },
        { label: "Status", render: (o) => badge(o.status) }, { label: "Items", right: true, key: "item_count" },
        { label: "Total", right: true, render: (o) => fmt.money(o.total_amount, o.currency || cur) },
        { label: "Paid", right: true, render: (o) => fmt.money(o.paid_amount, o.currency || cur) },
        { label: "Created", render: (o) => h("span", { title: fmt.date(o.created_at) }, fmt.ago(o.created_at)) }],
      r.items, { onRow: (o) => navigate(`/orders/${o.order_id}`), caption: "Orders",
        empty: empty("No orders yet", f.status ? "No orders with this status." : "Create one, or load sample data from the dashboard.", can("orders:write") ? newOrderButton() : null, "cart") }),
      r.total > limit && pager(f, r.total, limit, (o) => { f.offset = o; load(); }));
    } catch (e) { host.replaceChildren(errorBox(e)); }
  };
  load();
  return h("div", { class: "stack" },
    pageHead("Orders", "Totals are maintained by the database. Open an order to see exactly how its total was built.", can("orders:write") && newOrderButton()),
    h("div", { class: "card" }, h("div", { class: "filters" },
      field("Status", select(STATUSES.map((s) => [s, s || "All"]), f.status, { onchange: (e) => { f.status = e.target.value; f.offset = 0; load(); } }))), host));
}

function newOrderButton() { return h("button", { class: "btn primary", onclick: newOrderDialog }, icon("plus", 16), "New order"); }

async function newOrderDialog() {
  const [cs, ps] = await Promise.all([get("/customers", { limit: 200 }), get("/products", { limit: 200, active: true })]).catch((e) => { fail(e); return []; });
  if (!cs) return;
  if (!cs.items.length || !ps.items.length) return toast("Add at least one customer and one product first.", "bad");
  const cust = select(cs.items.map((c) => [c.customer_id, c.name]), cs.items[0].customer_id, {});
  const lines = h("div", { class: "stack" });
  const addLine = () => {
    const p = select(ps.items.map((x) => [x.product_id, `${x.name} · ${fmt.money(x.price)}`]), ps.items[0].product_id, { "aria-label": "Product" });
    const q = input({ type: "number", min: "0.01", step: "0.01", value: "1", "aria-label": "Quantity", style: "max-width:100px" });
    const row = h("div", { class: "row" }, h("div", { style: "flex:1" }, p), q, h("button", { type: "button", class: "btn sm ghost", "aria-label": "Remove line", onclick: () => row.remove() }, icon("x", 14)));
    row.get = () => ({ product_id: Number(p.value), quantity: q.value });
    lines.append(row);
  };
  addLine();
  formDialog("New order", [field("Customer", cust), h("div", null, h("div", { class: "lbl" }, "Items"), lines),
    h("button", { type: "button", class: "btn sm", onclick: addLine }, icon("plus", 14), "Add item")], "Create order", async (close) => {
    const items = [...lines.children].map((r) => r.get());
    const o = await api("POST", "/orders", { customer_id: Number(cust.value), items }, { idempotent: true });
    close(); navigate(`/orders/${o.order_id}`);
  }, { wide: true });
}

export async function orderDetail({ id }) {
  const o = await get(`/orders/${id}`);
  const cur = o.currency;
  return h("div", { class: "stack" },
    h("p", { class: "small" }, h("a", { href: "#/orders" }, "← Orders")),
    pageHead(`Order #${o.order_id}`, `${o.customer_name} · created ${fmt.ago(o.created_at)}`, [badge(o.status)]),
    h("div", { class: "grid g4" }, stat("Total", fmt.money(o.total_amount, cur)), stat("Paid", fmt.money(o.paid_amount, cur)),
      stat("Balance due", fmt.money(o.balance_due, cur)), stat("Items", fmt.n(o.item_count))),
    tabs([["overview", "Overview"], ["explain", "Explain total"], ["lineage", "Lineage"], ["history", "History"]], "overview", async (t) => {
      if (t === "overview") return orderOverview(o);
      if (t === "explain") return explain(o.order_id);
      if (t === "lineage") return lineage(o.order_id);
      return orderHistory(o.order_id);
    }));
}

function orderOverview(o) {
  const cur = o.currency, canWrite = can("orders:write");
  const editable = canWrite && o.status === "CREATED";
  const act = (fn) => async () => { try { await fn(); rerender(); } catch (e) { fail(e); } };
  return h("div", { class: "grid g21" },
    h("div", { class: "stack" },
      card("Items", table([
        { label: "Product", render: (i) => h("span", null, h("strong", null, i.name), " ", h("span", { class: "muted small" }, i.sku)) },
        { label: "Qty", right: true, render: (i) => fmt.n(i.quantity) }, { label: "Unit price", right: true, render: (i) => fmt.money(i.unit_price, cur) },
        { label: "Line total", right: true, render: (i) => fmt.money(i.line_total, cur) },
        editable && { label: "", right: true, render: (i) => h("button", { class: "btn sm ghost", "aria-label": `Remove ${i.name}`, onclick: act(() => del(`/orders/${o.order_id}/items/${i.product_id}`)) }, icon("x", 14)) }].filter(Boolean),
      o.items, { empty: empty("No items", "Add an item to give the order a total.", null, "box") }), { flush: true,
        actions: editable && h("button", { class: "btn sm", onclick: () => addItemDialog(o) }, icon("plus", 14), "Add item") }),
      card("Payments", table([{ label: "Method", key: "method" }, { label: "Status", render: (p) => badge(p.status) },
        { label: "Amount", right: true, render: (p) => fmt.money(p.amount, cur) }, { label: "When", render: (p) => fmt.ago(p.created_at) }],
      o.payments, { empty: empty("No payments", null, null, "cart") }), { flush: true,
        actions: canWrite && o.status === "CREATED" && o.total_amount > 0 && h("button", { class: "btn sm primary", onclick: () => paymentDialog(o) }, icon("plus", 14), "Add payment") })),
    card("Lifecycle", h("div", { class: "stack" },
      h("p", { class: "small muted" }, "The database allows only these moves from the current status. Anything else is refused, whichever client you use."),
      o.allowed_transitions.length ? h("div", { class: "row" }, o.allowed_transitions.map((s) =>
        h("button", { class: `btn ${s === "CANCELLED" || s === "REFUNDED" ? "danger" : ""}`, disabled: !canWrite || (s === "PAID"), title: s === "PAID" ? "Record a payment to mark the order paid" : null,
          onclick: async () => { if (await confirmDialog(`Mark order ${s.toLowerCase()}?`, `This changes the order from ${o.status} to ${s} and is recorded in the audit log.`, `Mark ${s.toLowerCase()}`, s === "CANCELLED" || s === "REFUNDED")) act(() => post(`/orders/${o.order_id}/status`, { status: s }))(); } }, `→ ${s}`)))
        : h("div", { class: "muted" }, "This order is in a final state."))));
}

async function addItemDialog(o) {
  const ps = await get("/products", { limit: 200, active: true });
  const p = select(ps.items.map((x) => [x.product_id, `${x.name} · ${fmt.money(x.price)}`]), ps.items[0]?.product_id, {});
  const q = input({ type: "number", min: "0.01", step: "0.01", value: "1", required: true });
  const u = input({ type: "number", min: "0", step: "0.01", placeholder: "List price" });
  formDialog("Add item", [field("Product", p), field("Quantity", q), field("Unit price override", u, "Leave empty to use the list price at this moment.")], "Add", async (close) => {
    await post(`/orders/${o.order_id}/items`, { product_id: Number(p.value), quantity: q.value, ...(u.value ? { unit_price: u.value } : {}) });
    close(); rerender();
  });
}

function paymentDialog(o) {
  const a = input({ type: "number", min: "0.01", step: "0.01", required: true, value: o.balance_due });
  const m = select(["CARD", "CASH", "BANK", "BKASH", "NAGAD"], "CARD", {});
  const r = input({ maxlength: "80", placeholder: "Optional" });
  formDialog("Record payment", [field("Amount", a, `Balance due: ${fmt.money(o.balance_due, o.currency)}`), field("Method", m), field("Reference", r)], "Record payment", async (close) => {
    await api("POST", `/orders/${o.order_id}/payments`, { amount: a.value, method: m.value, reference: r.value || null }, { idempotent: true });
    close(); rerender();
  });
}

// ---------------------------------------------------------------- explain
async function explain(orderId) {
  const x = await get(`/provenance/orders/${orderId}/explain`);
  const cur = x.order.currency, k = x.checks;
  const ok = (v, t) => h("div", { class: "check" }, icon(v ? "check" : "alert", 16), h("span", { class: v ? "" : "muted" }, t));
  return h("div", { class: "stack" },
    h("div", { class: `alert ${k.replay_matches_total && k.total_matches_lines ? "ok" : "bad"}` }, icon("shield"), h("div", null, x.summary)),
    h("div", { class: "grid g2" },
      card("Line by line", table([
        { label: "Item", render: (l) => h("span", null, h("strong", null, l.name))},
        { label: "Qty × price", render: (l) => `${fmt.n(l.quantity)} × ${fmt.money(l.unit_price, cur)}` },
        { label: "Price check", render: (l) => l.price_note ? h("span", { class: `small ${l.discount_pct > 0 ? "" : "muted"}` }, badge(l.discount_pct > 0 ? `${Math.abs(l.discount_pct)}% below list` : l.discount_pct < 0 ? "above list" : "list price", l.discount_pct >= 20 ? "warn" : "ok")) : "–" },
        { label: "Total", right: true, render: (l) => fmt.money(l.line_total, cur) }], x.lines), { flush: true, sub: "Compared with the catalogue price at the moment each item was added" }),
      card("Reconciliation of the total", h("div", { class: "stack" },
        ok(k.total_matches_lines, `Sum of lines is ${fmt.money(k.sum_of_lines, cur)}; order total is ${fmt.money(k.recorded_total, cur)}`),
        ok(k.replay_matches_total, `Replaying ${x.steps.length} recorded change(s) from the audit log gives ${fmt.money(k.replayed_total_from_audit, cur)}`),
        h("div", { class: "small muted" }, `Captured payments ${fmt.money(k.captured_payments, cur)} · balance ${fmt.money(k.balance_due, cur)}`)))),
    card("How the total was built", x.steps.length ? h("div", null, x.steps.map((s) => h("div", { class: "step" },
      h("div", null, h("strong", null, s.description), h("div", { class: "small muted" }, `${s.actor} · ${fmt.date(s.changed_at)} · record `, hash(s.row_hash, 8))),
      h("div", { class: `num delta ${Number(s.delta) >= 0 ? "pos" : "neg"}` }, `${Number(s.delta) >= 0 ? "+" : "−"}${fmt.money(Math.abs(s.delta), cur)}`),
      h("div", { class: "num", title: "Running total" }, fmt.money(s.running_total, cur))))) : empty("No item changes yet", null, null, "list"), { flush: true }));
}

// ---------------------------------------------------------------- lineage graph
const COLS = { customer: 0, product: 0, change_request: 0, order_item: 1, order: 2, payment: 3, alert: 3 };
const COL_NAMES = ["Origins", "Lines", "Order", "Consequences"];

async function lineage(orderId) {
  const g = await get(`/provenance/orders/${orderId}/lineage`);
  const W = 188, H = 46, GX = 92, GY = 18, PAD = 20;
  const cols = [[], [], [], []];
  for (const n of g.nodes) cols[COLS[n.type] ?? 1].push(n);
  const tallest = Math.max(...cols.map((c) => c.length), 1);
  const totalH = tallest * (H + GY) + PAD * 2 + 20;
  const pos = {};
  cols.forEach((col, ci) => {
    const offset = (totalH - 20 - col.length * (H + GY) + GY) / 2 + 20;
    col.forEach((n, i) => { pos[n.id] = { x: PAD + ci * (W + GX), y: offset + i * (H + GY), n }; });
  });
  const used = Math.max(...cols.map((c, i) => (c.length ? i : 0)));
  const width = PAD * 2 + (used + 1) * W + used * GX;
  const root = svg("svg", { class: "graph", viewBox: `0 0 ${width} ${totalH}`, role: "group", "aria-label": `Lineage graph of order ${orderId}` },
    svg("defs", null, svg("marker", { id: "arr", viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" },
      svg("path", { d: "M0 0L10 5L0 10z", fill: "currentColor", style: "color:var(--line-strong)" }))));
  COL_NAMES.forEach((name, ci) => { if (cols[ci].length) root.append(svg("text", { class: "col-label", x: PAD + ci * (W + GX), y: 14 }, name)); });
  for (const e of g.edges) {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) continue;
    const forward = a.x <= b.x;
    const x1 = forward ? a.x + W : a.x, x2 = forward ? b.x : b.x + W, y1 = a.y + H / 2, y2 = b.y + H / 2, mx = (x1 + x2) / 2;
    root.append(svg("path", { class: "edge", d: `M${x1} ${y1} C${mx} ${y1} ${mx} ${y2} ${x2} ${y2}`, "marker-end": "url(#arr)" }),
      svg("text", { class: "edge-label", x: mx, y: (y1 + y2) / 2 - 4, "text-anchor": "middle" }, e.label));
  }
  for (const { x, y, n } of Object.values(pos)) {
    const [entity] = n.id.split(":");
    const node = svg("g", { class: `node t-${n.type}`, tabindex: "0", role: "link", "aria-label": `${n.label}. ${n.detail}. Open history.` },
      svg("title", null, `${n.label}\n${n.detail}`),
      svg("rect", { x, y, width: W, height: H }),
      svg("text", { x: x + 10, y: y + 19 }, fmt.short(n.label, 26)), svg("text", { class: "sub", x: x + 10, y: y + 35 }, fmt.short(n.detail, 32)));
    const go = () => navigate(`/explorer/${entity}/${encodeURIComponent(n.record_pk || n.id.split(":").slice(1).join(":"))}`);
    node.addEventListener("click", go);
    node.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
    root.append(node);
  }
  const causal = g.events.filter((e) => e.caused_by);
  const legend = h("div", { class: "legend", "aria-hidden": "true" }, ["order", "customer", "order_item", "product", "payment", "change_request", "alert"].map((t) => h("span", { class: `t-${t}` }, t.replace("_", " "))));
  return h("div", { class: "stack" }, card("What shaped this order", h("div", { class: "stack" }, h("div", { class: "graph-wrap" }, root), legend,
    h("div", { class: "small muted" }, "Select any box to open that record's full history. On small screens, scroll the graph sideways."))),
  card("Cause and effect", causal.length ? table([{ label: "Effect", render: (e) => h("span", null, badge(e.operation), " ", `${e.entity} ${e.record_pk}`) },
    { label: "Because", render: (e) => e.explanation }, { label: "Caused by change", render: (e) => hash(String(e.caused_by), 8) },
    { label: "Request", render: (e) => hash(e.request_id, 8) }], causal, { onRow: (e) => navigate(`/explorer?request=${e.request_id}`) })
    : empty("No derived changes", "Derived changes (such as totals recalculated by the database) appear here, linked to their cause.", null, "graph"), { flush: true }));
}

async function orderHistory(orderId) {
  const r = await get(`/provenance/order/${orderId}/history`);
  return card("Order record history", r.history.length ? h("ol", { class: "timeline" }, r.history.slice().reverse().map((e) => h("li", { class: e.operation },
    h("span", { class: "dot" }), h("div", null, badge(e.operation), " ", h("strong", null, e.actor)), h("div", { class: "meta" }, `${fmt.date(e.changed_at)} · #${e.chain_seq}`), diffView(e.changes)))) : empty("No history"),
  { actions: h("a", { class: "btn sm", href: `#/explorer/order/${orderId}` }, icon("clock", 14), "Open in time-travel explorer") });
}

// ================================================================ customers
export async function customers(_p, q) {
  const f = { search: q.search || "", offset: 0 };
  const limit = 25, host = h("div");
  const load = async () => {
    host.replaceChildren(loading(5));
    try {
      const r = await get("/customers", { search: f.search, limit, offset: f.offset });
      host.replaceChildren(table([
        { label: "Customer", render: (c) => h("strong", null, c.name) }, { label: "Email", key: "email" }, { label: "Phone", render: (c) => c.phone || "–" },
        { label: "Orders", right: true, key: "order_count" }, { label: "Lifetime value", right: true, render: (c) => fmt.money(c.lifetime_value) },
        { label: "", right: true, render: (c) => h("span", { class: "row end" }, can("catalog:write") && h("button", { class: "btn sm", onclick: () => customerDialog(c) }, "Edit"),
          h("a", { class: "btn sm ghost", href: `#/explorer/customer/${c.customer_id}`, "aria-label": `History of ${c.name}` }, icon("clock", 14))) }],
      r.items, { empty: empty("No customers", f.search ? "No match for this search." : "Add your first customer.", can("catalog:write") && h("button", { class: "btn primary", onclick: () => customerDialog() }, "Add customer"), "users") }),
      r.total > limit && pager(f, r.total, limit, (o) => { f.offset = o; load(); }));
    } catch (e) { host.replaceChildren(errorBox(e)); }
  };
  load();
  return h("div", { class: "stack" }, pageHead("Customers", null, can("catalog:write") && h("button", { class: "btn primary", onclick: () => customerDialog() }, icon("plus", 16), "New customer")),
    h("div", { class: "card" }, h("div", { class: "filters" }, field("Search", input({ type: "search", placeholder: "Name or email", value: f.search, oninput: debounce((e) => { f.search = e.target.value; f.offset = 0; load(); }) }))), host));
}

function customerDialog(c) {
  const name = input({ required: true, maxlength: "120", value: c?.name || "" }), email = input({ type: "email", required: true, value: c?.email || "" }), phone = input({ maxlength: "30", value: c?.phone || "" });
  formDialog(c ? "Edit customer" : "New customer", [field("Name", name), field("Email", email), field("Phone", phone)], c ? "Save" : "Create", async (close) => {
    const body = { name: name.value, email: email.value, phone: phone.value || null };
    if (c) await patch(`/customers/${c.customer_id}`, body); else await api("POST", "/customers", body, { idempotent: true });
    close(); toast("Saved", "ok"); rerender();
  });
}

// ================================================================ products
export async function products(_p, q) {
  const f = { search: q.search || "", offset: 0 };
  const limit = 25, host = h("div");
  const load = async () => {
    host.replaceChildren(loading(5));
    try {
      const r = await get("/products", { search: f.search, limit, offset: f.offset });
      host.replaceChildren(table([
        { label: "Product", render: (p) => h("span", null, h("strong", null, p.name), " ", h("span", { class: "muted small" }, p.sku)) },
        { label: "Price", right: true, render: (p) => fmt.money(p.price) },
        { label: "Status", render: (p) => h("span", { class: "row" }, badge(p.active ? "ACTIVE" : "PAUSED", p.active ? "ok" : "plain"), p.pending_changes > 0 && badge("price change pending", "warn")) },
        { label: "", right: true, render: (p) => h("span", { class: "row end" }, can("catalog:write") && h("button", { class: "btn sm", onclick: () => productDialog(p) }, "Edit"),
          h("a", { class: "btn sm ghost", href: `#/explorer/product/${p.product_id}`, "aria-label": `History of ${p.name}` }, icon("clock", 14))) }],
      r.items, { empty: empty("No products", "Add a product to start taking orders.", can("catalog:write") && h("button", { class: "btn primary", onclick: () => productDialog() }, "Add product"), "tag") }),
      r.total > limit && pager(f, r.total, limit, (o) => { f.offset = o; load(); }));
    } catch (e) { host.replaceChildren(errorBox(e)); }
  };
  load();
  return h("div", { class: "stack" }, pageHead("Products", "Large price changes need a second admin to approve them.", can("catalog:write") && h("button", { class: "btn primary", onclick: () => productDialog() }, icon("plus", 16), "New product")),
    h("div", { class: "card" }, h("div", { class: "filters" }, field("Search", input({ type: "search", placeholder: "Name or SKU", value: f.search, oninput: debounce((e) => { f.search = e.target.value; f.offset = 0; load(); }) }))), host));
}

function productDialog(p) {
  const sku = input({ required: true, maxlength: "40", value: p?.sku || "", disabled: !!p }), name = input({ required: true, maxlength: "120", value: p?.name || "" });
  const price = input({ type: "number", min: "0", step: "0.01", required: true, value: p?.price ?? "" }), reason = input({ maxlength: "500", placeholder: "Shown to the approver" });
  const active = input({ type: "checkbox", checked: p ? p.active : true });
  formDialog(p ? "Edit product" : "New product", [!p && field("SKU", sku), field("Name", name), field("Price", price, p ? "A change at or above the organization's threshold is sent for approval instead of being applied." : null),
    p && field("Reason for price change", reason), field("Active", active)].filter(Boolean), p ? "Save" : "Create", async (close) => {
    if (p) {
      const body = { name: name.value, active: active.checked, ...(Number(price.value) !== Number(p.price) ? { price: price.value, reason: reason.value || null } : {}) };
      const r = await api("PATCH", `/products/${p.product_id}`, body);
      toast(r.pending_change_request ? r.pending_change_request.message : "Saved", r.pending_change_request ? "" : "ok");
    } else await api("POST", "/products", { sku: sku.value, name: name.value, price: price.value, active: active.checked }, { idempotent: true });
    close(); rerender();
  });
}
