"use strict";
/* Provenance Cloud web client. No build step, no dependencies, CSP-safe (no inline JS/CSS). */
(() => {
  const API = "/api/v1";
  const RANK = { viewer: 0, staff: 1, admin: 2 };
  let ME = null;
  let CURRENCY = "USD";
  let shellReady = false;

  // ---------------------------------------------------------------- utilities
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const esc = (v) => (v === null || v === undefined ? "" : String(v).replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
  const money = (v, cur = CURRENCY) => (v === null || v === undefined || v === "" ? "" :
    Number(v).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + (cur ? " " + cur : ""));
  const fmtNum = (v) => Number(v || 0).toLocaleString();
  const when = (v) => (v ? new Date(v).toLocaleString() : "");
  const badge = (v, cls) => (v === null || v === undefined ? "" : `<span class="badge ${esc(cls || v)}">${esc(v)}</span>`);
  const can = (role) => ME && RANK[ME.role] >= RANK[role];
  const short = (s, n = 12) => (s ? esc(String(s).slice(0, n)) : "");
  const val = (v) => (v === null || v === undefined ? "∅" : typeof v === "object" ? JSON.stringify(v) : String(v));
  const trunc = (s, n) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };

  const tokens = {
    get access() { return localStorage.getItem("pc_access"); },
    get refresh() { return localStorage.getItem("pc_refresh"); },
    set(t) { localStorage.setItem("pc_access", t.access_token); localStorage.setItem("pc_refresh", t.refresh_token); },
    clear() { localStorage.removeItem("pc_access"); localStorage.removeItem("pc_refresh"); },
  };

  function toast(message, kind = "") {
    const el = document.createElement("div");
    el.className = `toast ${kind}`;
    el.textContent = message;
    $("#toasts").appendChild(el);
    setTimeout(() => el.remove(), kind === "error" ? 7000 : 4000);
  }

  function on(root, event, selector, fn) {
    root.addEventListener(event, (e) => {
      const target = e.target.closest(selector);
      if (target && root.contains(target)) fn(e, target);
    });
  }

  function formData(form) {
    const out = {};
    for (const [k, v] of new FormData(form).entries()) {
      if (typeof v === "string" && v.trim() !== "") out[k] = v.trim();
    }
    return out;
  }

  const localInput = (d) => {
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };
  const toIso = (local) => new Date(local).toISOString();

  // ---------------------------------------------------------------- API client
  let refreshing = null;
  async function refreshTokens() {
    if (!tokens.refresh) return false;
    refreshing = refreshing || fetch(API + "/auth/refresh", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: tokens.refresh }),
    }).then(async (r) => { if (!r.ok) return false; tokens.set(await r.json()); return true; })
      .catch(() => false).finally(() => { setTimeout(() => { refreshing = null; }, 0); });
    return refreshing;
  }

  function errorText(data, fallback) {
    if (!data) return fallback;
    if (typeof data.detail === "string") return data.detail + (data.code ? ` (${data.code})` : "");
    if (Array.isArray(data.detail)) return data.detail.map((e) => `${(e.loc || []).slice(1).join(".")}: ${e.msg}`).join("; ");
    return fallback;
  }

  async function api(method, path, body, opts = {}) {
    const headers = {};
    if (tokens.access) headers.Authorization = "Bearer " + tokens.access;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(API + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    if (res.status === 401 && !opts.retried && !path.startsWith("/auth/login") && !path.startsWith("/auth/signup")) {
      if (await refreshTokens()) return api(method, path, body, { ...opts, retried: true });
      logout();
      throw new Error("Your session expired. Please sign in again.");
    }
    if (opts.raw) {
      if (!res.ok) throw new Error(errorText(await res.json().catch(() => null), res.statusText));
      return res;
    }
    const data = res.status === 204 ? null : await res.json().catch(() => null);
    if (!res.ok) {
      const err = new Error(errorText(data, `${res.status} ${res.statusText}`));
      err.status = res.status;
      throw err;
    }
    return data;
  }

  async function upload(path, form, retried = false) {
    const headers = tokens.access ? { Authorization: "Bearer " + tokens.access } : {};
    const res = await fetch(API + path, { method: "POST", headers, body: form });
    if (res.status === 401 && !retried && await refreshTokens()) return upload(path, form, true);
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new Error(errorText(data, `${res.status} ${res.statusText}`));
    return data;
  }

  async function guarded(fn, okMessage) {
    try {
      const result = await fn();
      if (okMessage) toast(okMessage, "ok");
      return result;
    } catch (err) {
      toast(err.message, "error");
      return undefined;
    }
  }

  function logout() {
    tokens.clear();
    ME = null;
    shellReady = false;
    location.hash = "#/login";
    route();
  }

  // ---------------------------------------------------------------- modal
  function modal(title, html, { wide = false } = {}) {
    const root = $("#modal-root");
    root.innerHTML = `<div class="modal-back"><div class="modal ${wide ? "wide" : ""}">
      <div class="modal-head"><h2>${esc(title)}</h2><button class="x" data-close aria-label="Close">&times;</button></div>
      <div class="modal-body">${html}</div></div></div>`;
    const back = root.firstElementChild;
    back.addEventListener("click", (e) => { if (e.target === back || e.target.closest("[data-close]")) closeModal(); });
    return $(".modal-body", back);
  }
  const closeModal = () => { $("#modal-root").innerHTML = ""; };
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });

  // ---------------------------------------------------------------- shared renderers
  function table(cols, rows, { empty = "Nothing here yet.", rowAttrs } = {}) {
    if (!rows || !rows.length) return `<div class="empty">${esc(empty)}</div>`;
    const head = cols.map((c) => `<th class="${c.cls || ""}">${esc(c.h)}</th>`).join("");
    const body = rows.map((r) => `<tr ${rowAttrs ? rowAttrs(r) : ""}>${cols.map((c) => `<td class="${c.cls || ""}">${c.f(r)}</td>`).join("")}</tr>`).join("");
    return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function header(title, sub = "", actions = "") {
    return `<div class="topbar"><div><h1>${esc(title)}</h1>${sub ? `<div class="sub">${sub}</div>` : ""}</div>
      <div class="actions">${actions}</div></div>`;
  }

  function diffList(changes, operation) {
    if (!changes || !changes.length) return "";
    return `<ul class="diff">${changes.map((c) => operation === "INSERT" || c.old === null
      ? `<li>${esc(c.field)} = <span class="new">${esc(val(c.new))}</span></li>`
      : operation === "DELETE" || c.new === null
        ? `<li>${esc(c.field)}: <span class="old">${esc(val(c.old))}</span></li>`
        : `<li>${esc(c.field)}: <span class="old">${esc(val(c.old))}</span> → <span class="new">${esc(val(c.new))}</span></li>`).join("")}</ul>`;
  }

  function auditTimeline(items, { showEntity = true } = {}) {
    if (!items || !items.length) return `<div class="empty">No recorded changes.</div>`;
    return `<ul class="timeline">${items.map((a) => `<li>
      <div class="what">${badge(a.operation)} ${showEntity ? `<a href="#" data-history="${esc(a.entity)}|${esc(a.record_pk)}">${esc(a.entity)} ${esc(a.record_pk)}</a>` : ""}
        ${a.change_request_id ? badge("approved change #" + a.change_request_id, "ok") : ""}
        ${a.explanation ? `<span class="help">— ${esc(a.explanation)}</span>` : ""}</div>
      <div class="meta">${esc(a.actor)} · ${esc(when(a.changed_at))} · chain #${esc(a.chain_seq)}
        ${a.request_id ? ` · request <a href="#" data-trace="${esc(a.request_id)}" class="mono">${short(a.request_id, 10)}</a>` : ""}
        ${a.db_user && a.db_user !== "PROV_APP" ? ` · ${badge("direct DB: " + a.db_user, "bad")}` : ""}</div>
      ${diffList(a.changes, a.operation)}</li>`).join("")}</ul>`;
  }

  // Global delegated links for provenance popups (work on every page and inside modals).
  document.addEventListener("click", (e) => {
    const h = e.target.closest("[data-history]");
    if (h) { e.preventDefault(); const [ent, pk] = h.dataset.history.split("|"); openHistory(ent, pk); return; }
    const t = e.target.closest("[data-trace]");
    if (t) { e.preventDefault(); openTrace(t.dataset.trace); }
  });

  async function openHistory(entity, pk) {
    const body = modal(`History of ${entity} ${pk}`, `<div class="empty">Loading…</div>`, { wide: true });
    const data = await guarded(() => api("GET", `/provenance/${encodeURIComponent(entity)}/${encodeURIComponent(pk)}/history`));
    if (data) body.innerHTML = `<p class="help">Where-provenance: every recorded version of this record, captured by database triggers.</p>${auditTimeline(data.history, { showEntity: false })}`;
  }

  async function openTrace(requestId) {
    const body = modal("Request trace", `<div class="empty">Loading…</div>`, { wide: true });
    const t = await guarded(() => api("GET", `/provenance/requests/${encodeURIComponent(requestId)}`));
    if (!t) return;
    body.innerHTML = `<p class="help">How-provenance: everything one API call changed, including changes made by triggers in the same transaction.</p>
      <div class="kv"><div class="k">Request ID</div><div class="mono">${esc(t.request_id)}</div>
      <div class="k">Actor</div><div>${esc(t.actor)}</div><div class="k">Started</div><div>${esc(when(t.started_at))}</div>
      <div class="k">Changes</div><div>${esc(t.change_count)} across ${esc(t.entities_touched.join(", "))}</div>
      <div class="k">Events emitted</div><div>${t.events.map((e) => badge(e.event_type, "info")).join(" ") || "none"}</div></div>
      <h3 class="mt">Changes</h3>${auditTimeline(t.changes)}`;
  }

  // ---------------------------------------------------------------- auth screen
  function renderAuth() {
    shellReady = false;
    $("#app").innerHTML = `<div class="auth">
      <div class="auth-hero"><h1>Know why every number<br>is what it is.</h1>
        <p>Provenance Cloud records every change in your commerce data inside Oracle: who made it, when, why, and what it caused. The history is protected by a tamper-evident hash chain.</p>
        <ul><li>Explain any order total step by step</li><li>Time-travel any record to any moment</li>
        <li>Four-eyes approval for risky price changes</li><li>Anomaly alerts and signed webhooks</li></ul></div>
      <div class="auth-form"><div class="card">
        <div class="tabs"><button class="active" data-tab="login">Sign in</button><button data-tab="signup">Create organization</button></div>
        <form id="login-form">
          <div class="field"><label>Email</label><input name="email" type="email" autocomplete="username" required></div>
          <div class="field"><label>Password</label><input name="password" type="password" autocomplete="current-password" required></div>
          <button class="btn primary" type="submit">Sign in</button>
          <p class="help">Demo users are created by <code>scripts/seed.py</code> (password: <code>DEMO_PASSWORD</code> in <code>.env</code>).</p>
        </form>
        <form id="signup-form" class="hidden">
          <div class="field"><label>Organization</label><input name="organization" required minlength="2"></div>
          <div class="field"><label>Your name</label><input name="full_name" required minlength="2"></div>
          <div class="field"><label>Email</label><input name="email" type="email" required></div>
          <div class="field"><label>Password (10+ characters)</label><input name="password" type="password" minlength="10" required autocomplete="new-password"></div>
          <button class="btn primary" type="submit">Create organization</button>
        </form></div></div></div>`;
    const root = $("#app");
    on(root, "click", "[data-tab]", (e, t) => {
      $$("[data-tab]", root).forEach((b) => b.classList.toggle("active", b === t));
      $("#login-form").classList.toggle("hidden", t.dataset.tab !== "login");
      $("#signup-form").classList.toggle("hidden", t.dataset.tab !== "signup");
    });
    const finish = (res) => { tokens.set(res); ME = res.user; location.hash = "#/dashboard"; route(); };
    $("#login-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const res = await guarded(() => api("POST", "/auth/login", formData(e.target)));
      if (res) finish(res);
    });
    $("#signup-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const res = await guarded(() => api("POST", "/auth/signup", formData(e.target)), "Organization created");
      if (res) finish(res);
    });
  }

  // ---------------------------------------------------------------- shell & routing
  const NAV = [
    ["Overview", [["#/dashboard", "Dashboard"]]],
    ["Commerce", [["#/customers", "Customers"], ["#/products", "Products"], ["#/orders", "Orders"]]],
    ["Provenance", [["#/audit", "Audit log"], ["#/time-travel", "Time travel"]]],
    ["Governance", [["#/alerts", "Alerts", "alerts"], ["#/approvals", "Approvals", "approvals"], ["#/webhooks", "Webhooks", null, "admin"], ["#/events", "Event stream", null, "staff"]]],
    ["Organization", [["#/integrations", "Integrations", null, "admin"], ["#/team", "Team", null, "admin"], ["#/settings", "Settings"]]],
  ];

  function renderShell() {
    const nav = NAV.map(([group, links]) => `<div class="nav-group">${esc(group)}</div><nav class="nav">${links
      .filter((l) => !l[3] || can(l[3]))
      .map(([href, label, countKey]) => `<a href="${href}">${esc(label)}${countKey ? `<span class="count hidden" data-count="${countKey}"></span>` : ""}</a>`)
      .join("")}</nav>`).join("");
    $("#app").innerHTML = `<div class="shell"><aside class="side">
      <div class="brand"><div class="brand-mark">◆</div>Provenance Cloud</div>${nav}
      <div class="side-foot"><div class="who">${esc(ME.full_name)}</div><div>${esc(ME.email)}</div>
        <div>${esc(ME.tenant.name)} · ${badge(ME.role, ME.role === "admin" ? "admin" : "")}</div>
        <p><a href="/docs" target="_blank" rel="noopener">API docs</a> · <a href="#" id="logout">Sign out</a></p></div>
      </aside><main class="main" id="main"></main></div>`;
    $("#logout").addEventListener("click", (e) => { e.preventDefault(); logout(); });
    shellReady = true;
  }

  async function refreshCounts() {
    try {
      const d = await api("GET", "/dashboard");
      CURRENCY = d.currency || CURRENCY;
      const set = (key, n) => { const el = $(`[data-count="${key}"]`); if (el) { el.textContent = n; el.classList.toggle("hidden", !n); } };
      set("alerts", d.counts.open_alerts);
      set("approvals", d.counts.pending_approvals);
    } catch { /* non-critical */ }
  }

  const ROUTES = [
    [/^#\/dashboard$/, pageDashboard], [/^#\/customers$/, pageCustomers], [/^#\/products$/, pageProducts],
    [/^#\/orders$/, pageOrders], [/^#\/orders\/(\d+)$/, pageOrder], [/^#\/audit$/, pageAudit],
    [/^#\/time-travel$/, pageTimeTravel], [/^#\/alerts$/, pageAlerts], [/^#\/approvals$/, pageApprovals],
    [/^#\/webhooks$/, pageWebhooks], [/^#\/events$/, pageEvents], [/^#\/team$/, pageTeam], [/^#\/settings$/, pageSettings], [/^#\/integrations$/, pageIntegrations],
  ];

  async function route() {
    closeModal();
    if (!tokens.access) return renderAuth();
    if (!ME) {
      try { ME = await api("GET", "/auth/me"); } catch { tokens.clear(); return renderAuth(); }
    }
    let hash = location.hash || "#/dashboard";
    let match = null, page = null;
    for (const [re, fn] of ROUTES) { match = hash.match(re); if (match) { page = fn; break; } }
    if (!page) { location.hash = "#/dashboard"; return; }
    if (!shellReady) renderShell();
    $$(".nav a").forEach((a) => a.classList.toggle("active", hash === a.getAttribute("href") || hash.startsWith(a.getAttribute("href") + "/")));
    const main = $("#main");
    const view = document.createElement("div");
    view.innerHTML = `<div class="empty">Loading…</div>`;
    main.replaceChildren(view);
    try {
      await page(view, ...match.slice(1));
    } catch (err) {
      view.innerHTML = `<div class="card"><h2>Something went wrong</h2><p>${esc(err.message)}</p></div>`;
    }
    refreshCounts();
  }
  window.addEventListener("hashchange", route);

  // ---------------------------------------------------------------- dashboard
  async function pageDashboard(view) {
    const d = await api("GET", "/dashboard");
    CURRENCY = d.currency || CURRENCY;
    const c = d.counts;
    const kpi = (label, value, hint = "", cls = "") => `<div class="kpi ${cls}"><div class="label">${esc(label)}</div><div class="value">${value}</div><div class="hint">${hint}</div></div>`;
    const maxDay = Math.max(1, ...d.revenue_by_day.map((r) => Number(r.amount)));
    const maxStatus = Math.max(1, ...d.orders_by_status.map((r) => Number(r.n)));
    view.innerHTML = header("Dashboard", `${esc(ME.tenant.name)} · everything below is reconstructed from provenance-tracked data`) + `
      <div class="grid k4">
        ${kpi("Revenue", money(c.revenue), "paid, shipped & delivered")}
        ${kpi("Orders", fmtNum(c.orders))}
        ${kpi("Customers", fmtNum(c.customers))}
        ${kpi("Active products", fmtNum(c.active_products))}
        ${kpi("Open alerts", fmtNum(c.open_alerts), `<a href="#/alerts">review</a>`, c.open_alerts ? "alert" : "")}
        ${kpi("Pending approvals", fmtNum(c.pending_approvals), `<a href="#/approvals">review</a>`)}
        ${kpi("Audit records", fmtNum(c.audit_records), "hash-chained")}
        ${kpi("Events", fmtNum(c.events), c.failing_deliveries ? `${c.failing_deliveries} failing deliveries` : "transactional outbox")}
      </div><div class="grid c3">
      <div>
        <div class="card"><h2>Revenue, last 14 days</h2>
          ${d.revenue_by_day.length ? `<div class="bars">${d.revenue_by_day.map((r) => `<div class="bar" data-h="${(Number(r.amount) / maxDay) * 100}" title="${esc(money(r.amount))}"></div>`).join("")}</div>
          <div class="bars-labels">${d.revenue_by_day.map((r) => `<span>${esc(new Date(r.day).toLocaleDateString(undefined, { month: "short", day: "numeric" }))}</span>`).join("")}</div>` : `<div class="empty">No paid orders yet.</div>`}
        </div>
        <div class="card"><h2>Recent activity</h2>${table([
          { h: "When", f: (r) => esc(when(r.changed_at)) },
          { h: "Change", f: (r) => `${badge(r.operation)} <a href="#" data-history="${esc(r.entity)}|${esc(r.record_pk)}">${esc(r.entity)} ${esc(r.record_pk)}</a>` },
          { h: "Actor", f: (r) => esc(r.actor) },
          { h: "Request", f: (r) => r.request_id ? `<a href="#" class="mono" data-trace="${esc(r.request_id)}">${short(r.request_id, 10)}</a>` : "" },
        ], d.recent_activity)}</div>
      </div>
      <div>
        <div class="card"><h2>Audit integrity</h2><div class="integrity" id="integrity">
          <div class="icon unknown">?</div><div><div><b>Not verified yet</b></div><div class="help">Recompute every SHA-256 link in Oracle.</div></div></div>
          <p><button class="btn primary" id="verify">Verify chain now</button></p></div>
        <div class="card"><h2>Orders by status</h2>${d.orders_by_status.map((r) => `<div class="hbar"><span>${badge(r.status)}</span>
          <div class="track"><div class="fill" data-w="${(Number(r.n) / maxStatus) * 100}"></div></div><span class="num">${fmtNum(r.n)}</span></div>`).join("") || `<div class="empty">No orders yet.</div>`}</div>
        <div class="card"><h2>Top products</h2>${table([
          { h: "Product", f: (r) => esc(r.name) }, { h: "Units", f: (r) => fmtNum(r.units), cls: "num" }, { h: "Revenue", f: (r) => money(r.amount, ""), cls: "num" },
        ], d.top_products, { empty: "No sales yet." })}</div>
        <div class="card"><h2>Most active users</h2>${table([
          { h: "Actor", f: (r) => esc(r.actor) }, { h: "Changes", f: (r) => fmtNum(r.changes), cls: "num" },
        ], d.top_actors)}</div>
      </div></div>`;
    $$("[data-h]", view).forEach((el) => { el.style.height = Math.max(2, Number(el.dataset.h)) + "%"; });
    $$("[data-w]", view).forEach((el) => { el.style.width = Number(el.dataset.w) + "%"; });
    $("#verify", view).addEventListener("click", () => verifyChain($("#integrity", view)));
  }

  async function verifyChain(target) {
    const r = await guarded(() => api("POST", "/audit/verify"));
    if (!r) return;
    target.innerHTML = r.ok
      ? `<div class="icon ok">✓</div><div><div><b>Intact</b> — ${fmtNum(r.checked)} records verified</div><div class="help">Head #${esc(r.head_seq)} · ${esc(when(r.verified_at))}</div></div>`
      : `<div class="icon bad">!</div><div><div><b>Tampering detected</b> at record #${esc(r.first_bad_seq)}</div><div class="help">${esc(r.reason)}</div></div>`;
    toast(r.ok ? "Audit chain verified: intact" : "Audit chain verification FAILED", r.ok ? "ok" : "error");
  }

  // ---------------------------------------------------------------- customers
  async function pageCustomers(view) {
    let search = "";
    const load = async () => {
      const data = await api("GET", `/customers?limit=200${search ? "&search=" + encodeURIComponent(search) : ""}`);
      $("#list", view).innerHTML = table([
        { h: "#", f: (r) => esc(r.customer_id) }, { h: "Name", f: (r) => esc(r.name) }, { h: "Email", f: (r) => esc(r.email) },
        { h: "Phone", f: (r) => esc(r.phone) }, { h: "Orders", f: (r) => fmtNum(r.order_count), cls: "num" },
        { h: "Lifetime value", f: (r) => money(r.lifetime_value), cls: "num" }, { h: "Since", f: (r) => esc(when(r.created_at)) },
      ], data.items, { rowAttrs: (r) => `class="click" data-id="${r.customer_id}"`, empty: "No customers yet." });
    };
    view.innerHTML = header("Customers", "Click a customer to see and edit their full change history",
      can("staff") ? `<button class="btn primary" id="new">New customer</button>` : "") +
      `<div class="card"><div class="filters"><div class="field"><label>Search</label><input id="q" placeholder="Name or email"></div></div><div id="list"></div></div>`;
    $("#q", view).addEventListener("input", (e) => { search = e.target.value; clearTimeout(view._t); view._t = setTimeout(load, 250); });
    $("#new", view)?.addEventListener("click", () => customerForm(null, load));
    on(view, "click", "tr[data-id]", (e, tr) => customerForm(tr.dataset.id, load));
    await load();
  }

  async function customerForm(id, reload) {
    const c = id ? await api("GET", `/customers/${id}`) : { name: "", email: "", phone: "" };
    const body = modal(id ? `Customer #${id}` : "New customer", `
      <form id="f"><div class="field"><label>Name</label><input name="name" value="${esc(c.name)}" required></div>
      <div class="field"><label>Email</label><input name="email" type="email" value="${esc(c.email)}" required></div>
      <div class="field"><label>Phone</label><input name="phone" value="${esc(c.phone)}"></div>
      <div class="actions">${can("staff") ? `<button class="btn primary">${id ? "Save" : "Create"}</button>` : ""}
      ${id && can("admin") ? `<button type="button" class="btn danger" id="del">Delete</button>` : ""}</div></form>
      ${id ? `<h3>History</h3><div id="hist"><div class="empty">Loading…</div></div>` : ""}`, { wide: !!id });
    $("#f", body).addEventListener("submit", async (e) => {
      e.preventDefault();
      const ok = await guarded(() => api(id ? "PATCH" : "POST", id ? `/customers/${id}` : "/customers", formData(e.target)), "Saved");
      if (ok) { closeModal(); reload(); }
    });
    $("#del", body)?.addEventListener("click", async () => {
      if (!confirm("Delete this customer? Customers with orders cannot be deleted.")) return;
      const ok = await guarded(() => api("DELETE", `/customers/${id}`).then(() => true), "Customer deleted");
      if (ok) { closeModal(); reload(); }
    });
    if (id) {
      const h = await api("GET", `/provenance/customer/${id}/history`);
      $("#hist", body).innerHTML = auditTimeline(h.history, { showEntity: false });
    }
  }

  // ---------------------------------------------------------------- products
  async function pageProducts(view) {
    const load = async () => {
      const data = await api("GET", "/products?limit=200");
      $("#list", view).innerHTML = table([
        { h: "#", f: (r) => esc(r.product_id) }, { h: "SKU", f: (r) => `<span class="mono">${esc(r.sku)}</span>` },
        { h: "Name", f: (r) => esc(r.name) }, { h: "Price", f: (r) => money(r.price), cls: "num" },
        { h: "Status", f: (r) => r.active ? badge("active", "ok") : badge("inactive") },
        { h: "Approvals", f: (r) => r.pending_changes ? badge(`${r.pending_changes} pending`, "warn") : "" },
      ], data.items, { rowAttrs: (r) => `class="click" data-id="${r.product_id}"`, empty: "No products yet." });
    };
    view.innerHTML = header("Products", "Price changes above your approval threshold go to a second admin for sign-off",
      can("staff") ? `<button class="btn primary" id="new">New product</button>` : "") + `<div class="card"><div id="list"></div></div>`;
    $("#new", view)?.addEventListener("click", () => productForm(null, load));
    on(view, "click", "tr[data-id]", (e, tr) => productForm(tr.dataset.id, load));
    await load();
  }

  async function productForm(id, reload) {
    const p = id ? await api("GET", `/products/${id}`) : { sku: "", name: "", price: "", active: true };
    const body = modal(id ? `Product #${id}` : "New product", `
      <form id="f"><div class="row">
        <div class="field"><label>SKU</label><input name="sku" value="${esc(p.sku)}" ${id ? "disabled" : "required"}></div>
        <div class="field"><label>Name</label><input name="name" value="${esc(p.name)}" required></div></div>
      <div class="row"><div class="field"><label>Price (${esc(CURRENCY)})</label><input name="price" type="number" step="0.01" min="0" value="${esc(p.price)}" required></div>
        <div class="field"><label class="check"><input type="checkbox" name="active" ${p.active ? "checked" : ""}> Active</label></div></div>
      ${id ? `<div class="field"><label>Reason for price change</label><input name="reason" placeholder="e.g. supplier cost increase"></div>` : ""}
      ${can("staff") ? `<button class="btn primary">${id ? "Save" : "Create"}</button>` : ""}</form>
      ${id ? `<h3>Price & change history</h3><div id="hist"><div class="empty">Loading…</div></div>` : ""}`, { wide: !!id });
    $("#f", body).addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = formData(e.target);
      const payload = { name: f.name, price: f.price, active: e.target.active.checked };
      if (!id) payload.sku = f.sku; else if (f.reason) payload.reason = f.reason;
      const res = await guarded(() => api(id ? "PATCH" : "POST", id ? `/products/${id}` : "/products", payload));
      if (!res) return;
      if (res.pending_change_request) toast(res.pending_change_request.message + ". Sent for approval.", "");
      else toast("Saved", "ok");
      closeModal();
      reload();
    });
    if (id) {
      const h = await api("GET", `/provenance/product/${id}/history`);
      $("#hist", body).innerHTML = auditTimeline(h.history, { showEntity: false });
    }
  }

  // ---------------------------------------------------------------- orders
  async function pageOrders(view) {
    let status = "";
    const load = async () => {
      const data = await api("GET", `/orders?limit=200${status ? "&status=" + status : ""}`);
      $("#list", view).innerHTML = table([
        { h: "Order", f: (r) => `<a href="#/orders/${r.order_id}">#${esc(r.order_id)}</a>` },
        { h: "Customer", f: (r) => esc(r.customer_name) }, { h: "Status", f: (r) => badge(r.status) },
        { h: "Items", f: (r) => fmtNum(r.item_count), cls: "num" }, { h: "Total", f: (r) => money(r.total_amount, r.currency), cls: "num" },
        { h: "Paid", f: (r) => money(r.paid_amount, ""), cls: "num" }, { h: "Created", f: (r) => esc(when(r.created_at)) },
      ], data.items, { rowAttrs: (r) => `class="click" data-id="${r.order_id}"`, empty: "No orders match." });
    };
    const statuses = ["", "CREATED", "PAID", "SHIPPED", "DELIVERED", "CANCELLED", "REFUNDED"];
    view.innerHTML = header("Orders", "Open an order to see why its total is what it is",
      can("staff") ? `<button class="btn primary" id="new">New order</button>` : "") +
      `<div class="card"><div class="filters"><div class="field"><label>Status</label><select id="st">${statuses.map((s) => `<option value="${s}">${s || "All"}</option>`).join("")}</select></div></div><div id="list"></div></div>`;
    $("#st", view).addEventListener("change", (e) => { status = e.target.value; load(); });
    $("#new", view)?.addEventListener("click", newOrderForm);
    on(view, "click", "tr[data-id]", (e, tr) => { if (!e.target.closest("a")) location.hash = `#/orders/${tr.dataset.id}`; });
    await load();
  }

  async function newOrderForm() {
    const [customers, products] = await Promise.all([api("GET", "/customers?limit=200"), api("GET", "/products?limit=200&active=true")]);
    const productOptions = products.items.map((p) => `<option value="${p.product_id}">${esc(p.name)} — ${esc(money(p.price))}</option>`).join("");
    const lineRow = () => `<tr><td><select name="product">${productOptions}</select></td><td><input name="qty" type="number" min="0.01" step="0.01" value="1"></td>
      <td><input name="price" type="number" min="0" step="0.01" placeholder="list price"></td><td><button type="button" class="btn small danger" data-remove>✕</button></td></tr>`;
    const body = modal("New order", `<form id="f">
      <div class="field"><label>Customer</label><select name="customer_id" required>${customers.items.map((c) => `<option value="${c.customer_id}">${esc(c.name)} (${esc(c.email)})</option>`).join("")}</select></div>
      <table class="lines"><thead><tr><th>Product</th><th>Qty</th><th>Unit price override</th><th></th></tr></thead><tbody id="lines">${lineRow()}</tbody></table>
      <p><button type="button" class="btn small" id="add">+ Add line</button></p>
      <div class="field"><label>Notes</label><input name="notes"></div>
      <p class="help">Leave the unit price empty to use the catalogue price at this moment. Overrides are flagged by the discount rule.</p>
      <button class="btn primary">Create order</button></form>`, { wide: true });
    $("#add", body).addEventListener("click", () => $("#lines", body).insertAdjacentHTML("beforeend", lineRow()));
    on(body, "click", "[data-remove]", (e, b) => b.closest("tr").remove());
    $("#f", body).addEventListener("submit", async (e) => {
      e.preventDefault();
      const items = $$("#lines tr", body).map((tr) => {
        const item = { product_id: Number($("[name=product]", tr).value), quantity: $("[name=qty]", tr).value };
        const price = $("[name=price]", tr).value;
        if (price !== "") item.unit_price = price;
        return item;
      });
      const res = await guarded(() => api("POST", "/orders", { customer_id: Number(e.target.customer_id.value), notes: e.target.notes.value || null, items }), "Order created");
      if (res) location.hash = `#/orders/${res.order_id}`;
    });
  }

  async function pageOrder(view, id) {
    const o = await api("GET", `/orders/${id}`);
    const editable = o.status === "CREATED" && can("staff");
    view.innerHTML = header(`Order #${o.order_id}`, `${badge(o.status)} · ${esc(o.customer_name)} · created ${esc(when(o.created_at))}`,
      `<a class="btn" href="#/orders">← All orders</a>` + (can("staff") ? o.allowed_transitions.map((s) => `<button class="btn ${s === "CANCELLED" || s === "REFUNDED" ? "danger" : ""}" data-status="${s}">Mark ${esc(s.toLowerCase())}</button>`).join("") : "")) + `
      <div class="grid c3"><div>
        <div class="card"><h2>Line items</h2>${table([
          { h: "Product", f: (r) => `${esc(r.name)} <span class="help mono">${esc(r.sku)}</span>` },
          { h: "Qty", f: (r) => editable ? `<input class="mono" data-qty="${r.product_id}" type="number" min="0.01" step="0.01" value="${esc(r.quantity)}">` : esc(r.quantity), cls: "num" },
          { h: "Unit price", f: (r) => money(r.unit_price, "") + (Number(r.unit_price) !== Number(r.list_price) ? `<div class="help">list ${esc(money(r.list_price, ""))}</div>` : ""), cls: "num" },
          { h: "Line total", f: (r) => money(r.line_total, ""), cls: "num" },
          { h: "", f: (r) => editable ? `<button class="btn small" data-save="${r.product_id}">Save</button> <button class="btn small danger" data-del="${r.product_id}">✕</button>` : "" },
        ], o.items, { empty: "No items yet." })}
        ${editable ? `<form id="add-item" class="row"><div class="field"><label>Add product</label><select name="product_id" id="prod"></select></div>
          <div class="field"><label>Qty</label><input name="quantity" type="number" min="0.01" step="0.01" value="1"></div>
          <div class="field"><label>Unit price override</label><input name="unit_price" type="number" min="0" step="0.01" placeholder="list"></div>
          <div class="field"><button class="btn">Add</button></div></form>` : ""}</div>
        <div class="card"><h2>Payments</h2>${table([
          { h: "#", f: (r) => esc(r.payment_id) }, { h: "Method", f: (r) => esc(r.method) }, { h: "Status", f: (r) => badge(r.status) },
          { h: "Amount", f: (r) => money(r.amount, ""), cls: "num" }, { h: "When", f: (r) => esc(when(r.created_at)) },
        ], o.payments, { empty: "No payments yet." })}
        ${editable && Number(o.balance_due) > 0 ? `<form id="pay" class="row"><div class="field"><label>Amount</label><input name="amount" type="number" step="0.01" min="0.01" value="${esc(o.balance_due)}"></div>
          <div class="field"><label>Method</label><select name="method">${["CARD", "CASH", "BKASH", "NAGAD", "BANK"].map((m) => `<option>${m}</option>`).join("")}</select></div>
          <div class="field"><label>Reference</label><input name="reference"></div><div class="field"><button class="btn primary">Record payment</button></div></form>` : ""}</div>
      </div><div>
        <div class="card"><h2>Summary</h2><div class="kv">
          <div class="k">Total</div><div><b>${money(o.total_amount, o.currency)}</b></div>
          <div class="k">Paid</div><div>${money(o.paid_amount, o.currency)}</div>
          <div class="k">Balance due</div><div>${money(o.balance_due, o.currency)}</div>
          <div class="k">Updated</div><div>${esc(when(o.updated_at))}</div>
          <div class="k">Notes</div><div>${esc(o.notes) || "—"}</div></div>
          <p class="help">The total is maintained by an Oracle compound trigger, never by the client.</p></div>
      </div></div>
      <div class="card"><div class="tabs" id="ptabs"><button class="active" data-ptab="explain">Explain total</button><button data-ptab="lineage">Lineage graph</button>
        <button data-ptab="history">Full history</button><button data-ptab="travel">Time travel</button></div><div id="pbody"></div></div>`;

    const reload = () => pageOrder(view, id);
    on(view, "click", "[data-status]", async (e, b) => {
      if ((b.dataset.status === "CANCELLED" || b.dataset.status === "REFUNDED") && !confirm(`Mark order ${b.dataset.status.toLowerCase()}?`)) return;
      if (await guarded(() => api("POST", `/orders/${id}/status`, { status: b.dataset.status }), `Order marked ${b.dataset.status}`)) reload();
    });
    on(view, "click", "[data-save]", async (e, b) => {
      const q = $(`[data-qty="${b.dataset.save}"]`, view).value;
      if (await guarded(() => api("PUT", `/orders/${id}/items/${b.dataset.save}`, { quantity: q }), "Quantity updated")) reload();
    });
    on(view, "click", "[data-del]", async (e, b) => {
      if (await guarded(() => api("DELETE", `/orders/${id}/items/${b.dataset.del}`), "Item removed")) reload();
    });
    const addForm = $("#add-item", view);
    if (addForm) {
      const products = await api("GET", "/products?limit=200&active=true");
      $("#prod", view).innerHTML = products.items.map((p) => `<option value="${p.product_id}">${esc(p.name)} — ${esc(money(p.price))}</option>`).join("");
      addForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const f = formData(e.target);
        const payload = { product_id: Number(f.product_id), quantity: f.quantity };
        if (f.unit_price) payload.unit_price = f.unit_price;
        if (await guarded(() => api("POST", `/orders/${id}/items`, payload), "Item added")) reload();
      });
    }
    $("#pay", view)?.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (await guarded(() => api("POST", `/orders/${id}/payments`, formData(e.target)), "Payment recorded")) reload();
    });

    const tabs = {
      explain: async (el) => {
        const x = await api("GET", `/provenance/orders/${id}/explain`);
        const ck = x.checks;
        const check = (k, v, good) => `<div class="check-item"><div class="k">${esc(k)}</div><div class="v">${v} ${good === undefined ? "" : good ? badge("ok", "ok") : badge("mismatch", "bad")}</div></div>`;
        el.innerHTML = `<div class="summary">${esc(x.summary)}</div>
          <div class="checks">${check("Sum of lines", money(ck.sum_of_lines, ""), ck.total_matches_lines)}${check("Recorded total", money(ck.recorded_total, ""))}
          ${check("Replayed from audit log", money(ck.replayed_total_from_audit, ""), ck.replay_matches_total)}${check("Captured payments", money(ck.captured_payments, ""))}${check("Balance due", money(ck.balance_due, ""))}</div>
          <div class="grid c2"><div><h3>How the total was built</h3>${x.steps.length ? `<ul class="timeline">${x.steps.map((s) => `<li>
            <div class="what">${esc(s.description)} <span class="badge ${Number(s.delta) >= 0 ? "ok" : "bad"}">${Number(s.delta) >= 0 ? "+" : ""}${esc(money(s.delta, ""))}</span></div>
            <div class="meta">${esc(s.actor)} · ${esc(when(s.changed_at))} · running total <b>${esc(money(s.running_total, ""))}</b> · chain #${esc(s.chain_seq)}</div></li>`).join("")}</ul>` : `<div class="empty">No item changes recorded.</div>`}</div>
          <div><h3>Where each price came from</h3>${table([
            { h: "Product", f: (r) => esc(r.name) }, { h: "Unit price", f: (r) => money(r.unit_price, ""), cls: "num" },
            { h: "List at order time", f: (r) => money(r.list_price_at_order_time, ""), cls: "num" },
            { h: "Note", f: (r) => r.price_note ? (r.price_note.startsWith("matches") ? badge(r.price_note, "ok") : badge(r.price_note, "warn")) : "" },
          ], x.lines)}</div></div>`;
      },
      lineage: async (el) => {
        const g = await api("GET", `/provenance/orders/${id}/lineage`);
        el.innerHTML = `<p class="help">Everything that shaped this order. Arrows show contribution; events list shows cause and effect inside each request.</p>
          <div class="graph">${lineageSvg(g)}</div><div class="legend">${["order", "customer", "order_item", "product", "payment", "change_request", "alert"].map((t) => `<span class="t-${t}">${t.replace("_", " ")}</span>`).join("")}</div>
          <h3 class="mt">Causal chain</h3>${auditTimeline(g.events)}`;
      },
      history: async (el) => {
        const g = await api("GET", `/provenance/orders/${id}/lineage`);
        el.innerHTML = auditTimeline(g.events);
      },
      travel: async (el) => {
        const start = new Date(o.created_at);
        el.innerHTML = `<form id="tt" class="row"><div class="field"><label>Show this order as it was at</label><input name="at" type="datetime-local" step="1" value="${localInput(new Date())}"></div>
          <div class="field"><button class="btn primary">Travel</button></div></form><p class="help">Order created ${esc(when(start))}. Reconstructed by replaying the hash-chained audit log, so it works for any point in history.</p><div id="ttout"></div>`;
        $("#tt", el).addEventListener("submit", async (e) => {
          e.preventDefault();
          const r = await guarded(() => api("GET", `/provenance/order/${id}/as-of?at=${encodeURIComponent(toIso(e.target.at.value))}`));
          if (r) $("#ttout", el).innerHTML = renderAsOf(r);
        });
      },
    };
    const showTab = async (name) => {
      $$("#ptabs [data-ptab]", view).forEach((b) => b.classList.toggle("active", b.dataset.ptab === name));
      const el = $("#pbody", view);
      el.innerHTML = `<div class="empty">Loading…</div>`;
      try { await tabs[name](el); } catch (err) { el.innerHTML = `<div class="empty">${esc(err.message)}</div>`; }
    };
    on(view, "click", "[data-ptab]", (e, b) => showTab(b.dataset.ptab));
    showTab("explain");
  }

  function renderAsOf(r) {
    if (!r.existed) return `<div class="empty">The record did not exist at ${esc(when(r.as_of))}.</div>`;
    const kv = Object.entries(r.state).map(([k, v]) => `<div class="k">${esc(k)}</div><div>${esc(val(v))}</div>`).join("");
    const items = r.items ? `<h3>Items at that time</h3>${table([
      { h: "Product", f: (i) => esc(i.product_id) }, { h: "Qty", f: (i) => esc(i.quantity), cls: "num" },
      { h: "Unit price", f: (i) => money(i.unit_price, ""), cls: "num" }, { h: "Line total", f: (i) => money(i.line_total, ""), cls: "num" },
    ], r.items, { empty: "No items at that time." })}` : "";
    const src = r.based_on ? `<p class="help">Source: ${esc(r.source)} — chain #${esc(r.based_on.chain_seq)} (${esc(r.based_on.operation)} by ${esc(r.based_on.actor)} at ${esc(when(r.based_on.changed_at))})</p>` : `<p class="help">Source: ${esc(r.source)}</p>`;
    return `${src}<div class="kv">${kv}</div>${items}`;
  }

  function lineageSvg(g) {
    const colOf = { customer: 0, payment: 0, alert: 0, order: 1, order_item: 2, product: 3, change_request: 4 };
    const color = { order: "#2c5be8", customer: "#7a5af8", order_item: "#0e9384", product: "#f79009", payment: "#12b76a", change_request: "#ee46bc", alert: "#f04438" };
    const W = 210, H = 50, GX = 80, GY = 22, PAD = 20;
    const cols = [[], [], [], [], []];
    g.nodes.forEach((n) => cols[colOf[n.type] ?? 4].push(n));
    const usedCols = cols.map((c, i) => (c.length ? i : -1)).filter((i) => i >= 0);
    const maxRows = Math.max(1, ...cols.map((c) => c.length));
    const height = PAD * 2 + maxRows * (H + GY) - GY;
    const pos = {};
    usedCols.forEach((ci, slot) => {
      const col = cols[ci];
      const offset = ((maxRows - col.length) * (H + GY)) / 2;
      col.forEach((n, i) => { pos[n.id] = { x: PAD + slot * (W + GX), y: PAD + offset + i * (H + GY) }; });
    });
    const width = PAD * 2 + usedCols.length * (W + GX) - GX;
    const edges = g.edges.filter((e) => pos[e.from] && pos[e.to]).map((e) => {
      const a = pos[e.from], b = pos[e.to];
      const forward = a.x < b.x;
      const x1 = forward ? a.x + W : a.x, y1 = a.y + H / 2, x2 = forward ? b.x : b.x + W, y2 = b.y + H / 2;
      const mx = (x1 + x2) / 2;
      const path = a.x === b.x ? `M${a.x + W},${y1} C${a.x + W + 40},${y1} ${b.x + W + 40},${y2} ${b.x + W},${y2}` : `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
      return `<path class="edge" d="${path}" marker-end="url(#arrow)"></path><text class="edge-label" x="${mx}" y="${(y1 + y2) / 2 - 4}" text-anchor="middle">${esc(e.label)}</text>`;
    }).join("");
    const nodes = g.nodes.filter((n) => pos[n.id]).map((n) => {
      const p = pos[n.id];
      return `<g class="node"><rect x="${p.x}" y="${p.y}" width="${W}" height="${H}" fill="#fff" stroke="${color[n.type] || "#999"}"></rect>
        <rect x="${p.x}" y="${p.y}" width="6" height="${H}" fill="${color[n.type] || "#999"}"></rect>
        <text x="${p.x + 14}" y="${p.y + 20}">${esc(trunc(n.label, 28))}</text><text class="detail" x="${p.x + 14}" y="${p.y + 37}">${esc(trunc(n.detail, 32))}</text>
        <title>${esc(n.label)} — ${esc(n.detail)}</title></g>`;
    }).join("");
    return `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">
      <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#98a2b3"></path></marker></defs>${edges}${nodes}</svg>`;
  }

  // ---------------------------------------------------------------- audit log
  async function pageAudit(view) {
    let filters = {};
    let before = null;
    const entities = ["", "customer", "product", "order", "order_item", "payment"];
    view.innerHTML = header("Audit log", "Every change, captured by Oracle triggers into a per-organization SHA-256 hash chain",
      `<button class="btn" id="verify">Verify chain</button>${can("staff") ? `<button class="btn" data-export="csv">Export CSV</button><button class="btn" data-export="json">Export JSON</button>` : ""}`) + `
      <div class="card"><div class="integrity hidden" id="integrity"></div>
      <form id="flt" class="filters">
        <div class="field"><label>Entity</label><select name="entity">${entities.map((e) => `<option value="${e}">${e || "All"}</option>`).join("")}</select></div>
        <div class="field"><label>Record</label><input name="record_pk" placeholder="id, e.g. 12 or 3:7"></div>
        <div class="field"><label>Operation</label><select name="operation"><option value="">All</option><option>INSERT</option><option>UPDATE</option><option>DELETE</option></select></div>
        <div class="field"><label>Actor</label><input name="actor" placeholder="email contains"></div>
        <div class="field"><label>Request ID</label><input name="request_id"></div>
        <div class="field"><label>Since</label><input name="since" type="datetime-local"></div>
        <div class="field"><button class="btn primary">Apply</button></div></form>
      <div id="list"></div><p><button class="btn hidden" id="more">Load more</button></p></div>`;
    const qs = () => {
      const p = new URLSearchParams();
      Object.entries(filters).forEach(([k, v]) => p.set(k, k === "since" ? toIso(v) : v));
      return p;
    };
    const row = (r) => `<tr><td class="mono">#${esc(r.chain_seq)}</td><td>${esc(when(r.changed_at))}</td>
      <td><a href="#" data-history="${esc(r.entity)}|${esc(r.record_pk)}">${esc(r.entity)} ${esc(r.record_pk)}</a></td><td>${badge(r.operation)}</td>
      <td>${esc(r.actor)}${r.db_user !== "PROV_APP" ? `<div>${badge("direct DB: " + r.db_user, "bad")}</div>` : ""}</td><td>${diffList(r.changes, r.operation)}</td>
      <td>${r.request_id ? `<a href="#" class="mono" data-trace="${esc(r.request_id)}">${short(r.request_id, 10)}</a>` : ""}</td>
      <td class="hash" title="${esc(r.row_hash)}">${short(r.row_hash, 10)}…</td></tr>`;
    const load = async (append) => {
      const p = qs(); p.set("limit", 50); if (append && before) p.set("before_id", before);
      const data = await api("GET", `/audit?${p}`);
      before = data.next_before_id;
      if (!append) {
        $("#list", view).innerHTML = data.items.length ? `<div class="table-wrap"><table><thead><tr><th>Seq</th><th>When</th><th>Record</th><th>Op</th><th>Actor</th><th>Changes</th><th>Request</th><th>Hash</th></tr></thead><tbody id="rows"></tbody></table></div>` : `<div class="empty">No matching records.</div>`;
      }
      $("#rows", view)?.insertAdjacentHTML("beforeend", data.items.map(row).join(""));
      $("#more", view).classList.toggle("hidden", !before);
    };
    $("#flt", view).addEventListener("submit", (e) => { e.preventDefault(); filters = formData(e.target); load(false); });
    $("#more", view).addEventListener("click", () => load(true));
    $("#verify", view).addEventListener("click", () => { const el = $("#integrity", view); el.classList.remove("hidden"); verifyChain(el); });
    on(view, "click", "[data-export]", async (e, b) => {
      const p = qs(); p.set("format", b.dataset.export);
      const res = await guarded(() => api("GET", `/audit/export?${p}`, undefined, { raw: true }));
      if (!res) return;
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = (res.headers.get("Content-Disposition") || "").match(/filename="(.+)"/)?.[1] || `audit.${b.dataset.export}`;
      a.click();
      URL.revokeObjectURL(a.href);
    });
    await load(false);
  }

  // ---------------------------------------------------------------- time travel
  async function pageTimeTravel(view) {
    const now = new Date();
    const hourAgo = new Date(now.getTime() - 3600 * 1000);
    const entitySelect = `<select name="entity">${["order", "product", "customer", "payment", "order_item"].map((e) => `<option>${e}</option>`).join("")}</select>`;
    view.innerHTML = header("Time travel", "Reconstruct any record at any moment, and compare two moments") + `
      <div class="grid c2">
      <div class="card"><h2>As of a point in time</h2><form id="asof">
        <div class="row"><div class="field"><label>Entity</label>${entitySelect}</div><div class="field"><label>Record ID</label><input name="pk" required placeholder="e.g. 1"></div></div>
        <div class="field"><label>At</label><input name="at" type="datetime-local" step="1" value="${localInput(now)}"></div>
        <button class="btn primary">Reconstruct</button></form><div id="asof-out"></div></div>
      <div class="card"><h2>Compare two moments</h2><form id="cmp">
        <div class="row"><div class="field"><label>Entity</label>${entitySelect}</div><div class="field"><label>Record ID</label><input name="pk" required></div></div>
        <div class="row"><div class="field"><label>From</label><input name="t1" type="datetime-local" step="1" value="${localInput(hourAgo)}"></div>
        <div class="field"><label>To</label><input name="t2" type="datetime-local" step="1" value="${localInput(now)}"></div></div>
        <button class="btn primary">Compare</button></form><div id="cmp-out"></div></div>
      <div class="card"><h2>Oracle Flashback Query</h2><p class="help">Reads the live table with <code>AS OF TIMESTAMP</code>, straight from Oracle's undo data. Only covers the undo retention window (minutes), while the audit replay covers all history.</p>
        <form id="fb"><div class="row"><div class="field"><label>Entity</label><select name="entity">${["order", "product", "customer", "payment"].map((e) => `<option>${e}</option>`).join("")}</select></div>
        <div class="field"><label>Record ID</label><input name="pk" required></div><div class="field"><label>Minutes ago</label><input name="m" type="number" min="0.1" step="0.1" value="5"></div></div>
        <button class="btn primary">Flashback</button></form><div id="fb-out"></div></div></div>`;
    $("#asof", view).addEventListener("submit", async (e) => {
      e.preventDefault(); const f = e.target;
      const r = await guarded(() => api("GET", `/provenance/${f.entity.value}/${encodeURIComponent(f.pk.value)}/as-of?at=${encodeURIComponent(toIso(f.at.value))}`));
      if (r) $("#asof-out", view).innerHTML = `<hr>${renderAsOf(r)}`;
    });
    $("#cmp", view).addEventListener("submit", async (e) => {
      e.preventDefault(); const f = e.target;
      const r = await guarded(() => api("GET", `/provenance/${f.entity.value}/${encodeURIComponent(f.pk.value)}/compare?t1=${encodeURIComponent(toIso(f.t1.value))}&t2=${encodeURIComponent(toIso(f.t2.value))}`));
      if (r) $("#cmp-out", view).innerHTML = `<hr><h3>Net difference</h3>${r.changes.length ? diffList(r.changes, "UPDATE") : `<div class="empty">No difference.</div>`}
        <h3>Changes in between (${r.events_between.length})</h3>${auditTimeline(r.events_between, { showEntity: false })}`;
    });
    $("#fb", view).addEventListener("submit", async (e) => {
      e.preventDefault(); const f = e.target;
      const r = await guarded(() => api("GET", `/provenance/${f.entity.value}/${encodeURIComponent(f.pk.value)}/flashback?minutes_ago=${encodeURIComponent(f.m.value)}`));
      if (r) $("#fb-out", view).innerHTML = `<hr>${r.existed ? `<div class="kv">${Object.entries(r.state).map(([k, v]) => `<div class="k">${esc(k)}</div><div>${esc(val(v))}</div>`).join("")}</div>` : `<div class="empty">No row at that time (it did not exist yet, or the change is only seconds old: Oracle samples its time-to-SCN map every few seconds).</div>`}<p class="help">${esc(r.source)}</p>`;
    });
  }

  // ---------------------------------------------------------------- alerts
  async function pageAlerts(view) {
    let status = "OPEN";
    const load = async () => {
      const rows = await api("GET", `/alerts${status ? "?status=" + status : ""}`);
      const link = (r) => r.entity === "order" ? `<a href="#/orders/${esc(r.entity_id)}">order ${esc(r.entity_id)}</a>`
        : r.entity === "order_item" ? `<a href="#/orders/${esc(String(r.entity_id).split(":")[0])}">item ${esc(r.entity_id)}</a>`
          : r.entity && r.entity !== "audit_log" ? `<a href="#" data-history="${esc(r.entity)}|${esc(r.entity_id)}">${esc(r.entity)} ${esc(r.entity_id)}</a>` : esc(r.entity);
      $("#list", view).innerHTML = table([
        { h: "Severity", f: (r) => badge(r.severity) }, { h: "Rule", f: (r) => `<span class="mono">${esc(r.rule_code)}</span>` },
        { h: "Finding", f: (r) => esc(r.title) }, { h: "Record", f: link }, { h: "Status", f: (r) => badge(r.status) },
        { h: "Raised", f: (r) => esc(when(r.created_at)) },
        { h: "", f: (r) => can("staff") ? (r.status === "OPEN" ? `<button class="btn small" data-alert="${r.alert_id}" data-to="ACKNOWLEDGED">Acknowledge</button> ` : "")
          + (r.status !== "RESOLVED" ? `<button class="btn small" data-alert="${r.alert_id}" data-to="RESOLVED">Resolve</button>` : `<button class="btn small" data-alert="${r.alert_id}" data-to="OPEN">Reopen</button>`) : "" },
      ], rows, { empty: "No alerts. Run the rules to scan your data." });
    };
    const catalogue = await api("GET", "/alerts/rules");
    view.innerHTML = header("Alerts", "Data-quality and anomaly rules run every minute over live data and the audit log",
      can("staff") ? `<button class="btn primary" id="run">Run rules now</button>` : "") + `
      <div class="grid c3"><div class="card"><div class="filters"><div class="field"><label>Status</label><select id="st">
        ${["OPEN", "ACKNOWLEDGED", "RESOLVED", ""].map((s) => `<option value="${s}">${s || "All"}</option>`).join("")}</select></div></div><div id="list"></div></div>
      <div class="card"><h2>Rule catalogue</h2>${table([{ h: "Code", f: (r) => `<span class="mono">${esc(r.code)}</span>` }, { h: "Rule", f: (r) => esc(r.name) }], catalogue)}</div></div>`;
    $("#st", view).addEventListener("change", (e) => { status = e.target.value; load(); });
    $("#run", view)?.addEventListener("click", async () => {
      const r = await guarded(() => api("POST", "/alerts/run"));
      if (r) { toast(`${r.findings} finding(s), ${r.new_alerts} new alert(s)`, r.new_alerts ? "" : "ok"); load(); refreshCounts(); }
    });
    on(view, "click", "[data-alert]", async (e, b) => {
      if (await guarded(() => api("PATCH", `/alerts/${b.dataset.alert}`, { status: b.dataset.to }))) { load(); refreshCounts(); }
    });
    await load();
  }

  // ---------------------------------------------------------------- approvals
  async function pageApprovals(view) {
    const load = async () => {
      const rows = await api("GET", "/approvals");
      $("#list", view).innerHTML = table([
        { h: "#", f: (r) => esc(r.change_request_id) }, { h: "Product", f: (r) => `<a href="#" data-history="product|${esc(r.entity_id)}">${esc(r.product_name || r.entity_id)}</a>` },
        { h: "Change", f: (r) => `${esc(money(r.payload.old_price, ""))} → <b>${esc(money(r.payload.new_price, ""))}</b> <span class="help">(${esc(r.payload.change_pct)}%)</span>` },
        { h: "Reason", f: (r) => esc(r.reason) || "—" },
        { h: "Requested", f: (r) => `${esc(r.requested_by)}<div class="help">${esc(when(r.requested_at))}</div>` },
        { h: "Status", f: (r) => badge(r.status) + (r.reviewed_by ? `<div class="help">by ${esc(r.reviewed_by)}${r.review_note ? ": " + esc(r.review_note) : ""}</div>` : "") },
        { h: "", f: (r) => r.can_review ? `<button class="btn small primary" data-review="${r.change_request_id}" data-act="approve">Approve</button> <button class="btn small danger" data-review="${r.change_request_id}" data-act="reject">Reject</button>`
          : r.status === "PENDING" ? `<span class="help">${r.requested_by_id === ME.user_id ? "awaiting another admin" : "admins only"}</span>` : "" },
      ], rows, { empty: "No change requests. Large price changes will appear here." });
    };
    view.innerHTML = header("Approvals", "Maker-checker: risky changes need a second admin. The database itself rejects self-approval.") + `<div class="card"><div id="list"></div></div>`;
    on(view, "click", "[data-review]", async (e, b) => {
      const note = prompt(b.dataset.act === "approve" ? "Approval note (optional)" : "Reason for rejecting (optional)") ?? null;
      if (note === null) return;
      const ok = await guarded(() => api("POST", `/approvals/${b.dataset.review}/${b.dataset.act}`, { note: note || null }), b.dataset.act === "approve" ? "Approved and applied" : "Rejected");
      if (ok) { load(); refreshCounts(); }
    });
    await load();
  }

  // ---------------------------------------------------------------- webhooks & events
  async function pageWebhooks(view) {
    if (!can("admin")) { view.innerHTML = header("Webhooks") + `<div class="card">Only admins can manage webhooks.</div>`; return; }
    const sink = `${location.origin}/api/v1/dev/webhook-sink`;
    const load = async () => {
      const hooks = await api("GET", "/webhooks");
      $("#list", view).innerHTML = table([
        { h: "#", f: (r) => esc(r.webhook_id) }, { h: "URL", f: (r) => `<span class="mono">${esc(r.url)}</span><div class="help">${esc(r.description)}</div>` },
        { h: "Events", f: (r) => r.event_types.split(",").map((t) => badge(t, "info")).join(" ") },
        { h: "Status", f: (r) => r.is_active === "Y" ? badge("active", "ok") : badge("paused") },
        { h: "Delivered", f: (r) => fmtNum(r.delivered), cls: "num" }, { h: "Failing", f: (r) => r.failing ? badge(r.failing, "bad") : "0", cls: "num" },
        { h: "", f: (r) => `<button class="btn small" data-test="${r.webhook_id}">Send test</button> <button class="btn small" data-deliveries="${r.webhook_id}">Deliveries</button>
          <button class="btn small" data-toggle="${r.webhook_id}" data-active="${r.is_active}">${r.is_active === "Y" ? "Pause" : "Resume"}</button>` },
      ], hooks, { empty: "No webhooks yet." });
    };
    const loadSink = async () => {
      const rows = await api("GET", "/dev/webhook-sink").catch(() => null);
      $("#sink", view).innerHTML = rows === null ? `<div class="empty">The dev receiver is disabled outside development.</div>` : table([
        { h: "Received", f: (r) => esc(when(r.received_at)) }, { h: "Event", f: (r) => badge(r.event, "info") },
        { h: "Delivery", f: (r) => esc(r.delivery) }, { h: "Signature", f: (r) => `<span class="hash">${short(r.signature, 34)}…</span>` },
        { h: "", f: (r, i) => `<button class="btn small" data-body='${esc(JSON.stringify(r.body))}'>Payload</button>` },
      ], rows, { empty: "Nothing received yet. Create a webhook pointing at the local receiver, then make a change." });
    };
    view.innerHTML = header("Webhooks", "Signed (HMAC-SHA256) deliveries from the transactional outbox, with retries and exponential backoff") + `
      <div class="card"><h2>New subscription</h2><form id="f"><div class="row">
        <div class="field"><label>URL</label><input name="url" value="${esc(sink)}" required></div>
        <div class="field"><label>Event types (comma separated, * and prefix.* allowed)</label><input name="event_types" value="order.*, alert.raised, change_request.*"></div>
        <div class="field"><label>Description</label><input name="description" value="Local test receiver"></div>
        <div class="field"><button class="btn primary">Subscribe</button></div></div></form></div>
      <div class="card"><h2>Subscriptions</h2><div id="list"></div></div>
      <div class="card"><div class="topbar"><h2>Local receiver (development)</h2><button class="btn small" id="rs">Refresh</button></div><div id="sink"></div></div>`;
    $("#f", view).addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = formData(e.target);
      const res = await guarded(() => api("POST", "/webhooks", { url: f.url, description: f.description, event_types: (f.event_types || "*").split(",").map((s) => s.trim()).filter(Boolean) }));
      if (!res) return;
      modal("Webhook created", `<p>Store this signing secret now. It will not be shown again.</p><div class="secret">${esc(res.secret)}</div>
        <p class="help">Deliveries follow the <a href="https://www.standardwebhooks.com/" target="_blank" rel="noopener">Standard Webhooks</a> spec: verify <code>webhook-signature</code> with any Standard Webhooks library, or compute base64(HMAC_SHA256(base64decode(secret without "whsec_"), "&lt;webhook-id&gt;.&lt;webhook-timestamp&gt;.&lt;raw body&gt;")).</p>`);
      load();
    });
    on(view, "click", "[data-test]", async (e, b) => { if (await guarded(() => api("POST", `/webhooks/${b.dataset.test}/test`), "Test event queued; it is delivered within a few seconds")) setTimeout(() => { load(); loadSink(); }, 3500); });
    on(view, "click", "[data-toggle]", async (e, b) => { if (await guarded(() => api("PATCH", `/webhooks/${b.dataset.toggle}`, { is_active: b.dataset.active !== "Y" }))) load(); });
    on(view, "click", "[data-body]", (e, b) => modal("Delivered payload", `<pre class="json">${esc(JSON.stringify(JSON.parse(b.dataset.body), null, 2))}</pre>`, { wide: true }));
    on(view, "click", "[data-deliveries]", async (e, b) => {
      const rows = await guarded(() => api("GET", `/webhooks/${b.dataset.deliveries}/deliveries`));
      if (!rows) return;
      const body = modal(`Deliveries for webhook #${b.dataset.deliveries}`, table([
        { h: "#", f: (r) => esc(r.delivery_id) }, { h: "Event", f: (r) => badge(r.event_type, "info") }, { h: "Status", f: (r) => badge(r.status) },
        { h: "Attempts", f: (r) => esc(r.attempts), cls: "num" }, { h: "HTTP", f: (r) => esc(r.response_code) },
        { h: "Error", f: (r) => `<span class="help">${esc(r.last_error)}</span>` }, { h: "Delivered", f: (r) => esc(when(r.delivered_at)) },
        { h: "", f: (r) => r.status !== "SUCCESS" ? `<button class="btn small" data-retry="${r.delivery_id}">Retry</button>` : "" },
      ], rows, { empty: "No deliveries yet." }), { wide: true });
      on(body, "click", "[data-retry]", async (ev, rb) => { if (await guarded(() => api("POST", `/webhooks/deliveries/${rb.dataset.retry}/retry`), "Retry queued")) closeModal(); });
    });
    $("#rs", view).addEventListener("click", loadSink);
    await Promise.all([load(), loadSink()]);
  }

  async function pageEvents(view) {
    const rows = await api("GET", "/events?limit=200");
    view.innerHTML = header("Event stream", "Transactional outbox: events are written in the same Oracle transaction as the change that caused them") +
      `<div class="card">${table([
        { h: "#", f: (r) => esc(r.event_id) }, { h: "Type", f: (r) => badge(r.event_type, "info") },
        { h: "Record", f: (r) => `${esc(r.entity)} ${esc(r.entity_id)}` },
        { h: "Request", f: (r) => r.request_id ? `<a href="#" class="mono" data-trace="${esc(r.request_id)}">${short(r.request_id, 10)}</a>` : "" },
        { h: "Created", f: (r) => esc(when(r.created_at)) }, { h: "Dispatched", f: (r) => r.dispatched_at ? esc(when(r.dispatched_at)) : badge("pending", "warn") },
        { h: "", f: (r) => `<button class="btn small" data-event="${r.event_id}">Payload</button>` },
      ], rows, { empty: "No events yet." })}</div>`;
    const byId = Object.fromEntries(rows.map((r) => [String(r.event_id), r]));
    on(view, "click", "[data-event]", (e, b) => modal(`Event #${b.dataset.event}`, `<pre class="json">${esc(JSON.stringify(byId[b.dataset.event].payload, null, 2))}</pre>`, { wide: true }));
  }

  // ---------------------------------------------------------------- team & settings
  async function pageTeam(view) {
    if (!can("admin")) { view.innerHTML = header("Team") + `<div class="card">Only admins can manage the team.</div>`; return; }
    const load = async () => {
      const users = await api("GET", "/users");
      $("#list", view).innerHTML = table([
        { h: "Name", f: (r) => esc(r.full_name) }, { h: "Email", f: (r) => esc(r.email) },
        { h: "Role", f: (r) => r.user_id === ME.user_id ? badge(r.role, "admin") : `<select data-role="${r.user_id}">${["admin", "staff", "viewer"].map((x) => `<option ${x === r.role ? "selected" : ""}>${x}</option>`).join("")}</select>` },
        { h: "Status", f: (r) => r.is_active === "Y" ? badge("active", "ok") : badge("deactivated", "bad") },
        { h: "Last login", f: (r) => esc(when(r.last_login_at)) || "never" },
        { h: "", f: (r) => r.user_id === ME.user_id ? `<span class="help">you</span>` : `<button class="btn small ${r.is_active === "Y" ? "danger" : ""}" data-active="${r.user_id}" data-to="${r.is_active === "Y" ? "false" : "true"}">${r.is_active === "Y" ? "Deactivate" : "Reactivate"}</button>` },
      ], users);
    };
    view.innerHTML = header("Team", "Roles: viewer (read), staff (operate), admin (manage, approve)") + `
      <div class="card"><h2>Invite a user</h2><form id="f" class="row">
        <div class="field"><label>Full name</label><input name="full_name" required></div><div class="field"><label>Email</label><input name="email" type="email" required></div>
        <div class="field"><label>Temporary password</label><input name="password" type="password" minlength="10" required autocomplete="new-password"></div>
        <div class="field"><label>Role</label><select name="role"><option>viewer</option><option>staff</option><option>admin</option></select></div>
        <div class="field"><button class="btn primary">Invite</button></div></form></div><div class="card"><div id="list"></div></div>`;
    $("#f", view).addEventListener("submit", async (e) => {
      e.preventDefault();
      if (await guarded(() => api("POST", "/users", formData(e.target)), "User invited")) { e.target.reset(); load(); }
    });
    on(view, "change", "[data-role]", async (e, s) => { await guarded(() => api("PATCH", `/users/${s.dataset.role}`, { role: s.value }), "Role updated"); load(); });
    on(view, "click", "[data-active]", async (e, b) => { if (await guarded(() => api("PATCH", `/users/${b.dataset.active}`, { is_active: b.dataset.to === "true" }), "Updated")) load(); });
    await load();
  }

  async function pageSettings(view) {
    const s = await api("GET", "/settings");
    const fields = [
      ["currency", "Currency (ISO code)", "text"], ["approval_price_change_pct", "Price change needing approval (%)", "number"],
      ["price_change_alert_pct", "Price change that raises an alert (%)", "number"], ["discount_alert_pct", "Discount vs. list price that raises an alert (%)", "number"],
      ["large_refund_amount", "Refund amount that raises an alert", "number"], ["rapid_change_count", "Rapid-change alert: number of edits", "number"],
      ["rapid_change_minutes", "Rapid-change alert: window (minutes)", "number"],
    ];
    view.innerHTML = header("Settings", "Thresholds used by approvals and the rules engine") + `<div class="card"><form id="f">
      <div class="grid c2">${fields.map(([k, label, type]) => `<div class="field"><label>${esc(label)}</label><input name="${k}" type="${type}" step="any" value="${esc(s[k])}" ${can("admin") ? "" : "disabled"}></div>`).join("")}</div>
      ${can("admin") ? `<button class="btn primary">Save settings</button>` : `<p class="help">Only admins can change settings.</p>`}</form></div>
      <div class="card"><h2>Organization</h2><div class="kv"><div class="k">Name</div><div>${esc(ME.tenant.name)}</div><div class="k">Slug</div><div class="mono">${esc(ME.tenant.slug)}</div>
      <div class="k">Plan</div><div>${badge(ME.tenant.plan, "info")}</div><div class="k">Isolation</div><div>Oracle Virtual Private Database policy on every tenant table</div></div></div>`;
    $("#f", view).addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = formData(e.target);
      for (const k of Object.keys(f)) if (k !== "currency") f[k] = Number(f[k]);
      if (f.currency) f.currency = f.currency.toUpperCase();
      if (await guarded(() => api("PATCH", "/settings", f), "Settings saved")) CURRENCY = f.currency || CURRENCY;
    });
  }

  // ---------------------------------------------------------------- integrations
  async function pageIntegrations(view) {
    if (!can("admin")) { view.innerHTML = header("Integrations") + `<div class="card">Only admins can manage integrations.</div>`; return; }
    const methods = ["CDC", "TRIGGER", "API", "CSV_IMPORT", "POLLING", "MANUAL"];
    const trustBadge = (t) => badge(t, t === "HIGH" ? "ok" : t === "MEDIUM" ? "warn" : "bad");
    const loadSources = async () => {
      const rows = await api("GET", "/sources");
      $("#sources", view).innerHTML = table([
        { h: "Code", f: (r) => `<span class="mono">${esc(r.code)}</span>` }, { h: "Name", f: (r) => esc(r.name) },
        { h: "Capture", f: (r) => esc(r.capture_method) }, { h: "Trust", f: (r) => trustBadge(r.trust_level) },
        { h: "Status", f: (r) => r.status === "ACTIVE" ? badge("active", "ok") : badge("paused", "warn") },
        { h: "Events", f: (r) => fmtNum(r.event_count), cls: "num" }, { h: "Last event", f: (r) => esc(when(r.last_event_at)) || "never" },
        { h: "", f: (r) => `<button class="btn small" data-src-events="${r.source_id}">Events</button>
          <button class="btn small" data-src-toggle="${r.source_id}" data-to="${r.status === "ACTIVE" ? "PAUSED" : "ACTIVE"}">${r.status === "ACTIVE" ? "Pause" : "Resume"}</button>` },
      ], rows, { empty: "No sources yet. Register the upstream system first." });
      $("#up-source", view).innerHTML = rows.filter((r) => r.status === "ACTIVE")
        .map((r) => `<option value="${esc(r.code)}">${esc(r.code)} (${esc(r.capture_method)}, ${esc(r.trust_level)})</option>`).join("");
    };
    const loadKeys = async () => {
      const rows = await api("GET", "/api-keys");
      $("#keys", view).innerHTML = table([
        { h: "Key ID", f: (r) => `<span class="mono">prv_${esc(r.key_id)}_…</span>` }, { h: "Name", f: (r) => esc(r.name) },
        { h: "Scopes", f: (r) => r.scopes.map((s) => badge(s, "info")).join(" ") },
        { h: "Created", f: (r) => `${esc(when(r.created_at))}<div class="help">${esc(r.created_by)}</div>` },
        { h: "Last used", f: (r) => esc(when(r.last_used_at)) || "never" },
        { h: "Status", f: (r) => r.revoked_at ? badge("revoked", "bad") : badge("active", "ok") },
        { h: "", f: (r) => r.revoked_at ? "" : `<button class="btn small danger" data-revoke="${esc(r.key_id)}">Revoke</button>` },
      ], rows, { empty: "No API keys yet." });
    };
    const loadRecons = async () => {
      const rows = await api("GET", "/reconciliations");
      $("#recons", view).innerHTML = table([
        { h: "#", f: (r) => esc(r.recon_id) }, { h: "Source", f: (r) => `<span class="mono">${esc(r.source)}</span>` },
        { h: "Entity", f: (r) => esc(r.entity) }, { h: "As of", f: (r) => esc(when(r.as_of)) },
        { h: "Records", f: (r) => fmtNum(r.total_records), cls: "num" }, { h: "Matched", f: (r) => fmtNum(r.matched), cls: "num" },
        { h: "Issues", f: (r) => [["mismatched", "warn"], ["missing", "bad"], ["unexpected", "bad"]]
          .filter(([k]) => r[k]).map(([k, c]) => badge(`${r[k]} ${k}`, c)).join(" ") || badge("all matched", "ok") },
        { h: "Run by", f: (r) => esc(r.created_by) },
      ], rows, { rowAttrs: (r) => `class="click" data-recon="${r.recon_id}"`, empty: "No reconciliations yet. Upstream systems run them with POST /api/v1/reconciliations." });
    };
    const curl = (key) => `curl -X POST ${location.origin}/api/v1/events \\
  -H "Authorization: Bearer ${key}" -H "Content-Type: application/json" \\
  -d '{"specversion":"1.0","id":"evt-1","source":"<source code>","type":"order.updated",
       "subject":"order/10045","time":"${new Date().toISOString()}",
       "data":{"op":"u","before":{"total":"1500.00"},"after":{"total":"1200.00"}}}'`;

    view.innerHTML = header("Integrations", "Connect existing systems: they send CloudEvents with an API key, and every event becomes hash-chained evidence") + `
      <div class="card"><h2>1. Sources</h2><p class="help">An upstream system (legacy shop, ERP, CDC pipeline). Its trust level is set here, never by the sender.</p>
        <form id="fsrc" class="row"><div class="field"><label>Code</label><input name="code" placeholder="legacy-shop" required pattern="[a-z0-9][a-z0-9._-]{1,59}"></div>
          <div class="field"><label>Name</label><input name="name" placeholder="Legacy POS" required></div>
          <div class="field"><label>Capture method</label><select name="capture_method">${methods.map((m) => `<option>${m}</option>`).join("")}</select></div>
          <div class="field"><label>Trust</label><select name="trust_level"><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div>
          <div class="field"><button class="btn primary">Register</button></div></form><div id="sources"></div></div>
      <div class="card"><h2>2. API keys</h2><p class="help">Machine credentials. The key is shown once; only its hash is stored.</p>
        <form id="fkey" class="row"><div class="field"><label>Name</label><input name="name" placeholder="legacy-connector" required></div>
          <div class="field"><label class="check"><input type="checkbox" name="w" checked> events:write</label><label class="check"><input type="checkbox" name="r"> events:read</label></div>
          <div class="field"><button class="btn primary">Create key</button></div></form><div id="keys"></div></div>
      <div class="card"><h2>3. Reconciliations</h2><p class="help">Upstream sends its current records; we compare them with the evidence we hold. Discrepancies raise an RC001 alert.</p>
        <div id="recons"></div></div>
      <div class="card"><h2>4. File upload (CSV)</h2>
        <p class="help">For systems that can only export files. The CSV needs an <code>external_id</code> column; every other column is a field.
          <b>Import</b> records only what changed since the last file. <b>Reconcile</b> only compares and records nothing.</p>
        <form id="fup"><div class="row">
          <div class="field"><label>Source</label><select name="source" id="up-source" required></select></div>
          <div class="field"><label>Entity</label><input name="entity" value="product" required pattern="[a-z][a-z0-9_]{0,29}"></div>
          <div class="field"><label>CSV file</label><input name="file" type="file" accept=".csv,text/csv" required></div></div>
          <div class="row"><div class="field"><label>Action</label><select name="mode">
            <option value="import">Import changes as events</option><option value="reconcile">Reconcile only</option></select></div>
          <div class="field"><label class="check"><input type="checkbox" name="complete"> Complete snapshot (missing rows = deleted / unexpected)</label>
            <label class="check"><input type="checkbox" name="dry_run" checked> Dry run (import preview, nothing saved)</label></div>
          <div class="field"><button class="btn primary">Upload</button></div></div></form>
        <p class="help">Example: <code>external_id,name,price</code> then <code>SKU-1,Keyboard,80.00</code></p></div>
      <div class="card"><h2>Endpoints</h2><div class="kv">
        <div class="k">POST /api/v1/events</div><div>One CloudEvent. Idempotent on <code>source</code> + <code>id</code>.</div>
        <div class="k">POST /api/v1/events:batch</div><div>Up to 500 events; per-event result.</div>
        <div class="k">GET /api/v1/ingested-events</div><div>Read back (scope <code>events:read</code>), cursor pagination.</div>
        <div class="k">POST /api/v1/reconciliations</div><div>Snapshot comparison: MISMATCH / MISSING / UNEXPECTED.</div>
        <div class="k">POST /api/v1/imports</div><div>CSV snapshot → only the changes become events (with <code>dry_run</code>).</div>
        <div class="k">POST /api/v1/reconciliations/upload</div><div>Reconcile a CSV snapshot.</div>
        <div class="k">Docs</div><div><a href="/docs#/ingestion" target="_blank" rel="noopener">OpenAPI reference</a> · errors are RFC 9457 · webhooks follow Standard Webhooks</div></div></div>`;

    $("#fsrc", view).addEventListener("submit", async (e) => {
      e.preventDefault();
      if (await guarded(() => api("POST", "/sources", formData(e.target)), "Source registered")) { e.target.reset(); loadSources(); }
    });
    $("#fkey", view).addEventListener("submit", async (e) => {
      e.preventDefault();
      const scopes = [e.target.w.checked && "events:write", e.target.r.checked && "events:read"].filter(Boolean);
      const res = await guarded(() => api("POST", "/api-keys", { name: e.target.name.value, scopes }));
      if (!res) return;
      modal("API key created", `<p>Copy this key now. It will not be shown again.</p><div class="secret">${esc(res.api_key)}</div>
        <h3 class="mt">Try it</h3><pre class="json">${esc(curl(res.api_key))}</pre>`, { wide: true });
      e.target.reset(); e.target.w.checked = true; loadKeys();
    });
    on(view, "click", "[data-revoke]", async (e, b) => {
      if (!confirm("Revoke this key? Systems using it will stop working immediately.")) return;
      if (await guarded(() => api("DELETE", `/api-keys/${b.dataset.revoke}`).then(() => true), "Key revoked")) loadKeys();
    });
    on(view, "click", "[data-src-toggle]", async (e, b) => {
      if (await guarded(() => api("PATCH", `/sources/${b.dataset.srcToggle}`, { status: b.dataset.to }))) loadSources();
    });
    on(view, "click", "[data-src-events]", async (e, b) => {
      const rows = await guarded(() => api("GET", `/sources/${b.dataset.srcEvents}/events`));
      if (!rows) return;
      const body = modal("Received events", table([
        { h: "#", f: (r) => esc(r.event_pk) }, { h: "Event ID", f: (r) => `<span class="mono">${esc(r.id)}</span>` },
        { h: "Type", f: (r) => badge(r.type, "info") }, { h: "Subject", f: (r) => esc(r.subject) },
        { h: "Occurred", f: (r) => esc(when(r.occurred_at)) }, { h: "Received", f: (r) => esc(when(r.received_at)) },
        { h: "", f: (r) => `<a href="#" data-history="external_event|${r.event_pk}">evidence</a>` },
      ], rows, { empty: "No events received yet." }), { wide: true });
      body.insertAdjacentHTML("afterbegin", `<p class="help">"evidence" shows the hash-chained audit record of each event.</p>`);
    });
    on(view, "click", "[data-recon]", async (e, tr) => {
      const r = await guarded(() => api("GET", `/reconciliations/${tr.dataset.recon}`));
      if (!r) return;
      const detail = (i) => i.details.differences
        ? `<ul class="diff">${i.details.differences.map((d) => `<li>${esc(d.field)}: upstream <span class="new">${esc(val(d.upstream))}</span>, recorded <span class="old">${esc(val(d.recorded))}</span></li>`).join("")}</ul>`
        : `<span class="help">${esc(i.details.reason)}</span>`;
      modal(`Reconciliation #${r.recon_id}`, `<div class="kv"><div class="k">Source / entity</div><div>${esc(r.source)} / ${esc(r.entity)}</div>
        <div class="k">As of</div><div>${esc(when(r.as_of))}</div><div class="k">Complete snapshot</div><div>${r.complete === "Y" ? "yes" : "no"}</div>
        <div class="k">Result</div><div>${fmtNum(r.matched)} of ${fmtNum(r.total_records)} matched</div></div>
        <h3 class="mt">Discrepancies</h3>${table([
          { h: "External ID", f: (i) => `<span class="mono">${esc(i.external_id)}</span>` },
          { h: "Outcome", f: (i) => badge(i.outcome, i.outcome === "MISMATCH" ? "warn" : "bad") }, { h: "Detail", f: detail },
        ], r.issues, { empty: "None — everything matched." })}`, { wide: true });
    });
    $("#fup", view).addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      const reconcileOnly = f.mode.value === "reconcile";
      const form = new FormData();
      form.append("file", f.file.files[0]);
      form.append("source", f.source.value);
      form.append("entity", f.entity.value.trim());
      form.append("complete", f.complete.checked ? "true" : "false");
      if (!reconcileOnly) form.append("dry_run", f.dry_run.checked ? "true" : "false");
      const res = await guarded(() => upload(reconcileOnly ? "/reconciliations/upload" : "/imports", form));
      if (!res) return;
      if (reconcileOnly) {
        loadRecons();
        refreshCounts();
        modal(`Reconciliation #${res.recon_id}`, `<div class="summary">${fmtNum(res.matched)} of ${fmtNum(res.total_records)} matched ·
          ${fmtNum(res.mismatched)} mismatched · ${fmtNum(res.missing)} missing · ${fmtNum(res.unexpected)} unexpected</div>${table([
          { h: "External ID", f: (i) => `<span class="mono">${esc(i.external_id)}</span>` },
          { h: "Outcome", f: (i) => badge(i.outcome, i.outcome === "MISMATCH" ? "warn" : "bad") },
          { h: "Detail", f: (i) => i.details.differences ? `<ul class="diff">${i.details.differences.map((d) => `<li>${esc(d.field)}: file <span class="new">${esc(val(d.upstream))}</span>, recorded <span class="old">${esc(val(d.recorded))}</span></li>`).join("")}</ul>` : `<span class="help">${esc(i.details.reason)}</span>` },
        ], res.issues, { empty: "Everything matched." })}`, { wide: true });
        return;
      }
      const verb = { created: "ok", updated: "warn", deleted: "bad" };
      const diff = (c) => c.change === "updated"
        ? `<ul class="diff">${c.changed_fields.map((k) => `<li>${esc(k)}: <span class="old">${esc(val(c.before[k]))}</span> → <span class="new">${esc(val(c.after[k]))}</span></li>`).join("")}</ul>`
        : c.change === "created" ? `<span class="help">${esc(Object.entries(c.after).map(([k, v]) => `${k}=${val(v)}`).join(", "))}</span>` : `<span class="help">absent from file</span>`;
      modal(res.dry_run ? "Import preview (nothing saved)" : "Import complete", `<div class="summary">${res.dry_run ? "Would record" : "Recorded"}:
        ${fmtNum(res.created)} created · ${fmtNum(res.updated)} updated · ${fmtNum(res.deleted)} deleted · ${fmtNum(res.unchanged)} unchanged
        <div class="help">Source trust: ${esc(res.trust_level)} (${esc(res.capture_method)})</div></div>${table([
        { h: "External ID", f: (c) => `<span class="mono">${esc(c.external_id)}</span>` },
        { h: "Change", f: (c) => badge(c.change, verb[c.change]) }, { h: "Detail", f: diff },
        { h: "", f: (c) => c.event_pk ? `<a href="#" data-history="external_event|${c.event_pk}">evidence</a>` : "" },
      ], res.changes, { empty: "No changes since the last import." })}
        ${res.dry_run && (res.created + res.updated + res.deleted) ? `<p><button class="btn primary" id="commit-import">Import for real</button></p>` : ""}`, { wide: true });
      $("#commit-import")?.addEventListener("click", () => { f.dry_run.checked = false; closeModal(); f.requestSubmit(); });
      if (!res.dry_run) loadSources();
    });
    await Promise.all([loadSources(), loadKeys(), loadRecons()]);
  }

  route();
})();
