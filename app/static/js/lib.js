// UI toolkit: DOM builder, API client, formatting, and shared components.
// Nothing here uses innerHTML: every value is inserted as text, so API data cannot inject markup.

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "dataset") Object.assign(el.dataset, v);
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (v === true) el.setAttribute(k, "");
      else el.setAttribute(k, v);
    }
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

// replaceChildren() turns `false`/`null` into the text "false"/"null". Conditional children such as
// `cond && node` are idiomatic in this code base, so drop empty values here once instead of at every call site.
{
  const nativeReplace = Element.prototype.replaceChildren;
  Element.prototype.replaceChildren = function (...nodes) { return nativeReplace.apply(this, nodes.flat().filter((n) => n != null && n !== false)); };
}

const SVG_NS = "http://www.w3.org/2000/svg";
export function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null) el.setAttribute(k, v);
  append(el, children);
  return el;
}

const ICONS = {
  home: "M3 11l9-8 9 8M5 10v10h5v-6h4v6h5V10",
  box: "M21 8l-9-5-9 5v8l9 5 9-5V8zM3 8l9 5 9-5M12 13v8",
  users: "M16 20v-1a4 4 0 00-4-4H6a4 4 0 00-4 4v1M9 11a4 4 0 100-8 4 4 0 000 8zM22 20v-1a4 4 0 00-3-3.9M16 3.1a4 4 0 010 7.8",
  tag: "M20 12l-8 8-9-9V3h8l9 9zM7.5 7.5h.01",
  cart: "M3 4h2l2.4 11h11l2-8H6M9 20a1 1 0 100-2 1 1 0 000 2zM18 20a1 1 0 100-2 1 1 0 000 2z",
  clock: "M12 21a9 9 0 100-18 9 9 0 000 18zM12 7v5l3 2",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3zM9 12l2 2 4-4",
  list: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  plug: "M9 2v6M15 2v6M6 8h12v4a6 6 0 01-12 0V8zM12 18v4",
  check: "M5 13l4 4L19 7",
  bell: "M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 01-3.4 0",
  webhook: "M10 14a4 4 0 117 2h3M8 18a4 4 0 110-8M14 6a4 4 0 00-4 4M5 8l3 3",
  settings: "M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z",
  search: "M11 19a8 8 0 100-16 8 8 0 000 16zM21 21l-4.3-4.3",
  plus: "M12 5v14M5 12h14",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  x: "M18 6L6 18M6 6l12 12",
  alert: "M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z",
  menu: "M3 12h18M3 6h18M3 18h18",
  file: "M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9l-6-6zM14 3v6h6",
  link: "M10 13a5 5 0 007 0l3-3a5 5 0 00-7-7l-1 1M14 11a5 5 0 00-7 0l-3 3a5 5 0 007 7l1-1",
  logout: "M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9",
  diff: "M12 3v18M5 8h4M7 6v4M15 16h4",
  lock: "M6 11V8a6 6 0 1112 0v3M5 11h14v10H5z",
  refresh: "M21 12a9 9 0 11-3-6.7L21 8M21 3v5h-5",
  download: "M12 3v12M7 10l5 5 5-5M4 21h16",
  graph: "M6 6a2 2 0 100-4 2 2 0 000 4zM18 6a2 2 0 100-4 2 2 0 000 4zM12 22a2 2 0 100-4 2 2 0 000 4zM6 6v4a4 4 0 004 4h4a4 4 0 004-4V6M12 14v4",
};

export function icon(name, size = 18) {
  const el = svg("svg", { viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor",
    "stroke-width": "1.8", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" },
    svg("path", { d: ICONS[name] || ICONS.box }));
  return el;
}

// ---------------------------------------------------------------- state & API
export const state = { token: null, me: null, listeners: new Set() };
let refreshing = null;

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.detail || `HTTP ${status}`);
    this.status = status; this.code = body?.code; this.body = body || {};
  }
}

async function refreshSession() {
  // Two tabs (or a reload during a rotation) can present the same refresh token within seconds. The server
  // answers 409 TOKEN_ROTATED and the browser already holds the winner's cookie, so retry instead of signing out.
  const attempt = async (tries) => {
    const r = await fetch("/api/v1/auth/refresh", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}", credentials: "same-origin" });
    if (r.status === 409 && tries > 0) { await new Promise((res) => setTimeout(res, 400)); return attempt(tries - 1); }
    if (!r.ok) return false;
    const b = await r.json();
    state.token = b.access_token; state.me = b.user;
    return true;
  };
  refreshing ??= attempt(3).catch(() => false).finally(() => { refreshing = null; });
  return refreshing;
}
export { refreshSession };

export async function api(method, path, body, opts = {}) {
  const run = async () => {
    const headers = { Accept: "application/json" };
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    let payload;
    if (body instanceof FormData) payload = body;
    else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
    if (opts.idempotent) headers["Idempotency-Key"] = crypto.randomUUID();
    let url = "/api/v1" + path;
    if (opts.params) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.params)) if (v !== undefined && v !== null && v !== "") q.set(k, v);
      if ([...q].length) url += "?" + q;
    }
    return fetch(url, { method, headers, body: payload, credentials: "same-origin" });
  };
  let r = await run();
  if (r.status === 401 && !opts.noRefresh && state.token && await refreshSession()) r = await run();
  if (r.status === 401 && !opts.noRefresh) { state.token = null; state.listeners.forEach((f) => f("signed-out")); }
  if (opts.raw) return r;
  if (r.status === 204) return null;
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new ApiError(r.status, typeof data === "object" ? data : { detail: data });
  return data;
}
export const get = (p, params) => api("GET", p, undefined, { params });
export const post = (p, b, o) => api("POST", p, b ?? {}, o);
export const patch = (p, b) => api("PATCH", p, b);
export const del = (p) => api("DELETE", p);

export function can(permission) { return !!state.me?.permissions?.includes(permission); }

// ---------------------------------------------------------------- formatting
const dtf = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
export const fmt = {
  date: (v) => (v ? dtf.format(new Date(v)) : "–"),
  ago(v) {
    if (!v) return "–";
    const s = (Date.now() - new Date(v).getTime()) / 1000;
    if (s < 45) return "just now";
    for (const [n, u] of [[60, "minute"], [3600, "hour"], [86400, "day"]]) {
      if (s < n * (u === "minute" ? 60 : u === "hour" ? 24 : 30)) return new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(-Math.round(s / n), u);
    }
    return fmt.date(v);
  },
  money(v, cur) {
    if (v == null) return "–";
    try { return new Intl.NumberFormat(undefined, { style: "currency", currency: cur || state.currency || "USD" }).format(Number(v)); }
    catch { return String(v); }
  },
  n: (v) => (v == null ? "–" : new Intl.NumberFormat().format(Number(v))),
  short: (s, n = 10) => (s && s.length > n ? s.slice(0, n) + "…" : s ?? ""),
  value(v) { return v === null || v === undefined ? "∅" : typeof v === "object" ? JSON.stringify(v) : String(v); },
};

export function toLocalInput(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// ---------------------------------------------------------------- components
const TONE = { OPEN: "bad", ACKNOWLEDGED: "warn", RESOLVED: "ok", CRITICAL: "bad", HIGH: "bad", MEDIUM: "warn", LOW: "info",
  CREATED: "info", PAID: "ok", SHIPPED: "brand", DELIVERED: "ok", CANCELLED: "plain", REFUNDED: "warn",
  PENDING: "warn", APPROVED: "ok", REJECTED: "bad", ACTIVE: "ok", PAUSED: "warn", SUCCESS: "ok", FAILED: "warn", DEAD: "bad",
  INSERT: "ok", UPDATE: "info", DELETE: "bad", MISMATCH: "warn", MISSING: "bad", UNEXPECTED: "info", CAPTURED: "ok", VOID: "plain" };
export const badge = (text, tone) => h("span", { class: `badge ${tone ?? TONE[text] ?? ""}` }, text);
export const hash = (s, n = 12) => (s ? h("span", { class: "hash", title: s }, s.slice(0, n)) : "–");

export function toast(msg, tone = "") {
  const root = document.getElementById("toasts");
  const t = h("div", { class: `toast ${tone}`, role: tone === "bad" ? "alert" : "status" }, msg);
  root.append(t);
  setTimeout(() => t.remove(), tone === "bad" ? 7000 : 3500);
}
export function fail(e) { toast(e instanceof ApiError ? e.message : "Something went wrong. Please try again.", "bad"); if (!(e instanceof ApiError)) console.error(e); }

export async function copy(text, label = "Copied") {
  try { await navigator.clipboard.writeText(text); toast(label, "ok"); } catch { toast("Copy failed. Select the text and copy it manually.", "bad"); }
}

export function loading(rows = 4) {
  return h("div", { class: "card-b stack", role: "status", "aria-label": "Loading" },
    Array.from({ length: rows }, (_, i) => h("div", { class: "skeleton", style: `width:${90 - i * 12}%` })));
}

export function empty(title, text, action, ico = "box") {
  return h("div", { class: "empty" }, h("div", { class: "ico" }, icon(ico, 44)), h("h3", null, title), text && h("p", null, text), action);
}

export function errorBox(e) {
  return h("div", { class: "alert bad", role: "alert" }, icon("alert"), h("div", null, h("strong", null, e instanceof ApiError && e.status === 403 ? "Not allowed. " : "Could not load. "), e.message));
}

export function card(title, body, { actions, flush = false, sub } = {}) {
  return h("section", { class: "card" },
    (title || actions) && h("div", { class: "card-h" }, h("div", { class: "grow" }, h("h2", null, title), sub && h("div", { class: "small muted" }, sub)), actions),
    h("div", { class: `card-b ${flush ? "flush" : ""}` }, body));
}

export function pageHead(title, desc, actions) {
  return h("div", { class: "page-head" }, h("div", { class: "grow" }, h("h1", null, title), desc && h("p", null, desc)), actions && h("div", { class: "row" }, actions));
}

export function stat(label, value, sub, ico) {
  return h("div", { class: "card stat" }, h("div", { class: "label" }, ico && icon(ico, 15), label), h("div", { class: "value" }, value), sub && h("div", { class: "sub" }, sub));
}

export function table(cols, rows, { onRow, empty: emptyNode, caption } = {}) {
  if (!rows.length && emptyNode) return emptyNode;
  return h("div", { class: "tbl-wrap" }, h("table", null,
    caption && h("caption", { class: "sr" }, caption),
    h("thead", null, h("tr", null, cols.map((c) => h("th", { class: c.right ? "r" : "", scope: "col" }, c.label)))),
    h("tbody", null, rows.map((r) => {
      const tr = h("tr", { class: onRow ? "click" : "", tabindex: onRow ? "0" : null }, cols.map((c) => h("td", { class: c.right ? "r" : "" }, c.render ? c.render(r) : r[c.key])));
      if (onRow) {
        tr.addEventListener("click", (e) => { if (!e.target.closest("button, a, input, select")) onRow(r); });
        tr.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target === tr) onRow(r); });
      }
      return tr;
    }))));
}

export function field(label, input, hint) {
  const id = "f" + Math.random().toString(36).slice(2, 8);
  input.id = id;
  return h("div", { class: "field" }, h("label", { for: id }, label), input, hint && h("div", { class: "hint" }, hint));
}
export const input = (attrs) => h("input", attrs);
export const select = (options, value, attrs) => {
  const s = h("select", attrs, options.map((o) => { const [v, l] = Array.isArray(o) ? o : [o, o]; return h("option", { value: v, selected: v === value }, l); }));
  return s;
};

export function modal(title, body, { wide = false, footer, onClose } = {}) {
  const root = document.getElementById("modal-root");
  const previous = document.activeElement;
  const close = () => { scrim.remove(); document.removeEventListener("keydown", onKey); previous?.focus?.(); onClose?.(); };
  const onKey = (e) => {
    if (e.key === "Escape") close();
    if (e.key === "Tab") {
      const f = [...dialog.querySelectorAll("button, input, select, textarea, a[href]")].filter((x) => !x.disabled);
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  };
  const dialog = h("div", { class: `modal ${wide ? "wide" : ""}`, role: "dialog", "aria-modal": "true", "aria-label": title },
    h("div", { class: "modal-h" }, h("h2", null, title)), h("div", { class: "modal-b" }, body),
    footer && h("div", { class: "modal-f" }, footer(close)));
  const scrim = h("div", { class: "scrim" }, dialog);
  scrim.addEventListener("mousedown", (e) => { if (e.target === scrim) close(); });
  root.append(scrim);
  document.addEventListener("keydown", onKey);
  (dialog.querySelector("input, select, textarea") || dialog.querySelector("button"))?.focus();
  return close;
}

export function confirmDialog(title, text, confirmLabel = "Confirm", danger = false) {
  return new Promise((resolve) => {
    modal(title, h("p", null, text), {
      onClose: () => resolve(false),
      footer: (close) => [
        h("button", { class: "btn", onclick: close }, "Cancel"),
        h("button", { class: `btn ${danger ? "danger" : "primary"}`, onclick: () => { resolve(true); close.call(null); } }, confirmLabel)],
    });
  });
}

/** A form dialog: `fields` is an array of Nodes; `submit(close)` must throw to keep it open. */
export function formDialog(title, fields, submitLabel, submit, { wide = false } = {}) {
  const form = h("form", { class: "form", novalidate: false }, fields);
  const err = h("div", { class: "alert bad", role: "alert", hidden: true });
  form.append(err);
  let closeFn;
  const go = async (e) => {
    e?.preventDefault();
    if (!form.reportValidity()) return;
    btn.disabled = true; err.hidden = true;
    try { await submit(closeFn); } catch (x) { err.hidden = false; err.textContent = x instanceof ApiError ? x.message : "Unexpected error"; btn.disabled = false; if (!(x instanceof ApiError)) console.error(x); }
  };
  const btn = h("button", { class: "btn primary", type: "button", onclick: go }, submitLabel);
  form.addEventListener("submit", go);
  closeFn = modal(title, form, { wide, footer: (close) => { closeFn = close; return [h("button", { class: "btn", type: "button", onclick: close }, "Cancel"), btn]; } });
  return closeFn;
}

export function tabs(items, initial, render) {
  const body = h("div");
  const bar = h("div", { class: "tabs", role: "tablist" });
  const show = async (id) => {
    for (const b of bar.children) b.setAttribute("aria-selected", String(b.dataset.id === id));
    body.replaceChildren(loading(3));
    try { body.replaceChildren(await render(id)); } catch (e) { body.replaceChildren(errorBox(e)); }
  };
  for (const [id, label] of items) bar.append(h("button", { role: "tab", dataset: { id }, onclick: () => show(id) }, label));
  show(initial ?? items[0][0]);
  return h("div", null, bar, body);
}

export function diffView(changes) {
  if (!changes?.length) return h("div", { class: "muted small" }, "No field changes");
  return h("div", { class: "diff" }, changes.flatMap((c) => [
    c.old !== undefined && h("div", { class: "del" }, `− ${c.field}: ${fmt.value(c.old)}`),
    h("div", { class: "add" }, `+ ${c.field}: ${fmt.value(c.new)}`)]));
}

export function jsonBlock(v) { return h("pre", { class: "code" }, JSON.stringify(v, null, 2)); }

export function codeBlock(text) {
  return h("div", { style: "position:relative" }, h("pre", { class: "code" }, text),
    h("button", { class: "btn sm", style: "position:absolute;top:8px;right:8px", onclick: () => copy(text) }, icon("copy", 14), "Copy"));
}

export function pager(state_, total, limit, onChange) {
  const from = total ? state_.offset + 1 : 0, to = Math.min(state_.offset + limit, total);
  return h("div", { class: "pager" }, h("span", { class: "grow", style: "flex:1" }, `${from}–${to} of ${fmt.n(total)}`),
    h("button", { class: "btn sm", disabled: state_.offset === 0, onclick: () => onChange(Math.max(0, state_.offset - limit)) }, "Previous"),
    h("button", { class: "btn sm", disabled: to >= total, onclick: () => onChange(state_.offset + limit) }, "Next"));
}

export const debounce = (fn, ms = 250) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

export const navigate = (path) => { location.hash = "#" + path; };
export const rerender = () => window.dispatchEvent(new HashChangeEvent("hashchange"));
