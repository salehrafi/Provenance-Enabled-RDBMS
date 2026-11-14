// Application shell: authentication, navigation, router.
import { h, icon, get, post, state, can, toast, fail, ApiError, refreshSession, errorBox, loading, field, input, navigate, badge } from "./lib.js";
import * as core from "./views_core.js";
import * as prov from "./views_prov.js";
import * as admin from "./views_admin.js";

const NAV = [
  ["Overview", [["/", "Dashboard", "home", null]]],
  ["Data", [["/orders", "Orders", "cart", "orders:read"], ["/customers", "Customers", "users", "catalog:read"], ["/products", "Products", "tag", "catalog:read"]]],
  ["Provenance", [["/explorer", "Explorer", "clock", "audit:read"], ["/audit", "Audit & integrity", "shield", "audit:read"]]],
  ["Govern", [["/alerts", "Alerts", "bell", "alerts:read"], ["/approvals", "Approvals", "check", "approvals:read"]]],
  ["Connect", [["/integrations", "Integrations", "plug", "sources:read"], ["/webhooks", "Webhooks", "webhook", "webhooks:manage"]]],
  ["Organization", [["/team", "Team", "users", "users:manage"], ["/activity", "Activity log", "list", "activity:read"], ["/settings", "Settings", "settings", "settings:read"]]],
];

const ROUTES = [
  ["/", "Dashboard", core.dashboard], ["/orders", "Orders", core.orders], ["/orders/:id", "Order", core.orderDetail],
  ["/customers", "Customers", core.customers], ["/products", "Products", core.products],
  ["/explorer", "Explorer", prov.explorer], ["/explorer/:entity/:pk", "Explorer", prov.explorer],
  ["/audit", "Audit & integrity", prov.audit], ["/alerts", "Alerts", admin.alerts], ["/approvals", "Approvals", admin.approvals],
  ["/integrations", "Integrations", admin.integrations], ["/integrations/:tab", "Integrations", admin.integrations],
  ["/webhooks", "Webhooks", admin.webhooks], ["/team", "Team", admin.team], ["/activity", "Activity log", admin.activity], ["/settings", "Settings", admin.settings],
];

const app = document.getElementById("app");
let badgeTimer = 0;

function match(path) {
  for (const [pattern, title, view] of ROUTES) {
    const keys = [];
    const re = new RegExp("^" + pattern.replace(/:([a-z]+)/g, (_, k) => { keys.push(k); return "([^/]+)"; }) + "/?$");
    const m = re.exec(path);
    if (m) return { title, view, params: Object.fromEntries(keys.map((k, i) => [k, decodeURIComponent(m[i + 1])])) };
  }
  return null;
}

function currentPath() {
  const [path, query] = (location.hash.slice(1) || "/").split("?");
  return { path, query: Object.fromEntries(new URLSearchParams(query || "")) };
}

// ---------------------------------------------------------------- auth screens
function authScreen(mode = "login") {
  const err = h("div", { class: "alert bad", role: "alert", hidden: true });
  const email = input({ type: "email", required: true, autocomplete: "username", placeholder: "you@company.com" });
  const password = input({ type: "password", required: true, autocomplete: mode === "login" ? "current-password" : "new-password", minlength: mode === "login" ? null : "6" });
  const org = input({ required: true, minlength: "2", maxlength: "120", placeholder: "Acme Retail", autocomplete: "organization" });
  const name = input({ required: true, minlength: "2", maxlength: "120", autocomplete: "name" });
  const submit = h("button", { class: "btn primary", type: "submit", style: "width:100%" }, mode === "login" ? "Sign in" : "Create organization");
  const form = h("form", { class: "form", onsubmit: async (e) => {
    e.preventDefault(); err.hidden = true; submit.disabled = true;
    try {
      const body = mode === "login" ? { email: email.value, password: password.value }
        : { organization: org.value, full_name: name.value, email: email.value, password: password.value };
      const r = await post(mode === "login" ? "/auth/login" : "/auth/signup", body, { noRefresh: true });
      state.token = r.access_token; state.me = r.user;
      navigate("/"); boot();
    } catch (x) {
      err.hidden = false; err.textContent = x instanceof ApiError ? x.message : "Could not reach the server.";
      submit.disabled = false;
    }
  } },
  mode === "signup" && field("Organization", org, "Your workspace. You become its first admin."),
  mode === "signup" && field("Your name", name),
  field("Work email", email),
  field("Password", password, mode === "signup" ? "At least 6 characters." : null),
  err, submit);
  const alt = h("p", { class: "small muted" }, mode === "login" ? "New here? " : "Already have an account? ",
    h("a", { href: "#", onclick: (e) => { e.preventDefault(); authScreen(mode === "login" ? "signup" : "login"); } }, mode === "login" ? "Create an organization" : "Sign in"));
  app.replaceChildren(h("main", { class: "auth", id: "main" },
    h("section", { class: "auth-hero" },
      h("div", { class: "brand" }, h("div", { class: "logo", "aria-hidden": "true" }, "◆"), "Provenance Cloud"),
      h("h1", null, "Know why every number is what it is."),
      h("ul", null,
        h("li", null, "Every change is recorded in a tamper-evident hash chain, with signed checkpoints you can keep."),
        h("li", null, "Rebuild any record as it was at any moment, and see who changed it, when and why."),
        h("li", null, "Connect any system with CloudEvents. Reconcile it against what it claims today."))),
    h("section", { class: "auth-form" }, h("div", { class: "auth-card" },
      h("div", null, h("h1", null, mode === "login" ? "Sign in" : "Create your organization"),
        h("p", { class: "muted", style: "margin-top:4px" }, mode === "login" ? "Welcome back." : "Free to start. No card needed.")),
      form, alt))));
  email.focus();
}

// ---------------------------------------------------------------- shell
const THEME_KEY = "prov-theme";
function applyTheme(t) {
  if (t === "dark") document.documentElement.dataset.theme = "dark"; else delete document.documentElement.dataset.theme;
}
function currentTheme() { try { return localStorage.getItem(THEME_KEY) === "dark" ? "dark" : "light"; } catch { return "light"; } }
function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  try { localStorage.setItem(THEME_KEY, next); } catch { /* private mode: applies for this page only */ }
  applyTheme(next);
}
applyTheme(currentTheme());

function shell() {
  let side, veil;
  const closeNav = () => { side.classList.remove("open"); veil.classList.remove("open"); document.getElementById("menu-btn")?.setAttribute("aria-expanded", "false"); };
  const toggleNav = () => { const open = side.classList.toggle("open"); veil.classList.toggle("open", open); document.getElementById("menu-btn").setAttribute("aria-expanded", String(open)); };
  const brand = () => h("div", { class: "brand" }, h("div", { class: "logo", "aria-hidden": "true" }, "◆"), "Provenance Cloud");
  side = h("aside", { class: "side", id: "side", "aria-label": "Primary" },
    brand(),
    h("nav", { class: "nav" }, NAV.map(([group, items]) => {
      const visible = items.filter(([, , , perm]) => !perm || can(perm));
      return visible.length ? [h("div", { class: "nav-group" }, group), visible.map(([path, label, ico]) =>
        h("a", { href: "#" + path, dataset: { path }, onclick: closeNav }, icon(ico, 17), label,
          path === "/alerts" && h("span", { class: "count", id: "cnt-alerts", hidden: true }),
          path === "/approvals" && h("span", { class: "count", id: "cnt-approvals", hidden: true })))] : null;
    })),
    h("div", { class: "side-foot" },
      h("div", { class: "who" }, state.me.full_name), h("div", { style: "overflow:hidden;text-overflow:ellipsis" }, state.me.email),
      h("div", null, `${state.me.tenant.name} · `, badge(state.me.role, state.me.role === "admin" ? "info" : "")),
      h("div", { class: "row" },
        h("a", { href: "/docs", target: "_blank", rel: "noopener" }, "API docs"), "·",
        h("a", { href: "#", onclick: (e) => { e.preventDefault(); signOut(); } }, "Sign out"),
        h("button", { class: "btn sm theme-btn", style: "margin-left:auto", title: "Switch light/dark", "aria-label": "Switch between light and dark theme", onclick: toggleTheme }, "◐"))));
  veil = h("div", { class: "scrim-nav", onclick: closeNav });
  const crumbs = h("div", { class: "crumbs", id: "crumbs" });
  const top = h("header", { class: "top" },
    h("button", { class: "menu-btn", id: "menu-btn", "aria-label": "Open menu", "aria-controls": "side", "aria-expanded": "false", onclick: toggleNav }, icon("menu", 20)),
    brand(), h("div", { class: "grow" }), crumbs);
  const main = h("main", { class: "page", id: "main", tabindex: "-1" });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeNav(); });
  app.replaceChildren(h("a", { class: "skip", href: "#main" }, "Skip to content"),
    h("div", { class: "app" }, side, veil, h("div", { class: "main" }, top, main)));
  return main;
}

async function refreshBadges() {
  clearTimeout(badgeTimer);
  try {
    const d = await get("/dashboard");
    state.currency = d.currency;
    const set = (id, n) => { const el = document.getElementById(id); if (el) { el.hidden = !n; el.textContent = n; } };
    set("cnt-alerts", d.counts.open_alerts); set("cnt-approvals", d.counts.pending_approvals);
  } catch { /* badges are a convenience */ }
  badgeTimer = setTimeout(refreshBadges, 60_000);
}

let renderToken = 0;
async function route() {
  if (!state.me) return;
  const main = document.getElementById("main");
  if (!main) return;
  const { path, query } = currentPath();
  const m = match(path);
  const mine = ++renderToken;
  for (const a of document.querySelectorAll(".nav a")) {
    const p = a.dataset.path;
    a.toggleAttribute("aria-current", p === "/" ? path === "/" : path === p || path.startsWith(p + "/"));
    if (a.hasAttribute("aria-current")) a.setAttribute("aria-current", "page");
  }
  if (!m) { main.replaceChildren(h("div", { class: "card" }, h("div", { class: "empty" }, h("h3", null, "Page not found"), h("a", { href: "#/" }, "Back to dashboard")))); return; }
  document.title = `${m.title} · Provenance Cloud`;
  document.getElementById("crumbs").textContent = m.title;
  main.replaceChildren(h("div", { class: "card" }, loading(5)));
  try {
    const node = await m.view(m.params, query);
    if (mine !== renderToken) return;
    main.replaceChildren(node);
    main.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  } catch (e) {
    if (mine !== renderToken) return;
    main.replaceChildren(errorBox(e));
  }
}
async function signOut() {
  try { await post("/auth/logout", {}, { noRefresh: true }); } catch { /* cookie is cleared server-side either way */ }
  state.token = null; state.me = null; clearTimeout(badgeTimer);
  authScreen("login");
}

async function boot() {
  if (!state.me && !(await refreshSession())) return authScreen("login");
  shell();
  await route();
  refreshBadges();
}

state.listeners.add((ev) => { if (ev === "signed-out" && state.me) { state.me = null; toast("Your session ended. Please sign in again."); authScreen("login"); } });
window.addEventListener("hashchange", route);
window.addEventListener("unhandledrejection", (e) => { fail(e.reason); });
boot();
