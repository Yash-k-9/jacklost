// Shared helpers for every Juice Guard page.
// The pages are served by the backend itself, so the login cookie (httpOnly) is sent
// automatically with every fetch. Page scripts never see the token.

const $ = id => document.getElementById(id);

// Escape anything that came from the server before putting it into innerHTML.
function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// fetch wrapper: JSON in/out, readable error messages, 401 -> login page.
async function api(path, { method = "GET", body, redirectOn401 = true } = {}) {
  const opts = { method, cache: "no-store", credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let r;
  try { r = await fetch(path, opts); }
  catch { throw new ApiError(0, "Cannot reach the server. Is the backend running?"); }

  if (r.status === 401 && redirectOn401) {
    location.href = "login.html?next=" + encodeURIComponent(location.pathname.replace(/^\//, "") + location.search);
    throw new ApiError(401, "Not logged in");
  }
  if (r.status === 204) return null;
  const data = await r.json().catch(() => null);
  if (!r.ok) {
    let d = data && data.detail;
    if (Array.isArray(d)) d = d.map(x => (typeof x === "string" ? x : x.msg)).join("; ");
    throw new ApiError(r.status, d || `HTTP ${r.status}`);
  }
  return data;
}

// Server stores naive UTC timestamps (no "Z").
const parseTs = s => (s ? new Date(/[zZ]|[+-]\d\d:\d\d$/.test(s) ? s : s + "Z") : null);
const fmtTs = s => (s ? parseTs(s).toLocaleString() : "–");

function ago(sec) {
  if (sec == null) return "never";
  if (sec < 60) return Math.round(sec) + " s ago";
  if (sec < 3600) return Math.round(sec / 60) + " min ago";
  if (sec < 86400) return Math.round(sec / 3600) + " h ago";
  return Math.round(sec / 86400) + " days ago";
}

function stateClass(state) {
  return { CHARGING: "ok", IDLE: "ok", NO_SUPPLY: "warn", UNKNOWN: "", OFFLINE: "bad", ALERT: "bad", TAMPER: "bad" }[state] ?? "warn";
}
const statePill = s => `<span class="pill ${stateClass(s)}">${esc(s)}</span>`;

function showMsg(el, text, ok = false) {
  el.textContent = text || "";
  el.className = "msg " + (text ? (ok ? "ok" : "err") : "");
}

// Big red box at the top of the page for problems that stop the page from working.
function showFatal(text) {
  let box = $("fatal");
  if (!box) {
    box = document.createElement("div");
    box.id = "fatal";
    box.style.cssText = "max-width:960px;margin:16px auto;padding:14px 16px;border-radius:10px;" +
      "background:var(--card);border:1px solid var(--bad);border-left:6px solid var(--bad);overflow-wrap:anywhere";
    document.body.prepend(box);
  }
  box.innerHTML = `<b>Can't load the portal</b><div class="muted" style="margin-top:4px">${esc(text)}</div>`;
}

// Checks the login, draws the top bar and returns the current user.
// adminOnly: hosts are sent back to the stations page.
async function requireLogin({ adminOnly = false, active = "" } = {}) {
  let me;
  try {
    me = await api("/api/auth/me");
  } catch (e) {
    if (e.status !== 401) showFatal(e.status === 404
      ? "The backend running on this port is an old version without logins (/api/auth is missing). " +
        "Stop it (Ctrl+C) and start it again from the backend folder: " +
        "..\\.venv\\Scripts\\python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
      : e.message);
    throw e;
  }
  if (adminOnly && me.role !== "admin") { location.href = "index.html"; throw new Error("admins only"); }

  const links = [["index.html", "Stations", "stations"]];
  if (me.role === "admin") links.push(["admin.html", "Admin", "admin"]);
  links.push(["account.html", "Account", "account"]);

  const bar = document.createElement("header");
  bar.className = "topbar";
  bar.innerHTML = `<div class="in">
      <a class="brand" href="index.html">⚡ Juice Guard</a>
      <nav>${links.map(([href, label, key]) => `<a href="${href}" class="${key === active ? "on" : ""}">${label}</a>`).join("")}</nav>
      <span class="who">${esc(me.full_name)} <span class="role">${esc(me.role)}</span></span>
      <button id="logoutBtn">Log out</button>
    </div>`;
  document.body.prepend(bar);
  $("logoutBtn").onclick = async () => {
    await api("/api/auth/logout", { method: "POST", redirectOn401: false }).catch(() => {});
    location.href = "login.html";
  };
  return me;
}
