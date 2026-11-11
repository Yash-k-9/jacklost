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
const STATE_LABEL = { CHARGING: "Charging", IDLE: "Idle", NO_SUPPLY: "No power", UNKNOWN: "Waiting",
                      OFFLINE: "Offline", ALERT: "Alert", TAMPER: "Tamper" };
const statePill = s => `<span class="pill ${stateClass(s)}">${esc(STATE_LABEL[s] || s)}</span>`;

// Small inline icons (stroke = currentColor).
const ICON = {
  bolt: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13 2 4 14h7l-1 8 9-12h-7z"/></svg>',
  clock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
  wifi: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M2 8.5a15 15 0 0 1 20 0M5 12a10 10 0 0 1 14 0M8.5 15.5a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1" fill="currentColor"/></svg>',
  pin: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 21s7-6.2 7-12a7 7 0 0 0-14 0c0 5.8 7 12 7 12z"/><circle cx="12" cy="9" r="2.5"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z"/><path d="m9 12 2 2 4-4"/></svg>',
  up: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>',
};

const LOGO = `<span class="logo">${ICON.bolt}</span>`;

function initials(name) {
  const parts = String(name || "?").trim().split(/[\s@._-]+/).filter(Boolean);
  return ((parts[0] || "?")[0] + (parts[1] ? parts[1][0] : "")).toUpperCase();
}
// Stable colour per person, so each host is easy to tell apart.
function avatarColor(key) {
  let h = 0; for (const c of String(key)) h = (h * 31 + c.charCodeAt(0)) % 360;
  return `hsl(${h} 55% 48%)`;
}
const avatar = (name, key, cls = "") =>
  `<span class="avatar ${cls}" style="background:${avatarColor(key || name)}" aria-hidden="true">${esc(initials(name))}</span>`;

function dur(sec) {
  if (sec == null) return "–";
  const h = Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  return h >= 24 ? `${Math.floor(h / 24)}d ${h % 24}h` : h ? `${h}h ${m}m` : m ? `${m}m ${s}s` : `${s}s`;
}
const num = (v, digits) => (v == null ? "–" : Number(v).toFixed(digits));

// ---------- charging-bay visuals ----------
const V_MAX = 6;           // gauge scale 0..6 V (USB is 5 V)
const I_MAX = 3000;        // flow bar full at 3 A

function arcPath(cx, cy, r, a0, a1) {   // angles in degrees, clockwise from 12 o'clock
  const pt = a => [cx + r * Math.sin(a * Math.PI / 180), cy - r * Math.cos(a * Math.PI / 180)];
  const [x0, y0] = pt(a0), [x1, y1] = pt(a1);
  return `M${x0.toFixed(2)} ${y0.toFixed(2)} A${r} ${r} 0 ${a1 - a0 > 180 ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}
const fracAngle = f => -135 + 270 * Math.max(0, Math.min(1, f));

// Voltage dial: 270° arc, shaded safe band between the station's own limits.
function gauge(v, thresholds, level, { size = "" } = {}) {
  const cx = 69, cy = 64, r = 52;
  const band = thresholds ? arcPath(cx, cy, r, fracAngle(thresholds.sag_v / V_MAX), fracAngle(thresholds.over_voltage_v / V_MAX)) : "";
  const fill = v != null && v > 0.02 ? arcPath(cx, cy, r, -135, fracAngle(v / V_MAX)) : "";
  const ticks = Array.from({ length: V_MAX + 1 }, (_, i) => {
    const a = fracAngle(i / V_MAX) * Math.PI / 180, r1 = r + 9, r2 = r + (i === 5 ? 14 : 12);
    return `<line class="tick" x1="${(cx + r1 * Math.sin(a)).toFixed(1)}" y1="${(cy - r1 * Math.cos(a)).toFixed(1)}"
      x2="${(cx + r2 * Math.sin(a)).toFixed(1)}" y2="${(cy - r2 * Math.cos(a)).toFixed(1)}" stroke-width="${i === 5 ? 2 : 1.2}" stroke-linecap="round"/>`;
  }).join("");
  return `<div class="gauge ${level} ${size}" role="img" aria-label="Voltage ${v == null ? "unknown" : v.toFixed(2) + " volts"}">
    <svg viewBox="0 0 138 120" fill="none">
      <path class="track" d="${arcPath(cx, cy, r, -135, 135)}" stroke-width="9" stroke-linecap="round"/>
      ${band ? `<path class="band" d="${band}" stroke-width="9"/>` : ""}
      ${fill ? `<path class="fill" d="${fill}" stroke-width="9" stroke-linecap="round"/>` : ""}
      ${ticks}
    </svg>
    <div class="read"><b>${v == null ? "–" : v.toFixed(2)}</b><span>VOLTS</span></div>
    <div class="scale"><span>0</span><span>6V</span></div>
  </div>`;
}

let _sparkId = 0;
function sparkline(values, level) {
  const vals = (values || []).filter(v => v != null);
  if (vals.length < 2) return `<svg class="spark" viewBox="0 0 300 38" preserveAspectRatio="none"><line x1="0" y1="36" x2="300" y2="36"
    stroke="var(--surface-3)" stroke-width="2" stroke-dasharray="4 5"/></svg>`;
  const max = Math.max(...vals, 100), n = vals.length - 1;
  const pts = vals.map((v, i) => [(i / n) * 300, 35 - (Math.max(0, v) / max) * 31]);
  const line = pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const color = { ok: "var(--volt)", warn: "var(--warn)", bad: "var(--bad)" }[level] || "var(--idle-dot)";
  const id = "sg" + (++_sparkId);
  return `<svg class="spark" viewBox="0 0 300 38" preserveAspectRatio="none" aria-hidden="true">
    <defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="${color}" stop-opacity=".35"/><stop offset="1" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>
    <polygon points="0,38 ${line} 300,38" fill="url(#${id})"/>
    <polyline points="${line}" fill="none" stroke="${color}" stroke-width="1.8" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>
  </svg>`;
}

function signalBars(rssi) {
  const n = rssi == null ? 0 : rssi > -55 ? 4 : rssi > -67 ? 3 : rssi > -75 ? 2 : rssi > -85 ? 1 : 0;
  return `<span class="bars" title="${rssi == null ? "No signal data" : rssi + " dBm"}">${[1, 2, 3, 4].map(i => `<i class="${i <= n ? "on" : ""}"></i>`).join("")}</span>`;
}

function shieldBadge(blocked) {
  if (blocked === true) return `<span class="shield">${ICON.shield}Data lines blocked</span>`;
  if (blocked === false) return `<span class="shield exposed">${ICON.shield}DATA EXPOSED</span>`;
  return `<span>${ICON.shield}Shield –</span>`;
}

// One charging bay: gauge + live current flow + power trend + shield.
function stationCard(d, { admin = false } = {}) {
  const level = d.online ? stateClass(d.state) : "bad";
  const charging = d.online && d.state === "CHARGING";
  const href = "station.html?id=" + encodeURIComponent(d.id);
  const iPct = d.current_ma == null || d.current_ma <= 0 ? 0 : Math.max(3, Math.min(100, d.current_ma / I_MAX * 100));
  const foot = [
    shieldBadge(d.online ? d.data_blocked : null),
    `<span>${signalBars(d.online ? d.rssi : null)}</span>`,
    `<span>${ICON.clock}${d.last_seen ? ago(d.seconds_since_seen) : "never"}</span>`,
    d.location ? `<span>${ICON.pin}${esc(d.location)}</span>` : "",
    admin && d.pairing_code ? `<span title="Pairing code">#${esc(d.pairing_code)}</span>` : "",
  ].join("");
  const alerts = d.active_incidents || 0;
  return `<a class="bay ${level} ${charging ? "charging" : ""} ${d.online ? "" : "offline"} ${alerts ? "has-alert" : ""}" href="${href}">
    <div class="bay-head">
      <div><div class="bay-name">${esc(d.name || d.id)}</div><div class="bay-id">${d.name ? esc(d.id) : "&nbsp;"}</div></div>
      <div class="bay-tags">${statePill(d.state)}${alerts ? `<span class="bay-alert">${WARN_ICON}${alerts} alert${alerts > 1 ? "s" : ""}</span>` : ""}</div>
    </div>
    <div class="bay-body">
      ${gauge(d.voltage_v, d.thresholds, level)}
      <div class="readouts">
        <div class="readout"><small>Current</small><b>${num(d.current_ma, 0)}<span>mA</span></b>
          <div class="flow"><i style="width:${d.online ? iPct : 0}%"></i></div></div>
        <div class="readout"><small>Power</small><b>${d.power_mw == null ? "–" : (d.power_mw / 1000).toFixed(2)}<span>W</span></b></div>
      </div>
    </div>
    ${sparkline(d.power_history, level)}
    <div class="bay-foot">${foot}</div>
    ${!d.last_seen ? `<div class="bay-wait">Waiting for first reading from <b>${esc(d.id)}</b></div>` : ""}
  </a>`;
}

// Totals for the KPI strip.
function statTiles(devices) {
  const online = devices.filter(d => d.online);
  const charging = online.filter(d => d.state === "CHARGING").length;
  const alerts = online.filter(d => stateClass(d.state) !== "ok").length + (devices.length - online.length);
  const tile = (cls, label, value) => `<div class="stat ${cls}"><small><i></i>${label}</small><strong>${value}</strong></div>`;
  return tile("accent", "Stations", devices.length) + tile("ok", "Online", online.length) +
         tile("ok", "Charging now", charging) + tile(alerts ? "bad" : "", "Need attention", alerts);
}

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
    box.className = "fatal";
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
      <a class="brand" href="index.html">${LOGO}<span class="word">Juice Guard</span></a>
      <nav>${links.map(([href, label, key]) => `<a href="${href}" class="${key === active ? "on" : ""}">${label}</a>`).join("")}</nav>
      <span class="who">${avatar(me.full_name, me.email)}
        <span class="txt"><span class="name">${esc(me.full_name)}</span><span class="role">${me.role === "admin" ? "Administrator" : "Station host"}</span></span></span>
      <button id="logoutBtn" class="ghost sm">Log out</button>
    </div>`;
  document.body.prepend(bar);
  $("logoutBtn").onclick = async () => {
    await api("/api/auth/logout", { method: "POST", redirectOn401: false }).catch(() => {});
    location.href = "login.html";
  };
  return me;
}

// ---------- security incidents ----------
const WARN_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>';
const INCIDENT = {
  data_exposed: { title: "Data lines exposed", icon: () => ICON.shield,
    text: i => `The station reported D+/D− connected (${i.count} reading${i.count > 1 ? "s" : ""}). A phone plugged in now could have its data read. Inspect the port and wiring before anyone uses it.` },
  over_voltage: { title: "Over-voltage", icon: () => ICON.bolt,
    text: i => `Voltage peaked at ${i.peak != null ? i.peak.toFixed(2) : "?"} V${i.detail && i.detail.limit_v ? ` (limit ${i.detail.limit_v} V)` : ""}. A malicious or faulty charger could damage phones. Unplug the supply and check it.` },
  voltage_spike: { title: "Voltage spike", icon: () => ICON.up,
    text: i => `Voltage jumped by up to ${i.peak != null ? i.peak.toFixed(2) : "?"} V between readings, ${i.count} time${i.count > 1 ? "s" : ""}. This can be power injection or a failing supply.` },
  reboot_loop: { title: "Restart loop", icon: () => ICON.clock,
    text: i => `The station restarted ${i.count} times in a short period. Someone may be power-cycling it to reset or tamper with it.` },
  bad_key: { title: "Impersonation attempt", icon: () => WARN_ICON,
    text: i => `${i.count} reading${i.count > 1 ? "s" : ""} claiming to be this station ${i.count > 1 ? "were" : "was"} rejected for a wrong API key${i.detail && i.detail.ips && i.detail.ips.length ? ` from ${i.detail.ips.join(", ")}` : ""}. Someone may be trying to fake its data.` },
};

// One incident as an alert row. opts.station: show which station; opts.owner: show host email (admin).
function incidentCard(i, { station = true, owner = false } = {}) {
  const meta = INCIDENT[i.kind] || { title: i.kind, icon: () => WARN_ICON, text: () => "" };
  const sev = i.severity === "critical" ? "critical" : "warning";
  const started = parseTs(i.started_at), ended = i.ended_at ? parseTs(i.ended_at) : null;
  const chips = [
    `<span class="chip">${i.active ? "since " + started.toLocaleTimeString() : "ended " + ago((Date.now() - ended) / 1000)}</span>`,
    i.count > 1 ? `<span class="chip">${i.count}×</span>` : "",
    owner && i.owner_email ? `<span class="chip">${esc(i.owner_email)}</span>` : "",
    i.acknowledged_at ? `<span class="chip" style="color:var(--shield)">acknowledged</span>` : "",
  ].join("");
  const link = station ? ` · <a href="station.html?id=${encodeURIComponent(i.device_id)}">${esc(i.device_name || i.device_id)}</a>` : "";
  return `<div class="alert-card ${sev} ${i.active ? "is-live" : ""} ${!i.active || i.acknowledged_at ? "done" : ""}">
    <span class="alert-ico">${meta.icon()}</span>
    <div style="min-width:0">
      <div class="alert-title">${esc(meta.title)}${link}${i.active ? ` <span class="pill ${sev === "critical" ? "bad" : "warn"}">Live</span>` : ""}</div>
      <div class="alert-text">${esc(meta.text(i))}</div>
      <div class="alert-meta">${chips}</div>
    </div>
    <div class="alert-side">
      <span class="when">${ago((Date.now() - parseTs(i.last_seen_at)) / 1000)}</span>
      ${i.acknowledged_at ? "" : `<button class="sm" data-ack="${i.id}">Acknowledge</button>`}
    </div>
  </div>`;
}

// Wire up Acknowledge buttons inside `root`; calls `after` once one succeeds.
function bindAcks(root, after) {
  root.querySelectorAll("[data-ack]").forEach(b => b.onclick = async () => {
    b.disabled = true;
    try { await api(`/api/incidents/${b.dataset.ack}/ack`, { method: "POST" }); after(); }
    catch (e) { b.disabled = false; alert(e.message); }
  });
}
