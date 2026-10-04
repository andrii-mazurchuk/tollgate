// Tollgate server console, revisions 1-2: Overview, Peers & roles, Sessions, Policy. Vanilla JS, no build step.
// Shared helpers (h, icon, badge, time, trend, hbars, serverList, tabOverview, tabChecks, ...) come from /edge/common.js.
"use strict";

const API = "/console/api";
const STATES = ["clean", "untrusted", "holds_private"];
PATHS.plus = ["M12 5v14M5 12h14"];

const ui = { pol: null, view: "overview", range: load("c.range") || "today", since: load("c.since") || "", tab: "overview", stepMode: "list",
  f: {}, trace: null, peer: null, role: null, roleNames: {}, dirty: false };

async function api(path, opts) {
  const r = await fetch(API + path, opts);
  if (!r.ok) {
    let msg = `${r.status} ${path}`;
    try { const j = await r.json(); if (j.error) msg = `${r.status} ${j.error}`; } catch { /* not JSON */ }
    throw new Error(msg);
  }
  return r.json();
}
const post = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
const view = () => document.getElementById("view");
const bar = (...kids) => document.getElementById("bar").replaceChildren(...kids.filter(Boolean));
const enc = encodeURIComponent;
const sessHref = (sid, step) => `#/sessions/${enc(sid)}` + (step ? "/" + enc(step) : "");
const kv = rows => h("dl", { class: "kv" }, rows.filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
const roleName = r => ui.roleNames[r] || r;
const ago = ts => {
  if (!ts) return "Never";
  const sec = (Date.now() - new Date(ts).getTime()) / 1000;
  return sec < 60 ? "Just now" : sec < 3600 ? `${Math.floor(sec / 60)} min ago` : sec < 86400 ? `${Math.floor(sec / 3600)} h ago` : time(ts);
};
const seen = p => p.revoked ? h("span", { class: "badge", title: p.revoked_at ? "Revoked " + time(p.revoked_at) : "Revoked" }, icon("x"), "Revoked")
  : h("span", { class: "seen", title: p.last_seen ? `Last seen ${time(p.last_seen)}` : "Never seen" }, h("span", { class: "odot" + (p.online ? " on" : "") }),
    p.online ? "Online" : ago(p.last_seen));
// Keyboard rows: Enter or Space on a focused row opens it, like a click.
const rowKeys = go => ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); go(); } };
const linkRow = (go, cls, extra) => ({ class: "link" + (cls ? " " + cls : ""), tabindex: "0", onclick: ev => { if (ev.target.tagName !== "A") go(); }, onkeydown: rowKeys(go), ...extra });
const tbl = (cols, heads, rows) => h("table", { class: "t" }, h("colgroup", {}, cols.map(w => h("col", w ? { style: `width:${w}` } : {}))),
  h("thead", {}, h("tr", {}, heads.map(t => Array.isArray(t) ? h("th", { class: t[1] }, t[0]) : h("th", {}, t)))), h("tbody", {}, rows));

/* ---------- dialogs: native <dialog> gives modal focus and Esc ---------- */
function dialog(title, body, actions) {
  const id = "dlg-" + Math.random().toString(36).slice(2, 8);
  const d = h("dialog", { class: "dlg", "aria-labelledby": id },
    h("div", { class: "dlg-h" }, h("h2", { id }, title)), h("div", { class: "dlg-b" }, body), h("div", { class: "dlg-f" }, actions));
  d.addEventListener("close", () => d.remove());
  document.body.append(d);
  d.showModal();
  return d;
}

/* ---------- shell: health, status, theme ---------- */
async function refreshStatus() {
  const box = document.getElementById("status");
  let st;
  try { st = await api("/status?since=" + enc(ui.since)); } catch {
    renderHealth({ level: "alert", message: "Server unreachable" });
    box.replaceChildren(h("span", {}, h("span", { class: "cdot off" }), "Not connected"));
    return;
  }
  renderHealth(st.health);
  // st.admin says how the caller was let in ("loopback" | "token"), not who: show the role, keep the how in the tooltip
  box.title = [`Signed in as admin (${st.admin})`, `Policy ${String(st.policy.version).slice(0, 7)} (${st.policy.profile})`, `Threat feed ${st.feed?.version ?? "local"}`, `App ${st.app_version}`].join("\n");
  box.replaceChildren(h("span", { class: "who" }, icon("user"), "Admin"), h("span", { class: "sep" }), h("span", {}, h("span", { class: "cdot" }), location.host));
}

function renderHealth(hl) {
  const b = document.getElementById("health");
  b.className = "health " + (hl.level === "ok" ? "" : hl.level);
  b.querySelector(".msg").textContent = hl.message;
  b.title = hl.detail || (hl.level === "ok" ? "Nothing needs your attention" : "Open the event");
  b.onclick = hl.level === "ok" ? null : () => {
    if (hl.ts) { ui.since = hl.ts; save("c.since", hl.ts); }
    if (hl.session_id) { ui.tab = "overview"; ui.f = {}; location.hash = sessHref(hl.session_id, hl.trace_id); }
    refreshStatus();
  };
}

document.getElementById("theme").addEventListener("click", () => applyTheme(themeNow() === "dark" ? "light" : "dark"));

/* ---------- top-bar controls per view ---------- */
function renderBar() {
  if (ui.view === "overview") {
    return bar(h("div", { class: "seg", role: "group", "aria-label": "Time range" }, Object.entries(RANGES).map(([k, l]) => h("button", { type: "button", "aria-pressed": String(ui.range === k),
      onclick: () => { ui.range = k; save("c.range", k); renderBar(); route(false); } }, l))), ...exportMenu());
  }
  if (ui.view === "sessions") return bar(...exportMenu());
  if (ui.view === "peers" || ui.view === "roles") {
    return bar(h("div", { class: "seg", role: "group", "aria-label": "Peers or roles" }, [["peers", "Peers"], ["roles", "Roles"]].map(([k, l]) =>
      h("button", { type: "button", "aria-pressed": String(ui.view === k), onclick: () => { location.hash = k === "peers" ? peerHref(ui.peer) : roleHref(ui.role); } }, l))),
      ui.view === "peers" ? h("button", { class: "btn", type: "button", onclick: enrollDialog }, icon("plus"), "Enroll a laptop") : null);
  }
  if (ui.view === "policy" && ui.pol) {
    return bar(h("span", { class: "bar-t" }, "Profile: ", h("strong", {}, profileLabel(ui.pol))),
      h("button", { class: "btn", type: "button", "aria-pressed": String(!!ui.edit), onclick: toggleEdit }, ui.edit ? "Stop editing" : "Edit access"),
      ui.edit ? null : h("button", { class: "btn", type: "button", onclick: () => switchDialog(ui.pol) }, "Switch profile…"));
  }
  bar();
}

/* ---------- Export: a plain download link carrying the view's range (Overview) or filters (Sessions) ---------- */
function exportQuery() {
  if (ui.view !== "sessions") return new URLSearchParams({ range: ui.range });
  const p = new URLSearchParams({ range: "all" });
  for (const k of ["peer", "role", "state"]) if (sel(k).length) p.set(k, sel(k).join(","));
  if (ui.sq) p.set("q", ui.sq);
  return p;
}
const setExportCount = c => { const el = document.getElementById("xcount"); if (el) el.textContent = `${n(c)} event${c === 1 ? "" : "s"}`; };
function exportMenu() {
  const opt = (fmt, l, sub) => h("a", { class: "dd-opt", href: `${API}/export?format=${fmt}`, download: "",
    onclick: ev => { ev.currentTarget.href = `${API}/export?format=${fmt}&${exportQuery()}`; ev.currentTarget.closest("details").open = false; } },
    h("span", {}, l), h("span", { class: "muted small" }, sub));
  const d = h("details", { class: "dd xp" }, h("summary", { class: "btn" }, "Export", icon("chev")),
    h("div", { class: "dd-pop" }, opt("csv", "CSV", "spreadsheet"), opt("jsonl", "JSONL", "one event per line"),
      h("div", { class: "muted small xp-n" }, "Decisions and fingerprints only; the text never leaves the laptop.")));
  d.addEventListener("toggle", () => {
    if (!d.open) return;
    const r = d.querySelector("summary").getBoundingClientRect(), pop = d.querySelector(".dd-pop");
    pop.style.left = Math.max(8, Math.min(r.right - 240, innerWidth - 248)) + "px"; pop.style.top = (r.bottom + 4) + "px";
  });
  return [h("span", { id: "xcount", class: "bar-t num" }), d];
}

/* ---------- Overview ---------- */
// p95 above target is the one thing here that turns red (AC15 targets come from the API)
const lms = v => v == null ? "–" : v < 1 ? `${v.toFixed(2)} ms` : v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`;
function latencyCard(L) {
  const head = h("span", { class: "muted small" }, "Hub ≤ 5 ms · tier 1 ≤ 5 ms · classifier ≤ 80 ms");
  if (!L || !L.n) return card("Latency", head, h("div", { class: "empty" }, "No timed actions in this time range."));
  const cn = L.classifier.n ? "Content (tier 1 + 2)" : "Content (tier 1 scan)";
  const rows = [{ label: "Hub checks (role + data flow)", ...L.hub }, ...L.stages.map(s => ({ label: s.name === "content" ? cn : STAGE[s.name] || s.name, ...s })),
    { label: "Classifier (tier 2)", ...L.classifier }].filter(r => r.n).sort((a, b) => b.p95 - a.p95);
  return card("Latency", head, h("div", { class: "lat" },
    h("div", { class: "kpi" }, h("div", { class: "l" }, "End to end, p95"), h("div", { class: "v" }, lms(L.total.p95)),
      h("div", { class: "d" }, `p50 ${lms(L.total.p50)} · ${n(L.n)} actions`)),
    tbl([null, "84px", "84px", "84px"], ["Check", ["p50", "r"], ["p95", "r"], ["Target", "r"]], rows.map(r => h("tr", {},
      h("td", {}, r.label), h("td", { class: "num r" }, lms(r.p50)),
      h("td", { class: "num r" + (r.over ? " over" : ""), title: r.over ? "Above target" : "" }, lms(r.p95)),
      h("td", { class: "num r muted" }, r.target ? `≤ ${r.target} ms` : "–"))))));
}
async function renderOverview() {
  const [o, map] = await Promise.all([api("/overview?range=" + ui.range), mapCard()]);
  const k = o.kpis;
  const tiles = [["checked", "Actions checked"], ["blocked", "Blocked"], ["attacks", "Attacks stopped"], ["peers_online", "Peers online"]];
  const d = (key, x) => key === "peers_online" && x.prev == null ? "right now" : delta(x, ui.range);
  const hasData = k.checked.value > 0;
  setExportCount(k.checked.value);
  view().replaceChildren(h("div", { class: "stack" }, map,
    h("div", { class: "kpis" }, tiles.map(([key, l]) => h("div", { class: "card kpi" },
      h("div", { class: "l" }, l), h("div", { class: "v" }, n(k[key].value)), h("div", { class: "d" }, d(key, k[key]))))),
    card("Actions over time", h("div", { class: "legend" }, h("span", {}, h("i", { class: "f-allow" }), "Allowed"),
      h("span", {}, h("i", { class: "f-mid" }), "Masked or waiting"), h("span", {}, h("i", { class: "f-block" }), "Blocked")),
      hasData ? h("div", { class: "card-b" }, trend(o.series, o.bucket_s), h("div", { class: "chart-foot" }, `One bar per ${bucketWords(o.bucket_s)}, all peers.`))
        : h("div", { class: "empty" }, "No actions in this time range.")),
    latencyCard(o.latency),
    h("div", { class: "grid2" },
      card("Blocked by reason", null, hbars(o.by_reason, r => r.label, r => r.count)),
      card("Blocked by role", null, hbars(o.by_role, r => `${r.agent} (${r.role})`, r => r.count))),
    card("Attacks stopped", h("a", { href: "#/sessions", class: "small" }, "All sessions"),
      o.attacks.length ? tbl(["120px", null, "180px", "160px", "200px"], ["Time", "What happened", "Peer", "Agent", "Tool"],
        o.attacks.map(x => h("tr", linkRow(() => { ui.f = {}; ui.tab = "overview"; location.hash = sessHref(x.session_id, x.trace_id); }),
          h("td", { class: "num muted" }, time(x.ts)),
          h("td", { title: x.action }, badge(x.kind), " ", x.action),
          h("td", { title: x.peer_label }, x.peer_label),
          h("td", { title: x.agent }, x.agent),
          h("td", { title: x.tool }, x.tool))))
        : h("div", { class: "empty" }, "No attacks in this time range."))));
  drawMap();
}

/* ---------- Peers & roles: Peers tab ---------- */
const peerHref = id => "#/peers" + (id ? "/" + enc(id) : "");
const roleHref = r => "#/roles" + (r ? "/" + enc(r) : "");

async function fleet() {
  const d = await api("/peers");
  for (const r of d.roles) ui.roleNames[r.role] = r.agent;
  return d;
}

async function renderPeers(idArg) {
  const d = await fleet();
  if (!d.peers.length) return view().replaceChildren(h("div", { class: "card empty" }, "No laptops enrolled yet. Use ", h("strong", {}, "Enroll a laptop"), " at the top right."));
  const id = d.peers.some(p => p.id === idArg) ? idArg : d.peers.some(p => p.id === ui.peer) ? ui.peer : d.peers[0].id;
  if (id !== ui.peer) ui.dirty = false;
  ui.peer = id;
  if (idArg !== id) history.replaceState(null, "", peerHref(id));
  const list = h("section", { class: "card pane", "data-keep": "plist" }, tbl([null, "148px", "104px", "68px", "64px"],
    ["Laptop", "Roles", "Seen", ["Sessions", "r"], ["Blocked", "r"]],
    d.peers.map(p => {
      const roles = p.roles.map(roleName).join(", ") || "None";
      return h("tr", linkRow(() => { location.hash = peerHref(p.id); }, p.id === id ? "sel" : "", { "aria-selected": String(p.id === id) }),
        h("td", { title: `${p.device} · ${p.owner} (${p.id})` }, h("div", { class: "two" }, h("span", { class: "ell" }, p.device), h("span", { class: "ell muted small" }, p.owner))),
        h("td", { class: p.roles.length ? "" : "muted", title: roles }, roles),
        h("td", {}, seen(p)),
        h("td", { class: "num r" }, n(p.sessions)),
        h("td", { class: "num r" }, n(p.blocked)));
    })));
  const right = h("section", { class: "card pane split" });
  view().replaceChildren(h("div", { class: "md wide" }, list, right));
  let p;
  try { p = await api("/peers/" + enc(id)); } catch (err) {
    return right.replaceChildren(h("div", { class: "empty" }, "Could not load this laptop. ", String(err.message)));
  }
  drawPeer(right, p, d.roles);
}

function drawPeer(box, p, roles) {
  const legacy = /unenrolled/i.test(`${p.id} ${p.device}`);
  const strip = h("div", { class: "strip" }, [
    ["Owner", p.owner || "–"], ["Device", p.device], ["Enrolled", p.enrolled_at ? time(p.enrolled_at) : "–"], ["Last seen", p.last_seen ? ago(p.last_seen) : "Never"],
    ["Keys minted", n(p.minted ?? (p.keys || []).length)], ["Sessions", n((p.sessions || []).length)], ["Blocked", n(p.blocked)],
  ].map(([k, v]) => h("div", {}, h("div", { class: "k" }, k), h("div", { class: "v" }, v))));

  // Roles this laptop may run: checkboxes + Save
  const picked = new Set(p.roles);
  const msg = h("span", { class: "small muted", role: "status" });
  const saveBtn = h("button", { class: "btn primary", type: "button", disabled: true, onclick: async () => {
    saveBtn.disabled = true; msg.className = "small muted"; msg.textContent = "Saving…";
    try {
      await post(`/peers/${enc(p.id)}/roles`, { roles: [...picked] });
      ui.dirty = false; msg.textContent = "Saved."; route(false);
    } catch (err) { msg.className = "small err"; msg.textContent = String(err.message); saveBtn.disabled = false; }
  } }, "Save");
  const locked = p.revoked || legacy;
  const checks = h("div", { class: "rolecheck" }, roles.map(r => h("label", {},
    h("input", { type: "checkbox", value: r.role, checked: picked.has(r.role), disabled: locked, onchange: ev => {
      ev.target.checked ? picked.add(r.role) : picked.delete(r.role);
      ui.dirty = [...picked].sort().join() !== [...p.roles].sort().join();
      saveBtn.disabled = !ui.dirty; msg.textContent = ui.dirty ? "Unsaved changes" : "";
    } }), h("span", {}, r.agent, h("span", { class: "sub-l" }, r.role)))));

  const sessions = (p.sessions || []);
  const keysT = (p.keys || []);
  const body = h("div", { class: "body", "data-keep": "pdetail" },
    h("div", { class: "sec" }, h("div", { class: "sec-h" }, h("h3", {}, "Roles this laptop may run")),
      checks,
      locked ? h("p", { class: "muted small", style: "margin:8px 0 0" }, p.revoked ? "This laptop is revoked: it cannot mint keys for any role." : "Legacy keys with no laptop. Enroll the laptop to manage its roles.")
        : h("div", { class: "save-row" }, saveBtn, msg, h("span", { class: "muted small", style: "margin-left:auto" }, "Removing a role ends this laptop's keys for it."))),
    h("div", { class: "sec" }, h("div", { class: "sec-h" }, h("h3", {}, `Sessions (${n(sessions.length)})`),
      sessions.length ? h("a", { class: "small", href: "#/sessions", onclick: () => { ui.f = { peer: p.id }; } }, "Show in Sessions") : null),
      sessions.length ? tbl([null, "120px", "56px", "64px", "96px"], ["Agent", "Started", ["Steps", "r"], "State", "Last"],
        sessions.slice(0, 50).map(x => h("tr", linkRow(() => { ui.f = {}; location.hash = sessHref(x.id); }),
          h("td", { title: x.id }, h("div", { class: "two" }, h("span", { class: "ell" }, x.agent, x.active ? h("span", { class: "live", title: "Active" }) : null), h("span", { class: "ell muted small mono" }, x.id))),
          h("td", { class: "num" }, time(x.first_ts)), h("td", { class: "num r" }, n(x.n)), h("td", {}, stateIcons(x.state)), h("td", {}, lastOutcome(x.last_verdict)))))
        : h("div", { class: "muted" }, "No sessions yet.")),
    h("div", { class: "sec" }, h("div", { class: "sec-h" }, h("h3", {}, "Keys"), h("span", { class: "muted small" }, "One key per agent launch")),
      keysT.length ? tbl([null, "160px", "200px", "64px"], ["Key ID", "Role", "Active", ["Calls", "r"]],
        keysT.map(k => h("tr", {}, h("td", { class: "mono", title: k.key_id }, k.key_id), h("td", { title: k.role }, roleName(k.role)),
          h("td", { class: "num muted", title: `${time(k.first_ts)} – ${time(k.last_ts)}` }, `${time(k.first_ts)} – ${time(k.last_ts).split(" ").pop()}`),
          h("td", { class: "num r" }, n(k.n)))))
        : h("div", { class: "muted" }, "No keys minted yet.")),
    legacy || p.revoked ? null : h("div", { class: "sec" }, h("div", { class: "sec-h" }, h("h3", {}, "Revoke this laptop")),
      h("p", { class: "muted", style: "margin:0 0 8px" }, "Every key it minted stops working at once. It must enroll again to run agents."),
      h("button", { class: "btn danger", type: "button", onclick: () => revokeDialog(p) }, "Revoke this laptop")));

  box.replaceChildren(h("div", { class: "pane-h" }, h("h2", {}, p.device), h("span", { class: "muted small ell" }, p.owner), h("span", { class: "muted small mono" }, p.id),
    h("span", { class: "right small muted" }, seen(p))), strip, body);
}

function revokeDialog(p) {
  const err = h("p", { class: "err small", role: "alert" });
  const cancel = h("button", { class: "btn", type: "button", autofocus: true, onclick: () => d.close() }, "Cancel");
  const go = h("button", { class: "btn danger-fill", type: "button", onclick: async () => {
    go.disabled = true;
    try { await post(`/peers/${enc(p.id)}/revoke`); d.close(); route(false); } catch (e) { err.textContent = String(e.message); go.disabled = false; }
  } }, `Revoke ${p.device}`);
  const d = dialog(`Revoke ${p.device}?`, [
    h("p", {}, `${p.owner}'s laptop ${p.device} loses access now. All ${n(p.minted ?? (p.keys || []).length)} keys it minted stop working, and running agents on it are cut off at their next call.`),
    h("p", {}, "This cannot be undone. The laptop can enroll again with a new one-time command."), err], [cancel, go]);
}

async function enrollDialog() {
  const body = h("div", {}, h("p", { class: "muted" }, "Creating a one-time command…"));
  const close = h("button", { class: "btn", type: "button", onclick: () => d.close() }, "Close");
  const d = dialog("Enroll a laptop", body, [close]);
  try {
    const t = await post("/enroll-token");
    const copyBtn = h("button", { class: "btn sm", type: "button", onclick: ev => copy(t.command, ev.currentTarget) }, "Copy");
    body.replaceChildren(
      h("p", {}, "Run this on the laptop. Fill in the owner and the device name; the admin sets its roles here afterwards."),
      h("div", { class: "cmd" }, h("pre", { class: "mono" }, t.command), copyBtn),
      h("p", { class: "muted small", style: "margin:12px 0 0" }, `One use only. Expires ${time(t.expires_at)}.`));
    copyBtn.focus();
  } catch (err) { body.replaceChildren(h("p", { class: "err" }, "Could not create a command: ", String(err.message))); }
}

/* ---------- Peers & roles: Roles tab ---------- */
async function renderRoles(roleArg) {
  const d = await fleet();
  if (!d.roles.length) return view().replaceChildren(h("div", { class: "card empty" }, "The policy has no roles."));
  const role = d.roles.some(r => r.role === roleArg) ? roleArg : d.roles.some(r => r.role === ui.role) ? ui.role : d.roles[0].role;
  ui.role = role;
  if (roleArg !== role) history.replaceState(null, "", roleHref(role));
  const sum = (r, k) => r.servers.reduce((a, s) => a + (s[k] || 0), 0);
  const list = h("section", { class: "card pane", "data-keep": "rlist" },
    tbl([null, "56px", "96px", "68px", "64px"], ["Agent", ["Peers", "r"], "Tools", ["Actions", "r"], ["Blocked", "r"]],
      d.roles.map(r => h("tr", linkRow(() => { location.hash = roleHref(r.role); }, r.role === role ? "sel" : "", { "aria-selected": String(r.role === role) }),
        h("td", { title: `${r.agent} (${r.role})` }, h("div", { class: "two" }, h("span", { class: "ell" }, r.agent), h("span", { class: "ell muted small" }, r.role))),
        h("td", { class: "num r" }, n(r.peers)),
        h("td", { class: "num", title: `${sum(r, "allowed")} allowed, ${sum(r, "hidden")} hidden` }, n(sum(r, "allowed")), h("span", { class: "muted" }, ` / ${n(sum(r, "hidden"))} hidden`)),
        h("td", { class: "num r" }, n(r.actions)),
        h("td", { class: "num r" }, n(r.blocked))))),
    h("div", { class: "sec" }, h("div", { class: "sec-h" }, h("h3", {}, "Peers per role")),
      hbars([...d.roles].sort((a, b) => b.peers - a.peers), r => r.agent, r => r.peers)));
  const right = h("section", { class: "card pane split" });
  view().replaceChildren(h("div", { class: "md" }, list, right));
  let a;
  try { a = await api("/roles/" + enc(role)); } catch (err) {
    return right.replaceChildren(h("div", { class: "empty" }, "Could not load this role. ", String(err.message)));
  }
  drawRole(right, a);
}

function drawRole(box, a) {
  const reach = a.servers.filter(s => s.reachable);
  const allowed = a.servers.reduce((x, s) => x + s.allowed.length, 0), hidden = a.servers.reduce((x, s) => x + s.denied.length, 0);
  const peers = a.peers || [];
  const strip = h("div", { class: "strip" }, [
    ["Peers", n(peers.filter(p => !p.revoked).length)], ["MCP servers", `${reach.length} of ${a.servers.length}`], ["Allowed tools", n(allowed)], ["Hidden tools", n(hidden)],
    ["Models", (a.models || []).join(", ") || "–"], ["Profile", a.policy?.profile || "–"],
  ].map(([k, v]) => h("div", {}, h("div", { class: "k" }, k), h("div", { class: "v" }, v))));
  const b = a.budget || {}, inj = a.content.injection, sig = a.content.signatures;
  const lst = xs => xs && xs.length ? xs.join(", ") : "–";
  const body = h("div", { class: "body", "data-keep": "rdetail" },
    h("div", { class: "sec" }, h("div", { class: "sec-h" }, h("h3", {}, "MCP servers and tools")), serverList(a.servers)),
    h("div", { class: "sec" }, h("div", { class: "grid2" },
      h("div", {}, h("div", { class: "sec-h" }, h("h3", {}, "Models and budget")), kv([
        ["Models allowed", lst(a.models)],
        ["Tokens today", b.limit == null ? `${n(b.used)} used · no limit` : `${n(b.used)} of ${n(b.limit)} used`]])),
      h("div", {}, h("div", { class: "sec-h" }, h("h3", {}, "Content checks")), kv([
        ["Masked", lst(a.content.masked)], ["Blocked", lst(a.content.blocked)], a.content.asks?.length ? ["Asks a human", lst(a.content.asks)] : null,
        ["Injection check", inj.words], ["Signatures", `${n(sig.count)} known attacks${sig.version != null ? " · v" + sig.version : ""}`]])))),
    h("div", { class: "sec" }, h("div", { class: "sec-h" }, h("h3", {}, "Data-flow rule")), h("p", { class: "flow" }, a.flow_rule.sentence)),
    h("div", { class: "sec" }, h("div", { class: "sec-h" }, h("h3", {}, `Peers running it (${n(peers.length)})`)),
      peers.length ? tbl([null, "180px", "120px"], ["Laptop", "Owner", "Seen"],
        peers.map(p => h("tr", linkRow(() => { location.hash = peerHref(p.id); }),
          h("td", { title: p.id }, p.device), h("td", { title: p.owner }, p.owner), h("td", {}, seen(p)))))
        : h("div", { class: "muted" }, "No laptop may run this role yet. Allow it in the Peers tab.")));
  box.replaceChildren(h("div", { class: "pane-h" }, h("h2", {}, a.agent), h("span", { class: "muted small mono" }, a.role),
    h("span", { class: "right small muted" }, a.policy?.version ? `policy ${String(a.policy.version).slice(0, 7)}` : "")), strip, body);
}

/* ---------- Threat feed: signatures in force (list -> detail), feed status, publish ---------- */
const sigHref = id => "#/feed" + (id ? "/" + enc(id) : "");
const SIG_ACT = { block: ["ban", "Blocks"], approve: ["clock", "Asks a human"], redact: ["lock", "Masks"], allow: ["dash", "Records only"] };
const sigAct = a => h("span", { class: "badge" }, icon((SIG_ACT[a] || ["flag"])[0]), (SIG_ACT[a] || [, a])[1]);
const base = p => String(p).split(/[\\/]/).pop();
const kcell = (k, v, tip) => h("div", tip ? { title: tip } : {}, h("div", { class: "k" }, k), h("div", { class: "v" }, v));

async function renderFeed(idArg) {
  const f = await api("/feed");
  bar(h("button", { class: "btn", type: "button", onclick: () => publishDialog(f) }, icon("plus"), "Publish a signature…"));
  const fd = f.feed;
  const check = !fd.enabled ? h("span", { class: "muted" }, "No feed") : fd.verified === true ? h("span", { class: "state" }, icon("check"), "Verified")
    : fd.verified === false ? h("span", { class: "badge fail" }, icon("x"), "Failed") : h("span", { class: "muted" }, "Not pulled yet");
  const status = h("section", { class: "card" }, h("div", { class: "card-h" }, h("h2", {}, "Feed status"),
    h("span", { class: "muted small" }, f.peers_note)),
    h("div", { class: "strip" }, [
      ["Signatures from", f.source === "threat feed" ? `Signed feed${f.file_version != null ? " v" + f.file_version : ""}` : "Local file"],
      ["Feed", fd.enabled ? h("code", { title: fd.url }, fd.url) : "Off"],
      ["Version pulled", fd.version != null ? "v" + fd.version : "–"],
      ["Last pull", fd.last_pull ? ago(fd.last_pull) : "–"],
      ["Signature check", check],
      ["File", h("code", {}, base(f.file)), f.file + (f.updated_at ? "\nUpdated " + time(f.updated_at) : "")],
    ].map(([k, v, tip]) => kcell(k, v, tip))),
    fd.last_error ? h("div", { class: "rejected", role: "alert" }, icon("warn"),
      h("span", {}, "Last pull failed: ", h("span", { class: "mono" }, fd.last_error), ". The signatures below stay in force.")) : null,
    f.errors.length ? h("div", { class: "rejected", role: "alert" }, icon("warn"),
      h("span", {}, `${f.errors.length} signature${f.errors.length > 1 ? "s" : ""} skipped: `, h("span", { class: "mono" }, f.errors.join("; ")))) : null);
  const list = f.signatures;
  const id = list.some(s => s.id === idArg) ? idArg : list.some(s => s.id === ui.sig) ? ui.sig : list[0]?.id;
  ui.sig = id;
  if (id && idArg !== id) history.replaceState(null, "", sigHref(id));
  const left = h("section", { class: "card pane", "data-keep": "siglist" }, list.length ? tbl([null, "128px", "56px"], ["Signature", "Action", ["Tags", "r"]],
    list.map(s => h("tr", linkRow(() => { location.hash = sigHref(s.id); }, s.id === id ? "sel" : "", { "aria-selected": String(s.id === id) }),
      h("td", { title: s.plain }, h("div", { class: "two" }, h("span", { class: "ell" }, s.plain), h("span", { class: "ell muted small mono" }, s.id))),
      h("td", {}, sigAct(s.action)),
      h("td", { class: "num r" }, n(s.tags.length)))))
    : h("div", { class: "empty" }, "No signatures in force."));
  const right = h("section", { class: "card pane split" });
  const sig = list.find(s => s.id === id);
  if (sig) drawSig(right, sig, f); else right.append(h("div", { class: "empty" }, "No signature to show."));
  view().replaceChildren(h("div", { class: "feed-wrap" }, status, h("div", { class: "md" }, left, right)));
}

const SIG_DONE = { block: "blocked", approve: "held for a human", redact: "masked", allow: "recorded" };
function drawSig(box, s, f) {
  box.replaceChildren(h("div", { class: "pane-h" }, h("h2", {}, s.plain)),
    h("div", { class: "strip" }, [["Rule", h("code", {}, s.rule)], ["Action", sigAct(s.action)], ["Source", s.source === "threat feed" ? "Signed feed" : "Local file"]].map(([k, v]) => kcell(k, v))),
    h("div", { class: "body", "data-keep": "sigdetail" },
      h("div", { class: "sec" }, h("div", { class: "sec-h" }, h("h3", {}, "What it catches")),
        h("p", { style: "margin:0 0 12px" }, `${s.plain}. Every call's arguments and tool results are checked against it; on a match the call is ${SIG_DONE[s.action] || s.action}.`),
        h("div", { class: "muted small", style: "margin-bottom:4px" }, "Pattern (regular expression, case-insensitive)"),
        h("pre", { class: "pat mono" }, s.pattern)),
      h("div", { class: "sec" }, h("div", { class: "sec-h" }, h("h3", {}, "Tags")),
        s.tags.length ? tbl(["200px", null], ["Tag", "Means"], s.tags.map(t => h("tr", {}, h("td", { class: "mono" }, t.id), h("td", { class: t.plain ? "" : "muted" }, t.plain || "–"))))
          : h("div", { class: "muted" }, "No tags.")),
      h("div", { class: "sec" }, h("div", { class: "sec-h" }, h("h3", {}, "Where it comes from")),
        h("p", { class: "muted", style: "margin:0" }, s.source === "threat feed"
          ? `Pulled from the signed feed at ${f.feed.url || "the feed"} and written to ${base(f.file)} on this hub. Change the feed, not the file: the next pull overwrites it.`
          : `Read from ${base(f.file)} on this hub. Changes to the file apply on the next call.`))));
}

function publishDialog(f) {
  if (!f.publish.enabled) {
    const close = h("button", { class: "btn", type: "button", autofocus: true, onclick: () => d.close() }, "Close");
    const d = dialog("Publish a signature", [h("p", {}, "This hub has no signature feed to publish to, so nothing is written."),
      h("p", { class: "muted" }, f.publish.reason)], [close]);
    return;
  }
  const errs = {};
  const field = (key, label, input, hint) => {
    errs[key] = h("div", { class: "err small", id: "pe-" + key, role: "alert" });
    input.id = "pf-" + key; input.setAttribute("aria-describedby", "pe-" + key + (hint ? " ph-" + key : ""));
    return h("div", { class: "fld" }, h("label", { for: input.id }, label), input, hint ? h("div", { class: "muted small", id: "ph-" + key }, hint) : null, errs[key]);
  };
  const inp = attrs => h("input", { type: "text", autocomplete: "off", spellcheck: "false", ...attrs });
  const fId = inp({ placeholder: "e.g. reverse_shell", maxlength: "64" });
  const fPat = inp({ class: "mono", placeholder: "e.g. nc\\s+-e\\s+/bin/(ba)?sh" });
  const fAct = h("select", {}, [["block", "Block the call"], ["approve", "Ask a human"], ["redact", "Mask the match"]].map(([v, l]) => h("option", { value: v }, l)));
  const fTags = inp({ placeholder: "e.g. OWASP-LLM06, ATLAS-AML.T0050" });
  const els = { id: fId, pattern: fPat, action: fAct, tags: fTags };
  const err = h("p", { class: "err small", role: "alert" });
  const cancel = h("button", { class: "btn", type: "button", onclick: () => d.close() }, "Cancel");
  const go = h("button", { class: "btn primary", type: "submit", form: "pubform" }, "Publish");
  const show = fields => {
    for (const [k, msg] of Object.entries(fields)) { if (errs[k]) { errs[k].textContent = msg; els[k].setAttribute("aria-invalid", "true"); } else err.textContent = msg; }
    const first = Object.keys(fields).find(k => els[k]);
    if (first) els[first].focus();
  };
  const form = h("form", { class: "pub", id: "pubform", novalidate: true, onsubmit: async ev => {
    ev.preventDefault();
    Object.values(errs).forEach(e => { e.textContent = ""; });
    Object.values(els).forEach(x => x.removeAttribute("aria-invalid"));
    err.textContent = "";
    const req = { id: fId.value.trim(), pattern: fPat.value, action: fAct.value, tags: fTags.value.split(",").map(t => t.trim()).filter(Boolean) };
    const local = {};
    if (!req.id) local.id = "Enter an ID.";
    if (!req.pattern.trim()) local.pattern = "Enter a pattern.";
    if (Object.keys(local).length) return show(local);
    go.disabled = true; go.textContent = "Publishing…";
    try {
      const r = await fetch(API + "/feed/publish", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(req) });
      const j = await r.json().catch(() => ({}));
      if (r.ok) {
        ui.sig = j.id;
        form.replaceChildren(h("p", {}, `${j.replaced ? "Replaced" : "Published"} `, h("code", {}, j.id), ` in feed version ${j.version}.`), h("p", { class: "muted" }, j.note));
        go.remove(); cancel.textContent = "Close"; cancel.focus();
        route(false);
        return;
      }
      if (j.fields) show(j.fields); else err.textContent = j.error || `Publish failed (${r.status}).`;
    } catch (e) { err.textContent = String(e.message); }
    go.disabled = false; go.textContent = "Publish";
  } },
    h("p", {}, `Adds the signature to the signed feed (now v${f.feed.version ?? "?"}). Every hub pulling the feed picks it up within ${f.feed.interval_s} s.`),
    field("id", "ID", fId, "Letters, digits and underscores. An existing ID is replaced."),
    field("pattern", "Pattern", fPat, "A regular expression, matched case-insensitively. Nested repeats such as (a+)+ are refused: they can hang the scanner."),
    field("action", "On a match", fAct),
    field("tags", "Tags", fTags, "Optional, comma-separated."), err);
  const d = dialog("Publish a signature", form, [cancel, go]);
  fId.focus();
}

/* ---------- Self-test: latest evaluation vs targets, per corpus and check, misses ---------- */
const pct = v => v == null ? "–" : v === 1 ? "100%" : `${(v * 100).toFixed(1)}%`;
const fmtT = (x, v) => v == null ? "–" : x.unit === "ms" ? ms(v) : pct(v);
const CHECK = { pii: "Personal data", secrets: "Secrets", injection: "Injection", signatures: "Signatures", obfuscation: "Obfuscation" };
const EXPECT = { flag: "flag", block: "block", redact: "mask", allow: "allow", approve: "ask a human" };

async function renderSelftest() {
  const s = await api("/selftest");
  const e = s.eval, run = s.run;
  const runBtn = h("button", { class: "btn", type: "button", disabled: run.running, onclick: async () => {
    runBtn.disabled = true;
    try { await post("/selftest/run"); } catch { /* 409: already running; the view shows it */ }
    route(false);
  } }, run.running ? "Running…" : "Run self-test");
  bar(h("span", { class: "bar-t" }, e ? ["Last run: ", h("strong", { title: time(e.ran_at) }, ago(e.ran_at))] : "Never run"), runBtn);
  if (run.running) setTimeout(() => { if (ui.view === "selftest") route(false); }, 2000);
  const cmd = h("div", { class: "cmd" }, h("pre", { class: "mono" }, s.command), h("button", { class: "btn sm", type: "button", onclick: ev => copy(s.command, ev.currentTarget) }, "Copy"));
  const runInfo = run.running ? h("div", { class: "local", role: "status" }, icon("clock"), `Self-test running since ${time(run.started_at)}…`)
    : run.error ? h("div", { class: "rejected boxed", role: "alert" }, icon("warn"), h("span", {}, "The last run failed: ", h("span", { class: "mono" }, run.error))) : null;
  const held = card("Held-out set", null, h("div", { class: "card-b" }, h("p", { style: "margin:0" },
    s.holdout.sets.map(x => `${x.name} (${n(x.cases)} cases)`).join(", ") || "None", ". ", s.holdout.note)));
  const cli = card("Full run from a terminal", null, h("div", { class: "card-b" }, h("p", { class: "muted", style: "margin:0 0 8px" }, s.run_note), cmd));
  if (!e) return view().replaceChildren(h("div", { class: "stack" }, runInfo, h("div", { class: "card empty" }, "No evaluation yet. Run the self-test."), h("div", { class: "grid2" }, held, cli)));

  const op = x => x.op === ">=" ? "≥" : "≤";
  const tiles = h("div", { class: "kpis tgt" }, e.headline.map(x => h("div", { class: "card kpi" },
    h("div", { class: "l" }, x.label), h("div", { class: "v" }, fmtT(x, x.value)),
    h("div", { class: "d" + (x.met === false ? " miss" : "") }, x.met == null ? `Target ${op(x)} ${fmtT(x, x.target)}`
      : [icon(x.met ? "check" : "x"), ` Target ${op(x)} ${fmtT(x, x.target)}: ${x.met ? "met" : "missed"}`]),
    h("div", { class: "d" }, x.source))));
  const t = s.tests, bad = t ? (t.failed || 0) + (t.error || 0) : 0;
  const suite = !t ? "Not recorded" : bad ? h("span", { class: "err" }, `${n(bad)} failed, ${n(t.passed)} passed`)
    : `${n(t.passed)} passed` + (t.xfailed ? `, ${n(t.xfailed)} expected to fail` : "") + (t.skipped ? `, ${n(t.skipped)} skipped` : "");
  const last = card("Last run", h("span", { class: "muted small" }, e.split || ""), h("div", { class: "strip" }, [
    ["Ran", time(e.ran_at)], ["Took", e.duration_s != null ? dur(e.duration_s) : "–"], ["Cases scanned", n(e.cases_run)], ["Profile", cap(e.profile) || "–"],
    ["Posture score", pct(e.posture)], ["Test suite", suite, t?.ran_at ? "Ran " + time(t.ran_at) : "Recorded by uv run tollgate test"],
  ].map(([k, v, tip]) => kcell(k, v, tip))));
  const rate = v => h("td", { class: "num r" + (v == null ? " muted" : "") }, pct(v));
  const two = (a, b) => h("div", { class: "two" }, h("span", { class: "ell" }, a), h("span", { class: "ell muted small mono" }, b));
  const srcT = card("By corpus", h("span", { class: "muted small" }, "Held-out 30% of each corpus"),
    tbl([null, "56px", "60px", "60px", "92px", "76px"], ["Corpus", ["Cases", "r"], ["Caught", "r"], ["Missed", "r"], ["False alarms", "r"], ["Recall", "r"]],
      e.sources.map(r => h("tr", {}, h("td", { title: r.name }, two(r.plain, r.name)),
        h("td", { class: "num r" }, n(r.n)), h("td", { class: "num r" }, n(r.caught)), h("td", { class: "num r" }, n(r.missed)),
        h("td", { class: "num r" }, n(r.false_alarms)), rate(r.recall)))));
  const ctlT = card("By check", h("span", { class: "muted small" }, "Held-out cases each check is scored on"),
    tbl([null, "56px", "60px", "60px", "92px", "76px"], ["Check", ["Cases", "r"], ["Caught", "r"], ["Missed", "r"], ["False alarms", "r"], ["Pass rate", "r"]],
      e.controls.map(r => h("tr", {}, h("td", {}, r.plain, r.enabled ? null : h("span", { class: "tag-if" }, "off")),
        h("td", { class: "num r" }, n(r.n)), h("td", { class: "num r" }, n(r.caught)), h("td", { class: "num r" }, n(r.missed)),
        h("td", { class: "num r" }, n(r.false_alarms)), rate(r.pass_rate)))));
  const all = e.misses;
  ui.mk = ui.mk || "all";
  const shown = (all || []).filter(m => ui.mk === "all" || m.kind === ui.mk);
  const seg = all && all.length ? h("div", { class: "seg", role: "group", "aria-label": "Show misses" }, [["all", "All"], ["missed", "Missed attacks"], ["false alarm", "False alarms"]].map(([k, l]) =>
    h("button", { type: "button", "aria-pressed": String(ui.mk === k), onclick: () => { ui.mk = k; route(false); } },
      `${l} (${n(k === "all" ? all.length : all.filter(m => m.kind === k).length)})`))) : null;
  const missT = card(all ? `Misses (${n(all.length)})` : "Misses", seg,
    all == null ? h("div", { class: "empty" }, "This run did not record its misses. Run the self-test again to list them.")
      : !shown.length ? h("div", { class: "empty" }, "No misses.")
        : h("div", { class: "miss-wrap", "data-keep": "misses" }, tbl(["124px", "120px", "104px", "112px", null], ["What went wrong", "Corpus", "Check", "Expected → got", "Text (first 120 characters; hover for the fingerprint)"],
          shown.map(m => h("tr", { class: "mrow" }, h("td", {}, m.kind === "missed" ? "Missed attack" : "False alarm"),
            h("td", { class: "ell", title: m.id }, m.source), h("td", {}, CHECK[m.control] || m.control),
            h("td", {}, `${EXPECT[m.expect] || m.expect} → ${EXPECT[m.got] || m.got}`),
            h("td", { class: "ell", title: `SHA-256 ${m.sha256}\n${m.text}` }, m.text))))));
  view().replaceChildren(h("div", { class: "stack" }, runInfo, tiles, last, h("div", { class: "grid2" }, srcT, ctlT), missT, h("div", { class: "grid2" }, held, cli)));
}

/* ---------- Sessions: master-detail across all peers ---------- */
// Filters are multi-select sets, ORed within a filter and ANDed across filters; elsewhere `ui.f = { peer: id }` still works.
const sel = k => [].concat(ui.f[k] || []);
const matches = x => {
  const [p, r, st] = [sel("peer"), sel("role"), sel("state")], q = (ui.sq || "").toLowerCase();
  return (!p.length || p.includes(x.peer)) && (!r.length || r.includes(x.role))
    && (!st.length || (x.state || "clean").split("+").some(s => st.includes(s)))
    && (!q || [x.agent, x.peer_label, x.id, x.role].join(" ").toLowerCase().includes(q));
};

// A compact filter button with a popover: search (for long lists), checkboxes, Clear. Scales to hundreds of options.
function dropdown(key, label, opts, onchange) {
  const btnText = () => { const v = sel(key); return v.length === 0 ? "All" : v.length === 1 ? (opts.find(o => o.id === v[0])?.name || v[0]) : `${v.length} selected`; };
  const val = h("span", { class: "dd-v ell" }, btnText());
  const listBox = h("div", { class: "dd-list", role: "group", "aria-label": label });
  const draw = q => listBox.replaceChildren(...(() => {
    const on = sel(key), shown = opts.filter(o => !q || (o.name + " " + (o.sub || "")).toLowerCase().includes(q.toLowerCase()))
      .sort((a, b) => on.includes(b.id) - on.includes(a.id));  // selected first
    return shown.length ? shown.map(o => h("label", { class: "dd-opt" },
      h("input", { type: "checkbox", checked: sel(key).includes(o.id), onchange: ev => {
        const s = new Set(sel(key)); ev.target.checked ? s.add(o.id) : s.delete(o.id);
        ui.f[key] = [...s]; val.textContent = btnText(); d.classList.toggle("on", s.size > 0); onchange();
      } }),
      h("span", { class: "ell" }, o.name), o.sub ? h("span", { class: "muted small ell" }, o.sub) : null))
      : [h("div", { class: "muted small", style: "padding:8px" }, "No match.")];
  })());
  const search = opts.length > 6 ? h("input", { class: "dd-search", type: "search", placeholder: `Find ${label.toLowerCase()}`, "aria-label": `Find ${label.toLowerCase()}`,
    oninput: ev => draw(ev.target.value) }) : null;
  const d = h("details", { class: "dd" + (sel(key).length ? " on" : "") },
    h("summary", { class: "btn sm" }, h("span", { class: "muted" }, label + ":"), val, icon("chev")),
    h("div", { class: "dd-pop" }, search, listBox,
      h("div", { class: "dd-foot" }, h("button", { type: "button", class: "btn sm", onclick: () => {
        ui.f[key] = []; val.textContent = btnText(); d.classList.remove("on"); draw(search?.value || ""); onchange();
      } }, "Clear"))));
  d.addEventListener("toggle", () => {
    if (!d.open) return;
    // fixed, so the scrolling list pane can't clip it; clamped to the viewport
    const r = d.querySelector("summary").getBoundingClientRect(), pop = d.querySelector(".dd-pop");
    pop.style.left = Math.max(8, Math.min(r.left, innerWidth - 268)) + "px"; pop.style.top = (r.bottom + 4) + "px";
    draw(""); if (search) { search.value = ""; search.focus(); }
  });
  return d;
}
document.addEventListener("click", ev => document.querySelectorAll("details.dd[open]").forEach(d => { if (!d.contains(ev.target)) d.open = false; }));
document.addEventListener("scroll", ev => { if (!ev.target.closest?.(".dd-pop")) document.querySelectorAll("details.dd[open]").forEach(d => { d.open = false; }); }, true);
document.addEventListener("keydown", ev => { if (ev.key === "Escape") document.querySelectorAll("details.dd[open]").forEach(d => { d.open = false; d.querySelector("summary").focus(); }); });

async function renderSessions(sidArg, stepArg) {
  const [res, fl] = await Promise.all([api("/sessions"), fleet().catch(() => ({ peers: [], roles: [] }))]);
  const all = Array.isArray(res) ? res : res.sessions;  // ponytail: filtered in the browser; send filters to the API past ~10k sessions
  if (sidArg && !all.filter(matches).some(x => x.id === sidArg)) { ui.f = {}; ui.sq = ""; }
  const items = all.filter(matches);
  const sid = sidArg || (ui.trace && items.some(x => x.id === ui.trace.sid) ? ui.trace.sid : items[0]?.id);
  const pick = id => { location.hash = sessHref(id); };
  const body = h("div", { class: "slist-b" });
  const count = h("span", { class: "muted small", style: "margin-left:auto" });
  const drawList = () => {
    const rows = all.filter(matches);
    count.textContent = `${n(rows.length)} of ${n(all.length)}`;
    setExportCount(rows.reduce((a, x) => a + x.n, 0));
    body.replaceChildren(rows.length ? tbl([null, "76px", "52px", "52px", "96px"], ["Agent and peer", "Started", ["Steps", "r"], "State", "Last"],
      rows.map(x => h("tr", linkRow(() => pick(x.id), x.id === sid ? "sel" : "", { "aria-selected": String(x.id === sid) }),
        h("td", { title: `${x.agent} on ${x.peer_label} (${x.id})` }, h("div", { class: "two" }, h("span", { class: "ell" }, x.agent, x.active ? h("span", { class: "live", title: "Active" }) : null),
          h("span", { class: "ell muted small" }, x.peer_label, " · ", x.id))),
        h("td", { class: "num" }, time(x.first_ts)),
        h("td", { class: "num r" }, n(x.n)),
        h("td", {}, stateIcons(x.state)),
        h("td", {}, lastOutcome(x.last_verdict)))))
      : h("div", { class: "empty" }, "No sessions match these filters."));
  };
  const peerOpts = fl.peers.map(p => ({ id: p.id, name: p.device || p.label || p.id, sub: p.owner }));
  const filters = h("div", { class: "fbar" },
    h("input", { class: "search", type: "search", placeholder: "Search agent, laptop or session", "aria-label": "Search sessions", value: ui.sq || "",
      oninput: ev => { ui.sq = ev.target.value; drawList(); } }),
    h("div", { class: "fbar-row" },
      dropdown("peer", "Peer", peerOpts, drawList),
      dropdown("role", "Role", fl.roles.map(r => ({ id: r.role, name: roleName(r.role), sub: r.role })), drawList),
      dropdown("state", "State", STATES.map(s => ({ id: s, name: STATE[s] })), drawList),
      count));
  drawList();
  const list = h("section", { class: "card pane", "data-keep": "slist" }, filters, body);
  const right = h("section", { class: "card pane split" });
  view().replaceChildren(h("div", { class: "md" }, list, right));
  if (!sid) return right.replaceChildren(h("div", { class: "empty" }, "No session to show."));
  let d;
  try { d = await api("/sessions/" + enc(sid)); } catch (err) {
    return right.replaceChildren(h("div", { class: "empty" }, String(err.message).startsWith("404") ? "This session is not on the server any more." : "Could not load this session."));
  }
  drawSession(right, d, stepArg);
}

function drawSession(box, d, stepArg) {
  const tl = d.timeline, x = d.session, sid = x.id;
  let idx = -1;
  if (stepArg && isNaN(stepArg)) idx = tl.findIndex(e => e.trace_id === stepArg);
  else if (stepArg) idx = Number(stepArg) - 1;
  if (!(idx >= 0 && idx < tl.length)) {
    idx = ui.trace && ui.trace.sid === sid ? ui.trace.idx : -1;
    if (!(idx >= 0 && idx < tl.length)) { const b = tl.findIndex(e => e.kind === "blocked"); idx = b >= 0 ? b : tl.length - 1; }
  }
  ui.trace = { sid, idx };
  if (stepArg !== String(idx + 1)) history.replaceState(null, "", sessHref(sid, idx + 1));
  const c = x.counts || {};
  const strip = h("div", { class: "strip" }, [
    ["Peer", x.peer_label || "–"], ["Agent", x.agent], ["Role", x.role], ["Started", time(x.first_ts)], ["Duration", dur(x.duration_s)], ["Steps", n(x.n)],
    ["Blocked", n(c.block)], ["Masked", n(c.redact)], ["State", stateEl(x.state)],
  ].map(([k, v]) => h("div", {}, h("div", { class: "k" }, k), h("div", { class: "v" }, v))));
  const steps = h("div", { class: "steps" }), detail = h("div", { class: "detail", "data-keep": "sdetail" });
  box.replaceChildren(h("div", { class: "pane-h" }, h("h2", {}, x.agent), h("span", { class: "muted small mono ell", title: sid }, sid),
    x.peer ? h("a", { class: "small", href: peerHref(x.peer) }, x.peer_label) : null,
    h("span", { class: "muted small", style: "margin-left:auto" }, x.active ? "Active" : "Ended")), strip, steps, detail);
  const draw = () => { drawSteps(steps, tl, draw); drawDetail(detail, tl[ui.trace.idx], x); };
  draw();
}

function drawSteps(box, tl, redraw) {
  const t0 = new Date(tl[0].ts).getTime(), span = Math.max(1, new Date(tl[tl.length - 1].ts).getTime() - t0);
  const pick = i => { ui.trace.idx = i; history.replaceState(null, "", sessHref(ui.trace.sid, i + 1)); redraw(); };
  const seg = h("div", { class: "seg", role: "group", "aria-label": "Step view" }, [["list", "List"], ["timeline", "Timeline"]].map(([k, l]) =>
    h("button", { type: "button", "aria-pressed": String(ui.stepMode === k), onclick: () => { ui.stepMode = k; redraw(); } }, l)));
  const rows = tl.map((e, i) => {
    const cur = String(i === ui.trace.idx);
    if (ui.stepMode === "timeline") {
      const off = (new Date(e.ts).getTime() - t0) / span;
      return h("li", {}, h("button", { class: "step tl", "aria-current": cur, onclick: () => pick(i) },
        h("span", { class: "tm" }, "+" + ((new Date(e.ts).getTime() - t0) / 1000).toFixed(1) + " s"),
        h("span", { class: "nm ell", title: e.explain.tool_name }, e.explain.tool_name), badge(e.kind) || h("span", {}),
        h("span", { class: "lane" }, h("i", { class: e.kind === "blocked" ? "blocked" : "", style: `left:calc(${off * 100}% - ${off * 4}px)` }))));
    }
    return h("li", {}, h("button", { class: "step", "aria-current": cur, onclick: () => pick(i) },
      h("span", { class: "no" }, i + 1), h("span", { class: "nm ell", title: e.explain.tool_name }, e.explain.tool_name),
      badge(e.kind) || h("span", {}), h("span", { class: "ms" }, ms(e.ms))));
  });
  box.replaceChildren(h("div", { class: "steps-h" }, h("h2", {}, "Steps"), seg), h("ul", { class: "steplist", "data-keep": "steps" }, rows));
}

const TABS = [["overview", "Overview"], ["checks", "Checks"], ["fingerprint", "Fingerprint"]];

function drawDetail(box, e, sess) {
  const x = e.explain;
  if (!TABS.some(([k]) => k === ui.tab)) ui.tab = "overview";
  const pane = h("div", { class: "tabpane", role: "tabpanel" });
  const tabs = h("div", { class: "tabs", role: "tablist" }, TABS.map(([k, l]) => h("button", { type: "button", role: "tab", "aria-selected": String(ui.tab === k),
    onclick: () => { ui.tab = k; drawDetail(box, e, sess); } }, l)));
  pane.append(...({ overview: tabOverview, checks: tabChecks, fingerprint: tabFingerprint }[ui.tab])(e, x, sess));
  box.replaceChildren(h("div", { class: "detail-h" }, h("h2", {}, x.sentence),
    h("div", { class: "meta" }, h("span", { class: "num" }, time(e.ts)), badge(e.kind), e.action ? h("span", {}, e.action) : null, e.ms ? h("span", {}, ms(e.ms)) : null)), tabs, pane);
}

function tabFingerprint(e, x, sess) {
  const fp = e.content_sha256;
  return [h("div", { class: "local" }, icon("lock"), "The text stays on the peer's laptop. The server keeps the decision and this fingerprint only."),
    kv([["Fingerprint (SHA-256)", fp ? h("span", { class: "fp" }, h("code", {}, fp), h("button", { class: "btn sm", type: "button", onclick: ev => copy(fp, ev.currentTarget) }, "Copy")) : "–"],
      ["Decision", VERDICT[e.verdict] || e.verdict], ["Check", e.action || "Every check passed"], ["Tool", x.tool_name],
      ["Peer", sess.peer_label || "–"], ["Session state", (e.state_after || "clean").split("+").map(k => STATE[k] || k).join(" + ")],
      ["Time", time(e.ts)], ["Trace ID", h("code", {}, e.trace_id || "–")]])];
}

/* ---------- Policy: read-only, plus the profile switch ---------- */
const cap = x => x ? x[0].toUpperCase() + x.slice(1) : x;
const profileLabel = d => (cap(d.profiles.current) || "Custom") + (d.status.modified ? " (edited)" : "");
const ACCESS = { read: "Read", write: "Write", asks: "Asks a human" };
const errText = e => e ? (typeof e === "string" ? e : e.message) : "";
const short = v => String(v ?? "–").slice(0, 7);

async function renderPolicy() {
  const d = await api("/policy");
  ui.pol = d;
  if (ui.edit && !pending().length) ui.edit.base = d.status.version;  // nothing pending: follow the live version
  renderBar();
  const st = d.status, err = st.last_error;
  const strip = h("div", { class: "strip" }, [
    ["Version", h("code", { title: st.version }, short(st.version))], ["Profile", profileLabel(d)], ["Loaded", st.loaded_at ? time(st.loaded_at) : "–"],
    ["File", h("code", {}, st.path || "–")],
  ].map(([k, v]) => h("div", {}, h("div", { class: "k" }, k), h("div", { class: "v" }, v))));
  const inForce = h("section", { class: "card" }, h("div", { class: "card-h" }, h("h2", {}, "In force"),
    h("span", { class: "muted small" }, "Live: edits to the policy file apply on the next call")), strip,
    err ? h("div", { class: "rejected", role: "alert" }, icon("warn"),
      h("span", {}, `Edit rejected${err.at ? " at " + time(err.at) : ""}: `, h("span", { class: "mono" }, errText(err)), `. Still enforcing ${short(st.version)}.`)) : null);
  view().replaceChildren(h("div", { class: "stack" }, inForce, matrixCard(d.matrix), rulesCard(d.rules), historyCard(d.history, st.version)));
}

function matrixCard(m) {
  if (ui.edit) return editMatrixCard(m);
  const cell = c => !c || c.access === "hidden"
    ? h("td", { class: "mx-c hidden", title: "Hidden from this role" }, h("span", { "aria-label": "Hidden" }, "–"))
    : h("td", { class: "mx-c " + c.access }, h("div", {}, ACCESS[c.access] || c.access),
      (c.limits || []).length ? h("div", { class: "lim", title: c.limits.join("; ") }, c.limits.join("; ")) : null);
  const table = h("table", { class: "t mx" },
    h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Tool"), h("th", { scope: "col" }, "Data flow"),
      m.roles.map(r => h("th", { scope: "col", title: `${r.agent} (${r.role})` }, h("div", { class: "two" }, h("span", { class: "ell" }, r.agent), h("span", { class: "muted small mono" }, r.role)))))),
    m.servers.map(srv => h("tbody", {},
      h("tr", { class: "grp" }, h("th", { scope: "colgroup", colspan: String(m.roles.length + 2) }, srv.name, h("span", { class: "sub-l small" }, `${srv.tools.length} tools`))),
      srv.tools.map(t => h("tr", {},
        h("th", { scope: "row", title: t.name }, h("div", { class: "two" }, h("span", { class: "ell" }, t.plain), h("span", { class: "ell muted small mono" }, t.name))),
        h("td", { class: (t.labels || []).length ? "" : "muted" }, (t.labels || []).join(", ") || "–"),
        m.roles.map(r => cell(t.cells[r.role])))))),
    (m.builtins || []).length ? h("tbody", {},
      h("tr", { class: "grp" }, h("th", { scope: "colgroup", colspan: String(m.roles.length + 2) }, "Agent built-in tools", h("span", { class: "sub-l small" }, "seen through the hook; read-only here"))),
      m.builtins.map(t => h("tr", {},
        h("th", { scope: "row", title: t.name }, h("div", { class: "two" }, h("span", { class: "ell" }, t.plain), h("span", { class: "ell muted small mono" }, t.name))),
        h("td", { class: (t.labels || []).length ? "" : "muted" }, (t.labels || []).join(", ") || "–"),
        m.roles.map(r => t.cells[r.role]?.access === "denied"
          ? h("td", { class: "mx-c hidden", title: "Denied for this role" }, h("div", {}, "Denied"))
          : h("td", { class: "mx-c read" }, h("div", {}, "Allowed")))))) : null);
  const c = card("Who may do what", h("span", { class: "muted small" }, "Hidden tools are not listed to the role and are refused if called"),
    h("div", { class: "mx-wrap", "data-keep": "matrix" }, table));
  c.dataset.mx = "1";
  return c;
}

// Rule actions are neutral badges: red stays for real Blocked events and problems, not for describing the policy.
// rule actions come as plain lowercase words from the API (block | mask | ask a human | off)
const RULE_ACT = { block: ["ban", "Blocks"], mask: ["lock", "Masks"], "ask a human": ["clock", "Asks a human"], off: ["dash", "Off"] };
const rulesCard = rules => card("Rules in plain words", null, h("div", { class: "rules" }, rules.map(r => h("div", { class: "rule" },
  h("div", { class: "rule-h" }, h("h3", {}, r.title), h("span", { class: "badge" }, icon((RULE_ACT[r.action] || ["flag"])[0]), (RULE_ACT[r.action] || [, r.action])[1])),
  h("p", {}, r.sentence)))));

const historyCard = (hist, cur) => card("Version history", h("span", { class: "muted small" }, "Every version this hub has seen, newest first"),
  hist.length ? tbl(["140px", "150px", "120px", "120px", null], ["Version", "Time", "Profile", "Result", "Reason"],
    hist.map(x => h("tr", {},
      h("td", { class: "mono", title: x.version }, short(x.version), x.ok && x.version === cur ? h("span", { class: "tag-if" }, "in force") : null),
      h("td", { class: "num muted" }, time(x.at)),
      h("td", {}, cap(x.profile) || "Custom"),
      h("td", {}, x.ok ? h("span", { class: "state" }, icon("check"), "Applied") : h("span", { class: "badge fail" }, icon("x"), "Rejected")),
      h("td", { class: x.error ? "mono small" : x.note ? "" : "muted", title: errText(x.error) || x.note || "" }, errText(x.error) || x.note || "–"))))
    : h("div", { class: "empty" }, "No versions recorded yet."));

function switchDialog(d) {
  const P = d.profiles, cur = P.current, edited = d.status.modified;
  let target = null;
  const err = h("p", { class: "err small", role: "alert" });
  const changes = h("div", { class: "chg", "aria-live": "polite" }, h("p", { class: "muted" }, "Pick a profile to see what would change."));
  const cancel = h("button", { class: "btn", type: "button", autofocus: true, onclick: () => dlg.close() }, "Cancel");
  const go = h("button", { class: "btn primary", type: "button", disabled: true, onclick: async () => {
    go.disabled = true; err.textContent = "";
    try {
      const r = await post("/policy/profile", { profile: target });
      body.replaceChildren(h("p", {}, `Switched to ${cap(target)}. Version `, h("code", {}, short(r.status?.version)), " applies from the next call."),
        h("p", { class: "muted" }, "The previous policy file is saved as ", h("code", {}, r.backup || "–"), "."));
      cancel.textContent = "Close"; go.remove(); cancel.focus();
      refreshStatus(); route(false);
    } catch (e) { err.textContent = String(e.message); go.disabled = false; }
  } }, "Switch");
  const pick = name => {
    target = name;
    table.querySelectorAll("[data-p]").forEach(el => el.classList.toggle("tgt", el.dataset.p === name));
    go.disabled = false; go.textContent = `Switch to ${cap(name)}`;
    const xs = name === cur ? [] : (P.changes || {})[name] || [];
    const grp = (dir, label) => {
      const ys = xs.filter(x => x.direction === dir);
      return ys.length ? h("div", {}, h("h3", {}, `${label} (${ys.length})`), h("ul", { class: "plain" }, ys.map(x => h("li", {}, x.plain)))) : null;
    };
    changes.replaceChildren(name === cur ? h("p", {}, `Restores the ${cap(cur)} profile as written: the edits in the file are replaced.`)
      : xs.length ? h("div", { class: "grid2" }, grp("stricter", "Stricter"), grp("looser", "Looser")) : h("p", { class: "muted" }, "No setting changes."));
  };
  const head = name => h("th", { scope: "col", "data-p": name, class: name === cur ? "cur" : null },
    h("label", {}, h("input", { type: "radio", name: "prof", value: name, disabled: name === cur && !edited, onchange: () => pick(name) }),
      cap(name), name === cur ? h("span", { class: "tag" }, edited ? "in force, edited" : "in force") : null));
  const table = h("table", { class: "t pdiff" }, h("colgroup", {}, h("col", {}), P.names.map(() => h("col", { style: "width:20%" }))),
    h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Setting"), P.names.map(head))),
    h("tbody", {}, P.diff.map(r => h("tr", {}, h("th", { scope: "row" }, r.plain),
      P.names.map(nm => h("td", { "data-p": nm, class: nm === cur ? "cur" : null }, r.values[nm] ?? "–"))))));
  const body = h("div", {},
    h("p", {}, "Only the settings that differ between the profiles are shown. Pick the profile to switch to."),
    edited ? h("div", { class: "warnbox" }, icon("warn"), h("span", {}, "The policy file has edits that are not in the profile. Switching replaces them; the current file is kept in ",
      h("code", {}, "audit/policy-backups/"), ".")) : null,
    h("div", { class: "pdiff-wrap" }, table), changes, err);
  const dlg = dialog("Switch policy profile", body, [cancel, go]);
  dlg.classList.add("wide");
}

/* ---------- Policy: edit access (revision 3). ui.edit = { base: version, want: {"role\ttool": bool} } ---------- */
const accKey = (role, tool) => role + "\t" + tool;
const lower1 = x => x ? x[0].toLowerCase() + x.slice(1) : x;
const isAllowed = (t, role) => (t.cells[role]?.access || "hidden") !== "hidden";
const want = (t, role) => ui.edit.want[accKey(role, t.name)] ?? isAllowed(t, role);
const plural = (k, w) => `${k} ${w}${k === 1 ? "" : "s"}`;

// Every role x tool whose wanted state differs from the policy in force.
function pending() {
  if (!ui.edit || !ui.pol) return [];
  const m = ui.pol.matrix, out = [];
  for (const t of m.servers.flatMap(s => s.tools)) for (const r of m.roles) {
    const w = want(t, r.role);
    if (w !== isAllowed(t, r.role)) out.push({ role: r.role, agent: r.agent, tool: t.name, allowed: w, t });
  }
  return out;
}

function toggleEdit() {
  if (!ui.edit) ui.edit = { base: ui.pol.status.version, want: {} };
  else {
    const k = pending().length;
    if (k && !confirm(`Discard ${plural(k, "unsaved access change")}?`)) return;
    ui.edit = null; ui.dirty = false;
  }
  renderBar(); redrawMatrix();
}

function setWant(list) {
  for (const [role, tool, v] of list) ui.edit.want[accKey(role, tool)] = v;
  ui.dirty = pending().length > 0;  // the 10 s poll leaves the view alone while edits are pending
  redrawMatrix();
}

// Re-render only the matrix card, keeping its scroll position and the focused control.
function redrawMatrix() {
  const old = document.querySelector("[data-mx]");
  if (!old || !ui.pol) return;
  const w = old.querySelector(".mx-wrap"), top = w?.scrollTop || 0, left = w?.scrollLeft || 0, fk = document.activeElement?.dataset?.k;
  const nu = matrixCard(ui.pol.matrix);
  old.replaceWith(nu);
  const w2 = nu.querySelector(".mx-wrap");
  if (w2) { w2.scrollTop = top; w2.scrollLeft = left; }
  if (fk) [...nu.querySelectorAll("[data-k]")].find(el => el.dataset.k === fk)?.focus();
}

function editMatrixCard(m) {
  const P = pending(), changed = new Set(P.map(p => accKey(p.role, p.tool)));
  const cell = (t, r) => {
    const k = accKey(r.role, t.name), on = want(t, r.role), lim = t.cells[r.role]?.limits || [];
    return h("td", { class: "mx-c ed" + (changed.has(k) ? " chg" : "") },
      h("div", { class: "ed-row" },
        h("button", { type: "button", class: "tgl", "data-k": k, "aria-pressed": String(on), "aria-label": `${t.plain} (${t.name}) for ${r.agent}`,
          title: changed.has(k) ? `Changed: was ${on ? "hidden" : "allowed"}` : null, onclick: () => setWant([[r.role, t.name, !on]]) },
          h("span", { class: "sw", "aria-hidden": "true" }), on ? "Allowed" : "Hidden"),
        h("span", { class: "kind", title: "Set by the MCP server" }, t.write ? "Write" : "Read")),
      lim.length ? h("div", { class: "lim", title: lim.join("; ") }, lim.join("; ")) : null);
  };
  const quick = (srv, r) => {
    const ts = srv.tools, on = ts.filter(t => want(t, r.role)), reads = ts.filter(t => !t.write);
    const now = !on.length ? "none" : on.length === ts.length ? "all" : on.length === reads.length && on.every(t => !t.write) ? "read" : null;
    return h("td", { class: "qs" }, h("div", { class: "seg", role: "group", "aria-label": `${srv.name} for ${r.agent}` },
      [["none", "Hidden", () => false], ["read", "Read only", t => !t.write], ["all", "All tools", () => true]].map(([key, label, f]) =>
        h("button", { type: "button", "data-k": `q\t${srv.name}\t${r.role}\t${key}`, "aria-pressed": String(now === key),
          onclick: () => setWant(ts.map(t => [r.role, t.name, f(t)])) }, label))));
  };
  const table = h("table", { class: "t mx editing" },
    h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Tool"), h("th", { scope: "col" }, "Data flow"),
      m.roles.map(r => h("th", { scope: "col", title: `${r.agent} (${r.role})` }, h("div", { class: "two" }, h("span", { class: "ell" }, r.agent), h("span", { class: "muted small mono" }, r.role)))))),
    m.servers.map(srv => h("tbody", {},
      h("tr", { class: "grp" }, h("th", { scope: "colgroup", colspan: "2" }, srv.name, h("span", { class: "sub-l small" }, `${srv.tools.length} tools`)),
        m.roles.map(r => quick(srv, r))),
      srv.tools.map(t => h("tr", {},
        h("th", { scope: "row", title: t.name }, h("div", { class: "two" }, h("span", { class: "ell" }, t.plain), h("span", { class: "ell muted small mono" }, t.name))),
        h("td", { class: (t.labels || []).length ? "" : "muted" }, (t.labels || []).join(", ") || "–"),
        m.roles.map(r => cell(t, r)))))));
  const editbar = h("div", { class: "editbar" },
    h("span", { class: "small" + (P.length ? "" : " muted"), "aria-live": "polite" }, P.length ? plural(P.length, "change") : "No changes yet"),
    h("button", { class: "btn sm", type: "button", disabled: !P.length, onclick: () => { ui.edit.want = {}; ui.dirty = false; redrawMatrix(); } }, "Discard"),
    h("button", { class: "btn sm primary", type: "button", disabled: !P.length, onclick: reviewDialog }, "Review changes…"));
  const c = card("Who may do what", editbar,
    h("p", { class: "muted small ed-hint" }, "Editing access. Each cell allows or hides one tool for one role; the server row sets a whole MCP server. Read or Write is fixed by the server. Limits stay as they are."),
    h("div", { class: "mx-wrap", "data-keep": "matrix" }, table));
  c.dataset.mx = "1";
  return c;
}

const accessSentence = p => p.allowed
  ? `${p.agent} may now ${lower1(p.t.plain)} (${[p.t.write ? "write" : "read", ...(p.t.labels || [])].join(", ")})`
  : `${p.agent} can no longer ${lower1(p.t.plain)}`;

// A role that gains a public destination while it can read outside text and private data: the data-flow rule is what guards it.
function flowWarnings(P) {
  const flow = (ui.pol.rules || []).find(r => r.id === "data_flow");
  const all = ui.pol.matrix.servers.flatMap(s => s.tools);
  return ui.pol.matrix.roles.filter(r => P.some(p => p.role === r.role && p.allowed && (p.t.labels || []).includes("public destination")))
    .filter(r => ["outside text", "private data"].every(l => all.some(t => want(t, r.role) && (t.labels || []).includes(l))))
    .map(r => `${r.agent} can now read outside text and private data and send to a public destination. ` + (flow?.action === "off"
      ? "The data-flow rule is off, so nothing stops private data from leaving."
      : `The data-flow rule still guards this: ${lower1(flow?.sentence || "a call to a public destination after both is blocked.")}`));
}

function reviewDialog() {
  const err = h("p", { class: "err small", role: "alert" });
  const body = h("div", {});
  const cancel = h("button", { class: "btn", type: "button", autofocus: true, onclick: () => dlg.close() }, "Back to editing");
  const go = h("button", { class: "btn primary", type: "button", onclick: save });
  const fill = notice => {
    const P = pending();
    go.textContent = P.length ? `Save ${plural(P.length, "change")}` : "Save"; go.disabled = !P.length;
    body.replaceChildren(h("div", {},
      notice ? h("div", { class: "warnbox", role: "alert" }, icon("warn"), h("span", {}, notice)) : null,
      P.length ? ui.pol.matrix.roles.filter(r => P.some(p => p.role === r.role)).map(r => h("div", { class: "chg" },
        h("h3", {}, r.agent, h("span", { class: "sub-l mono" }, r.role)), h("ul", { class: "plain" }, P.filter(p => p.role === r.role).map(p => h("li", {}, accessSentence(p))))))
        : h("p", { class: "muted" }, "Nothing left to save: the policy in force already says this."),
      flowWarnings(P).map(w => h("div", { class: "warnbox" }, icon("warn"), h("span", {}, w))),
      h("p", { class: "muted small" }, "Saving backs up the policy file, writes the new access and applies it from the next call. Comments in the file are not kept; the backup has them."),
      err));
  };
  async function save() {
    const P = pending();
    go.disabled = true; err.textContent = "";
    let r, j = {};
    try {
      r = await fetch(API + "/policy/access", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ base_version: ui.edit.base, changes: P.map(({ role, tool, allowed }) => ({ role, tool, allowed })) }) });
      j = await r.json().catch(() => ({}));
    } catch { err.textContent = "Could not reach the server. Nothing was saved."; go.disabled = false; return; }
    if (r.status === 409) {  // someone changed the file: review against the version now in force
      ui.edit.base = j.version;
      await route(false);
      ui.dirty = pending().length > 0;
      return fill(`The policy changed while you were editing (now ${short(j.version)}). Review again.`);
    }
    if (!r.ok) { err.textContent = `Not saved: ${j.error || r.status}`; go.disabled = false; return; }
    ui.edit = null; ui.dirty = false;
    body.replaceChildren(h("p", {}, "Saved. Version ", h("code", {}, short(j.status?.version)), " applies from the next call."),
      h("ul", { class: "plain" }, (j.sentences || []).map(x => h("li", {}, x))),
      h("p", { class: "muted" }, "The previous policy file is saved as ", h("code", {}, j.backup || "–"), "."));
    cancel.textContent = "Close"; go.remove(); cancel.focus();
    refreshStatus(); route(false);
  }
  fill();
  const dlg = dialog("Review access changes", body, [cancel, go]);
  dlg.classList.add("mid");
}

/* ---------- routing + live refresh ---------- */
const VIEWS = { overview: renderOverview, peers: renderPeers, roles: renderRoles, sessions: renderSessions, policy: renderPolicy, feed: renderFeed, selftest: renderSelftest, try: renderTry };
async function route(focus) {
  const parts = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  ui.view = VIEWS[parts[0]] ? parts[0] : "overview";
  const nav = ui.view === "roles" ? "peers" : ui.view;
  document.querySelectorAll(".nav a").forEach(a => a.dataset.view === nav ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"));
  renderBar();
  const keep = Object.fromEntries([...document.querySelectorAll("[data-keep]")].map(el => [el.dataset.keep, el.scrollTop]));
  try {
    await VIEWS[ui.view](parts[1], parts[2]);
  } catch (err) {
    view().replaceChildren(h("div", { class: "notice" }, h("span", { class: "cdot" }), "Could not reach the server. The page retries every 10 seconds.",
      h("button", { class: "btn sm", style: "margin-left:auto", onclick: () => route(false) }, "Retry")));
  }
  document.querySelectorAll("[data-keep]").forEach(el => { if (keep[el.dataset.keep]) el.scrollTop = keep[el.dataset.keep]; });
  if (focus) view().focus({ preventScroll: true });
}
window.addEventListener("hashchange", () => {
  if (ui.edit && !/^#\/?policy/.test(location.hash)) {  // leaving the Policy view: pending access edits ask first
    const k = pending().length;
    if (k && !confirm(`Discard ${k} unsaved access change${k === 1 ? "" : "s"}?`)) return history.replaceState(null, "", "#/policy");
    ui.edit = null; ui.dirty = false;
  }
  route(true);
});
window.addEventListener("beforeunload", ev => { if (ui.edit && pending().length) ev.preventDefault(); });

// Poll every 10 s; skip the view while a dialog is open, a role edit is unsaved, or a control has focus.
setInterval(() => {
  refreshStatus();
  if (document.querySelector("dialog[open], details.dd[open]") || ui.dirty || document.activeElement?.matches?.("input, select, textarea, #view :focus-visible")) return;
  route(false);
}, 10000);

renderThemeBtn();
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", renderThemeBtn);
refreshStatus();
route(false);
