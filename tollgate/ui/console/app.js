// Tollgate server console, revision 1: Overview, Peers & roles, Sessions. Vanilla JS, no build step.
// Shared helpers (h, icon, badge, time, trend, hbars, serverList, tabOverview, tabChecks, ...) come from /edge/common.js.
"use strict";

const API = "/console/api";
const STATES = ["clean", "untrusted", "holds_private"];
PATHS.plus = ["M12 5v14M5 12h14"];

const ui = { view: "overview", range: load("c.range") || "today", since: load("c.since") || "", tab: "overview", stepMode: "list",
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
  const admin = typeof st.admin === "string" ? st.admin : (st.admin && (st.admin.name || st.admin.id)) || "Admin";
  box.title = [`Policy ${String(st.policy.version).slice(0, 7)} (${st.policy.profile})`, `Threat feed ${st.feed?.version ?? "local"}`, `App ${st.app_version}`].join("\n");
  box.replaceChildren(h("span", { class: "who" }, icon("user"), admin), h("span", { class: "sep" }), h("span", {}, h("span", { class: "cdot" }), location.host));
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
      onclick: () => { ui.range = k; save("c.range", k); renderBar(); route(false); } }, l))));
  }
  if (ui.view === "peers" || ui.view === "roles") {
    return bar(h("div", { class: "seg", role: "group", "aria-label": "Peers or roles" }, [["peers", "Peers"], ["roles", "Roles"]].map(([k, l]) =>
      h("button", { type: "button", "aria-pressed": String(ui.view === k), onclick: () => { location.hash = k === "peers" ? peerHref(ui.peer) : roleHref(ui.role); } }, l))),
      ui.view === "peers" ? h("button", { class: "btn", type: "button", onclick: enrollDialog }, icon("plus"), "Enroll a laptop") : null);
  }
  bar();
}

/* ---------- Overview ---------- */
async function renderOverview() {
  const o = await api("/overview?range=" + ui.range);
  const k = o.kpis;
  const tiles = [["checked", "Actions checked"], ["blocked", "Blocked"], ["attacks", "Attacks stopped"], ["peers_online", "Peers online"]];
  const d = (key, x) => key === "peers_online" && x.prev == null ? "right now" : delta(x, ui.range);
  const hasData = k.checked.value > 0;
  view().replaceChildren(h("div", { class: "stack" },
    h("div", { class: "kpis" }, tiles.map(([key, l]) => h("div", { class: "card kpi" },
      h("div", { class: "l" }, l), h("div", { class: "v" }, n(k[key].value)), h("div", { class: "d" }, d(key, k[key]))))),
    card("Actions over time", h("div", { class: "legend" }, h("span", {}, h("i", { class: "f-allow" }), "Allowed"),
      h("span", {}, h("i", { class: "f-mid" }), "Masked or waiting"), h("span", {}, h("i", { class: "f-block" }), "Blocked")),
      hasData ? h("div", { class: "card-b" }, trend(o.series, o.bucket_s), h("div", { class: "chart-foot" }, `One bar per ${bucketWords(o.bucket_s)}, all peers.`))
        : h("div", { class: "empty" }, "No actions in this time range.")),
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

/* ---------- Sessions: master-detail across all peers ---------- */
async function renderSessions(sidArg, stepArg) {
  const q = new URLSearchParams(Object.entries(ui.f).filter(([, v]) => v));
  const [res, fl] = await Promise.all([api("/sessions?" + q), fleet().catch(() => ({ peers: [], roles: [] }))]);
  // Apply the filters here too, so the list is right whatever the server's state matching is.
  let items = (Array.isArray(res) ? res : res.sessions).filter(x => (!ui.f.peer || x.peer === ui.f.peer) && (!ui.f.role || x.role === ui.f.role)
    && (!ui.f.state || (x.state || "clean").split("+").includes(ui.f.state)));
  if (sidArg && !items.some(x => x.id === sidArg) && Object.values(ui.f).some(Boolean)) { ui.f = {}; return renderSessions(sidArg, stepArg); }
  const peerNames = Object.fromEntries(fl.peers.map(p => [p.id, p.device]));
  const group = (key, label, opts, words) => h("div", { class: "pills", role: "group", "aria-label": label }, h("span", { class: "lab" }, label),
    [null, ...opts].map(v => h("button", { type: "button", class: "fpill", "aria-pressed": String((ui.f[key] || null) === v),
      onclick: () => { ui.f[key] = v; if (location.hash === "#/sessions") route(false); else location.hash = "#/sessions"; } }, v == null ? "All" : words(v))));
  const filters = h("div", { class: "filters" },
    group("peer", "Peer", fl.peers.map(p => p.id), v => peerNames[v] || v),
    group("role", "Role", fl.roles.map(r => r.role), roleName),
    group("state", "State", STATES, v => STATE[v]));
  const sid = sidArg || (ui.trace && items.some(x => x.id === ui.trace.sid) ? ui.trace.sid : items[0]?.id);
  const pick = id => { location.hash = sessHref(id); };
  const list = h("section", { class: "card pane", "data-keep": "slist" }, filters,
    items.length ? tbl([null, "76px", "52px", "52px", "96px"], ["Agent and peer", "Started", ["Steps", "r"], "State", "Last"],
      items.map(x => h("tr", linkRow(() => pick(x.id), x.id === sid ? "sel" : "", { "aria-selected": String(x.id === sid) }),
        h("td", { title: `${x.agent} on ${x.peer_label} (${x.id})` }, h("div", { class: "two" }, h("span", { class: "ell" }, x.agent, x.active ? h("span", { class: "live", title: "Active" }) : null),
          h("span", { class: "ell muted small" }, x.peer_label, " · ", x.id))),
        h("td", { class: "num" }, time(x.first_ts)),
        h("td", { class: "num r" }, n(x.n)),
        h("td", {}, stateIcons(x.state)),
        h("td", {}, lastOutcome(x.last_verdict)))))
      : h("div", { class: "empty" }, "No sessions match these filters."));
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

/* ---------- routing + live refresh ---------- */
const VIEWS = { overview: renderOverview, peers: renderPeers, roles: renderRoles, sessions: renderSessions };
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
window.addEventListener("hashchange", () => route(true));

// Poll every 10 s; skip the view while a dialog is open, a role edit is unsaved, or a control has focus.
setInterval(() => {
  refreshStatus();
  if (document.querySelector("dialog[open]") || ui.dirty || document.activeElement?.matches?.("input, select, textarea, #view :focus-visible")) return;
  route(false);
}, 10000);

renderThemeBtn();
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", renderThemeBtn);
refreshStatus();
route(false);
