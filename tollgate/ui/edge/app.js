// Tollgate local edge UI v3. Vanilla JS, no build step, no network beyond this gateway.
"use strict";

const API = "/edge/api";
const VERDICT = { allow: "Allowed", redact: "Masked", approve: "Waiting", block: "Blocked" };
const KIND = { blocked: "Blocked", masked: "Masked", waiting: "Waiting", flagged: "Flagged" };
const STAGE = { key: "Key", role: "Role", arguments: "Arguments", data_flow: "Data flow", content: "Content", budget: "Budget", approval: "Approval" };
const OUTCOME = { ok: "ok", warn: "flagged", fail: "failed", skip: "skipped" };
const STATE = { clean: "Clean", untrusted: "Untrusted", holds_private: "Holds private data" };
const RANGES = { "15m": "15 min", "1h": "1 h", today: "Today", all: "All" };
const PREV = { "15m": "previous 15 min", "1h": "previous hour", today: "yesterday by now" };
const MASK_RE = /\[(?:EMAIL|SECRET|PESEL|NIP|SIG|INJ|IBAN:[^\]]*|CARD:[^\]]*)\]/g;
const PART = { args: ["Arguments the agent sent", "What the tool received"], result: ["Original result", "What the agent got"],
  prompt: ["Original prompt", "What the model got"], response: ["Original reply", "What the agent got"] };

const ui = { view: "overview", settings: null, ev: null, range: load("range") || "today", since: load("since") || "", tab: "overview",
  stepMode: "list", f: {}, q: "", trace: null, running: false };

function load(k) { try { return localStorage.getItem("tg." + k); } catch { return null; } }
function save(k, v) { try { localStorage.setItem("tg." + k, v); } catch { /* private window */ } }

// DOM builder: text is always set as text, never parsed as HTML (tool output is attacker-controlled).
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c.nodeType ? c : String(c));
  return el;
}
const NS = "http://www.w3.org/2000/svg";
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  for (const c of kids) el.append(c.nodeType ? c : document.createTextNode(String(c)));
  return el;
}
const CIRCLE = "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z";
const PATHS = {
  ban: [CIRCLE, "M5.7 5.7l12.6 12.6"], lock: ["M6 11h12v10H6z", "M8 11V7a4 4 0 0 1 8 0v4"], clock: [CIRCLE, "M12 7v5l3 2"],
  flag: ["M5 21V4h11l-1.5 4L16 12H5"], check: ["M5 12l5 5L20 7"], x: ["M6 6l12 12M18 6 6 18"], dash: ["M7 12h10"],
  user: ["M16 8a4 4 0 1 1-8 0 4 4 0 0 1 8 0z", "M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"], warn: ["M12 3 2 20h20z", "M12 10v4M12 17h.01"],
  back: ["M15 6l-6 6 6 6"], moon: ["M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9z"],
  sun: ["M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0z", "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"],
};
const icon = (name, cls) => s("svg", { class: "i" + (cls ? " " + cls : ""), viewBox: "0 0 24 24", "aria-hidden": "true" }, ...PATHS[name].map(d => s("path", { d })));
const KIND_ICON = { blocked: "ban", masked: "lock", waiting: "clock", flagged: "flag" };
const badge = (kind, text) => kind ? h("span", { class: "badge " + kind }, icon(KIND_ICON[kind]), text || KIND[kind]) : null;
const STATE_ICON = { clean: "check", untrusted: "warn", holds_private: "lock" };
const stateEl = st => (st || "clean").split("+").map(x => h("span", { class: "state", style: "margin-right:8px" }, icon(STATE_ICON[x] || "dash"), STATE[x] || x));

async function api(path, opts) {
  const r = await fetch(API + path, opts);
  if (!r.ok) throw new Error(`${r.status} ${path}`);
  return r.json();
}
const sameDay = d => d.toDateString() === new Date().toDateString();
const time = ts => {
  const d = new Date(ts);
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return sameDay(d) ? t : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + t;
};
const dur = sec => sec < 1 ? "<1 s" : sec < 60 ? `${Math.round(sec)} s` : sec < 3600 ? `${Math.floor(sec / 60)} min ${Math.round(sec % 60)} s` : `${(sec / 3600).toFixed(1)} h`;
const ms = v => v == null ? "" : v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`;
const n = v => Number(v || 0).toLocaleString();
const view = () => document.getElementById("view");
const stepHref = (sid, step) => `#/sessions/${encodeURIComponent(sid)}` + (step ? "/" + encodeURIComponent(step) : "");
const card = (title, right, ...body) => h("section", { class: "card" }, title ? h("div", { class: "card-h" }, h("h2", {}, title), right || null) : null, ...body);
const emptyState = msg => h("div", { class: "empty" }, msg || "Nothing in this time range. ", "Connect your agent in ", h("a", { href: "#/setup" }, "Setup"), " or run the ", h("a", { href: "#/scenario" }, "Scenario"), ".");

async function copy(text, btn) {
  try { await navigator.clipboard.writeText(text); } catch {
    const t = h("textarea", {}, text); document.body.append(t); t.select(); document.execCommand("copy"); t.remove();
  }
  const old = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = old), 1200);
}

/* ---------- shell: health, status, range, theme ---------- */
async function refreshStatus() {
  const box = document.getElementById("status");
  let st;
  try { st = await api("/status?since=" + encodeURIComponent(ui.since)); } catch {
    renderHealth({ level: "alert", message: "Gateway unreachable" });
    box.replaceChildren(h("span", {}, h("span", { class: "cdot off" }), "Not connected"));
    return;
  }
  renderHealth(st.health);
  const host = st.server.url.replace(/^https?:\/\//, "");
  box.title = [`Key ${st.account.key_id}`, `Server ${host}`, `App ${st.app_version}`,
    `Policy ${String(st.policy.version).slice(0, 7)} (${st.policy.profile})`, `Threat feed ${st.feed.version ?? "local"}`,
    `Injection check ${st.classifier}`].join("\n");
  box.replaceChildren(
    h("span", { class: "who" }, icon("user"), st.account.agent, h("span", { class: "muted" }, st.account.role)),
    h("span", { class: "sep" }),
    h("span", {}, h("span", { class: "cdot" }), host));
}

function renderHealth(hl) {
  const b = document.getElementById("health");
  b.className = "health " + (hl.level === "ok" ? "" : hl.level);
  b.querySelector(".msg").textContent = hl.message;
  b.title = hl.detail || (hl.level === "ok" ? "Nothing needs your attention" : "Open the event");
  b.onclick = hl.level === "ok" ? null : () => {
    if (hl.ts) { ui.since = hl.ts; save("since", hl.ts); }
    if (hl.session_id) { ui.tab = "overview"; location.hash = stepHref(hl.session_id, hl.trace_id); }
    refreshStatus();
  };
}

// Top-bar slot for the current view's controls: the time range (Overview, Events) or the scenario runner.
const bar = (...kids) => document.getElementById("bar").replaceChildren(...kids);
function renderRange() {
  if (!["overview", "events"].includes(ui.view)) return bar();
  bar(h("div", { class: "seg", role: "group", "aria-label": "Time range" }, Object.entries(RANGES).map(([k, l]) => h("button", { type: "button", "aria-pressed": String(ui.range === k),
    onclick: () => { ui.range = k; save("range", k); renderRange(); route(false); } }, l))));
}

function themeNow() {
  const t = document.documentElement.dataset.theme;
  return t || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}
function renderThemeBtn() { document.getElementById("theme").replaceChildren(icon(themeNow() === "dark" ? "sun" : "moon")); }
function applyTheme(t) {
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  save("theme", t === "system" ? "" : t); renderThemeBtn();
}
document.getElementById("theme").addEventListener("click", () => {
  const t = themeNow() === "dark" ? "light" : "dark";
  applyTheme(t);
  fetch(API + "/settings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ theme: t }) })
    .then(r => r.json()).then(j => { if (j.settings) ui.settings = j.settings; if (ui.view === "setup") route(false); }).catch(() => {});
});

/* ---------- Overview ---------- */
function delta(k) {
  if (k.prev == null) return "all time";
  const d = k.value - k.prev;
  return `${d > 0 ? "+" : d < 0 ? "−" : "±"}${n(Math.abs(d))} vs ${PREV[ui.range]}`;
}

function trend(series, bucket) {
  const W = 1000, H = 200, L = 36, R = 32, B = 24, T = 8;
  const tot = r => r.allow + r.redact + r.approve + r.block;
  const max = Math.max(1, ...series.map(tot));
  const step = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000].find(v => max / v <= 4) || Math.ceil(max / 4);
  const top = step * Math.ceil(max / step);
  const y = v => T + (H - T - B) * (1 - v / top);
  const slot = (W - L - R) / Math.max(series.length, 1), bw = Math.max(2, Math.min(24, slot * 0.7));
  const g = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Actions over time" });
  for (let v = 0; v <= top; v += step) g.append(s("line", { class: "grid", x1: L, x2: W - R, y1: y(v), y2: y(v) }), s("text", { x: L - 8, y: y(v) + 4, "text-anchor": "end" }, v));
  const fmt = t => {
    const d = new Date(t);
    return bucket >= 86400 ? d.toLocaleDateString([], { month: "short", day: "numeric" })
      : d.toLocaleTimeString([], bucket < 60 ? { hour: "2-digit", minute: "2-digit", second: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
  };
  const every = Math.ceil(series.length / 6);
  series.forEach((r, i) => {
    const x = L + slot * i + (slot - bw) / 2;
    let acc = 0;
    for (const [cls, v, label] of [["f-allow", r.allow, "allowed"], ["f-mid", r.redact + r.approve, "masked or waiting"], ["f-block", r.block, "blocked"]]) {
      if (!v) continue;
      const rect = s("rect", { class: cls, x, width: bw, y: y(acc + v), height: Math.max(1, y(acc) - y(acc + v)) });
      rect.append(s("title", {}, `${fmt(r.t)}: ${v} ${label}`));
      g.append(rect); acc += v;
    }
    if (i % every === 0) g.append(s("text", { x: x + bw / 2, y: H - 6, "text-anchor": "middle" }, fmt(r.t)));
  });
  return g;
}

const bucketWords = b => b >= 3600 ? `${b / 3600} h` : b >= 60 ? `${b / 60} min` : `${b} s`;

function hbars(rows, label, count) {
  if (!rows.length) return h("div", { class: "empty" }, "Nothing in this time range.");
  const max = Math.max(...rows.map(count));
  return h("div", { class: "hbars card-b" }, rows.map(r => h("div", { class: "hbar", title: label(r) },
    h("span", { class: "lab" }, label(r)), h("span", { class: "num" }, n(count(r))),
    h("div", { class: "track" }, h("div", { class: "fill", style: `width:${100 * count(r) / max}%` })))));
}

function eventsTable(items, withCheck) {
  return h("table", { class: "t" },
    h("colgroup", {}, h("col", { style: "width:120px" }), h("col", {}), h("col", { style: "width:160px" }), h("col", { style: "width:200px" }), withCheck ? h("col", { style: "width:220px" }) : null),
    h("thead", {}, h("tr", {}, h("th", {}, "Time"), h("th", {}, "What happened"), h("th", {}, "Agent"), h("th", {}, "Tool"), withCheck ? h("th", {}, "Session") : null)),
    h("tbody", {}, items.map(x => h("tr", { class: "link", onclick: ev => { if (ev.target.tagName !== "A") location.hash = stepHref(x.session_id, x.trace_id); } },
      h("td", { class: "num muted" }, time(x.ts)),
      h("td", { title: x.action }, badge(x.kind), " ", x.action),
      h("td", { title: x.agent }, x.agent),
      h("td", { title: x.tool }, x.tool),
      withCheck ? h("td", {}, h("a", { href: stepHref(x.session_id, x.trace_id), title: x.session_id }, x.session_label || x.session_id)) : null))));
}

async function renderOverview() {
  const o = await api("/overview?range=" + ui.range);
  const k = o.kpis;
  const tiles = [["checked", "Actions checked"], ["blocked", "Blocked"], ["masked", "Masked"], ["sessions", "Sessions"]];
  const hasData = k.checked.value > 0;
  view().replaceChildren(
    h("div", { class: "stack" },
      h("div", { class: "kpis" }, tiles.map(([key, l]) => h("div", { class: "card kpi" },
        h("div", { class: "l" }, l), h("div", { class: "v" }, n(k[key].value)), h("div", { class: "d" }, delta(k[key]))))),
      card("Actions over time", h("div", { class: "legend" }, h("span", {}, h("i", { class: "f-allow" }), "Allowed"),
        h("span", {}, h("i", { class: "f-mid" }), "Masked or waiting"), h("span", {}, h("i", { class: "f-block" }), "Blocked")),
        hasData ? h("div", { class: "card-b" }, trend(o.series, o.bucket_s), h("div", { class: "chart-foot" }, `One bar per ${bucketWords(o.bucket_s)}.`)) : emptyState()),
      h("div", { class: "grid2" },
        card("Top reasons", null, hbars(o.top_reasons, r => r.label, r => r.count)),
        card("Top tools and sources", null, hbars(o.top_tools, r => r.name, r => r.count))),
      card("Needs a look", h("a", { href: "#/events", class: "small" }, "All events"),
        o.needs_look.length ? eventsTable(o.needs_look, true) : h("div", { class: "empty" }, "Nothing blocked or flagged in this time range."))));
}

/* ---------- Sessions: master-detail on one screen ---------- */
const OUTCOME_KIND = { block: "blocked", redact: "masked", approve: "waiting" };
const stateIcons = st => {
  const xs = (st || "clean").split("+"), words = xs.map(x => STATE[x] || x).join(" + ");
  return h("span", { class: "state", title: words, "aria-label": words }, xs.map(x => icon(STATE_ICON[x] || "dash")));
};
const lastOutcome = v => v === "allow" ? h("span", { class: "muted" }, "Allowed") : badge(OUTCOME_KIND[v]);

async function renderSessions(sidArg, stepArg) {
  const { sessions } = await api("/sessions");
  if (!sessions.length) return view().replaceChildren(h("div", { class: "card" }, emptyState("No sessions yet. ")));
  const sid = sidArg || (ui.trace && sessions.some(x => x.id === ui.trace.sid) ? ui.trace.sid : sessions[0].id);
  const pick = id => { ui.tab = ui.tab || "overview"; location.hash = stepHref(id); };
  const list = h("section", { class: "card pane", "data-keep": "slist" }, h("table", { class: "t" },
    h("colgroup", {}, h("col", {}), h("col", { style: "width:76px" }), h("col", { style: "width:52px" }), h("col", { style: "width:52px" }), h("col", { style: "width:96px" })),
    h("thead", {}, h("tr", {}, ["Agent", "Started", "Steps", "State", "Last"].map((t, i) => h("th", { class: i === 2 ? "r" : null }, t)))),
    h("tbody", {}, sessions.map(x => h("tr", { class: "link" + (x.id === sid ? " sel" : ""), tabindex: "0", "aria-selected": String(x.id === sid),
      onclick: () => pick(x.id), onkeydown: ev => { if (ev.key === "Enter") pick(x.id); } },
      h("td", { title: `${x.agent} ${x.label || ""} (${x.id})` }, h("div", { class: "two" }, h("span", { class: "ell" }, x.agent, x.active ? h("span", { class: "live", title: "Active" }) : null),
        h("span", { class: "ell muted small" }, x.label || x.id))),
      h("td", { class: "num" }, time(x.first_ts)),
      h("td", { class: "num r" }, n(x.n)),
      h("td", {}, stateIcons(x.state)),
      h("td", {}, lastOutcome(x.last_verdict)))))));
  const right = h("section", { class: "card pane split" });
  view().replaceChildren(h("div", { class: "md" }, list, right));
  let d;
  try { d = await api("/sessions/" + encodeURIComponent(sid)); } catch (err) {
    right.replaceChildren(h("div", { class: "empty" }, String(err.message).startsWith("404") ? "This session is not on this laptop any more." : "Could not load this session."));
    return;
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
  ui.trace = { sid, idx, d };
  if (stepArg !== String(idx + 1)) history.replaceState(null, "", stepHref(sid, idx + 1));
  const c = x.counts;
  const strip = h("div", { class: "strip" }, [
    ["Agent", x.agent], ["Role", x.role], ["Started", time(x.first_ts)], ["Duration", dur(x.duration_s)], ["Steps", n(x.n)],
    ["Blocked", n(c.block)], ["Masked", n(c.redact)], ["State", stateEl(x.state)],
  ].map(([k, v]) => h("div", {}, h("div", { class: "k" }, k), h("div", { class: "v" }, v))));
  const steps = h("div", { class: "steps" }), detail = h("div", { class: "detail", "data-keep": "sdetail" });
  box.replaceChildren(h("div", { class: "pane-h" }, h("h2", {}, x.label || x.agent), h("span", { class: "muted small mono ell", title: sid }, sid), h("span", { class: "muted small", style: "margin-left:auto" }, x.active ? "Active" : "Ended")), strip, steps, detail);
  const draw = () => { drawSteps(steps, tl, draw); drawDetail(detail, tl[ui.trace.idx]); };
  draw();
}

function drawSteps(box, tl, redraw) {
  const t0 = new Date(tl[0].ts).getTime(), span = Math.max(1, new Date(tl[tl.length - 1].ts).getTime() - t0);
  const pick = i => { ui.trace.idx = i; history.replaceState(null, "", stepHref(ui.trace.sid, i + 1)); redraw(); };
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

function highlight(text, spans, masked) {
  const pre = h("pre", { class: "text" });
  if (masked) {
    let last = 0;
    for (const m of text.matchAll(MASK_RE)) { pre.append(text.slice(last, m.index), h("mark", {}, m[0])); last = m.index + m[0].length; }
    pre.append(text.slice(last));
    return pre;
  }
  let last = 0;
  for (const [a, b] of (spans || []).filter(Boolean).sort((p, q) => p[0] - q[0])) {
    if (a < last) continue;
    pre.append(text.slice(last, a), h("mark", {}, text.slice(a, b))); last = b;
  }
  pre.append(text.slice(last));
  return pre;
}

const TABS = [["overview", "Overview"], ["io", "Input/Output"], ["checks", "Checks"], ["sent", "Sent to server"]];

function drawDetail(box, e) {
  const x = e.explain;
  const pane = h("div", { class: "tabpane", role: "tabpanel" });
  const tabs = h("div", { class: "tabs", role: "tablist" }, TABS.map(([k, l]) => h("button", { type: "button", role: "tab", "aria-selected": String(ui.tab === k),
    onclick: () => { ui.tab = k; drawDetail(box, e); } }, l)));
  pane.append(...({ overview: tabOverview, io: tabIO, checks: tabChecks, sent: tabSent }[ui.tab] || tabOverview)(e, x));
  box.replaceChildren(h("div", { class: "detail-h" }, h("h2", {}, x.sentence),
    h("div", { class: "meta" }, h("span", { class: "num" }, time(e.ts)), badge(e.kind), e.action ? h("span", {}, e.action) : null, e.ms ? h("span", {}, ms(e.ms)) : null)), tabs, pane);
}

function tabOverview(e, x) {
  const kv = rows => h("dl", { class: "kv" }, rows.filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  return [kv([["What happened", x.sentence], e.action ? ["Check", e.action] : null, ["Effect on the session", x.effect], ["Why", x.why], ["What you can do", x.todo]]),
    h("details", { class: "tech" }, h("summary", {}, "Technical details"), kv([
      ["Rules", (e.reasons || []).length ? (e.reasons || []).map(r => h("div", {}, `${r.rule} (tier ${r.tier})${r.detail ? ": " + r.detail : ""}`)) : "–"],
      ["Tool", `${e.door} door · ${e.tool}`], ["Trace ID", e.trace_id || "–"],
      ["Session state", `${e.state_before || "?"} → ${e.state_after || "?"}`],
      ["Timing", Object.entries(e.latency_ms || {}).map(([k, v]) => `${k} ${v} ms`).join(" · ") || "–"],
      e.t2_score != null ? ["Injection score", e.t2_score.toFixed(3)] : null, ["Policy", e.policy_version || "–"]]))];
}

function tabIO(e) {
  const parts = Object.entries(e.text || {});
  if (!parts.length) return [h("div", { class: "empty" }, ui.settings && !ui.settings.keep_text
    ? ["Keep full text is off in ", h("a", { href: "#/setup" }, "Setup"), ", so the text of new actions is not stored on this laptop."]
    : "The full text of this action is not stored on this laptop.")];
  return parts.map(([name, t]) => {
    const [origL, sentL] = PART[name] || [name, name];
    const stopped = e.verdict === "block" && name === "args";
    const nMasked = (t.sent.match(MASK_RE) || []).length;
    return h("div", { class: "io" },
      h("div", {}, h("h3", {}, origL), highlight(t.original, t.spans, false)),
      h("div", {}, h("h3", {}, sentL, stopped ? h("span", { class: "badge" }, "not sent") : nMasked ? badge("masked", `${nMasked} masked`) : h("span", { class: "badge plain" }, "unchanged")),
        stopped ? h("div", { class: "empty" }, "The call was stopped, so nothing was sent.") : highlight(t.sent, null, true)));
  });
}

function tabChecks(e) {
  const st = (e.stages || []).filter(x => !(x.name === "approval" && x.outcome === "skip"));
  if (!st.length) return [h("div", { class: "empty" }, "No check details for this action.")];
  const ic = { ok: () => icon("check"), warn: () => icon("flag"), fail: () => icon("x", "fail"), skip: () => icon("dash") };
  return [h("ul", { class: "checks" }, st.map(x => h("li", { class: x.outcome === "skip" ? "skip" : "" },
    (ic[x.outcome] || ic.skip)(), h("span", {}, STAGE[x.name] || x.name), h("span", { class: "oc " + x.outcome }, OUTCOME[x.outcome] || x.outcome),
    h("span", { class: "dt", title: x.detail || "" }, x.detail || ""), h("span", { class: "ms" }, ms(x.ms)))))];
}

function tabSent(e, x) {
  return [h("div", { class: "local" }, icon("lock"), "The text never left this laptop. Only the decision and a fingerprint were sent."),
    h("dl", { class: "kv" }, [["Decision", VERDICT[e.verdict] || e.verdict], ["Reason", x.why], ["Check", e.action || "Every check passed"],
      ["Tool", x.tool_name], ["Session state", (e.state_after || "clean").split("+").map(k => STATE[k] || k).join(" + ")], ["Time", time(e.ts)],
      ["Fingerprint (SHA-256)", h("code", {}, e.content_sha256 || "–")], ["Not sent", "Prompts, arguments, results, and the originals of masked values."]]
      .map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]))];
}

/* ---------- Events: master-detail on one screen ---------- */
const evHref = tid => "#/events" + (tid ? "/" + encodeURIComponent(tid) : "");

async function renderEvents(tidArg) {
  const q = new URLSearchParams({ range: ui.range, ...Object.fromEntries(Object.entries(ui.f).filter(([, v]) => v)) });
  const d = await api("/events?" + q);
  const words = { action: v => KIND[v] || v, agent: v => d.facets.names[v] || v, check: v => v };
  const group = (key, label) => h("div", { class: "pills", role: "group", "aria-label": label }, h("span", { class: "lab" }, label),
    [null, ...new Set([...(d.facets[key] || []), ...(ui.f[key] ? [ui.f[key]] : [])])].map(v => h("button", { type: "button", class: "fpill", "aria-pressed": String((ui.f[key] || null) === v),
      onclick: () => { ui.f[key] = v; route(false); } }, v == null ? "All" : words[key](v))));
  const needle = ui.q.toLowerCase();
  const items = needle ? d.items.filter(x => [x.action, x.agent, x.tool, x.session_label, x.session_id].join(" ").toLowerCase().includes(needle)) : d.items;
  const search = h("input", { class: "search", type: "search", placeholder: "Search events", "aria-label": "Search events", value: ui.q,
    oninput: ev => { ui.q = ev.target.value; clearTimeout(renderEvents.t); renderEvents.t = setTimeout(() => route(false).then(() => {
      const el = document.querySelector(".search"); if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); } }), 200); } });
  const tid = items.some(x => x.trace_id === (tidArg || ui.ev)) ? (tidArg || ui.ev) : items[0]?.trace_id;
  ui.ev = tid;
  if (tid && tidArg !== tid) history.replaceState(null, "", evHref(tid));
  const pick = t => { location.hash = evHref(t); };
  const list = h("section", { class: "card pane", "data-keep": "elist" },
    h("div", { class: "filters" }, search, group("action", "Action"), group("agent", "Agent"), group("check", "Check")),
    items.length ? h("table", { class: "t" },
      h("colgroup", {}, h("col", { style: "width:100px" }), h("col", {}), h("col", { style: "width:80px" })),
      h("thead", {}, h("tr", {}, h("th", {}, "Action"), h("th", {}, "What happened"), h("th", { class: "r" }, "Time"))),
      h("tbody", {}, items.map(x => h("tr", { class: "link" + (x.trace_id === tid ? " sel" : ""), tabindex: "0", "aria-selected": String(x.trace_id === tid),
        onclick: () => pick(x.trace_id), onkeydown: ev => { if (ev.key === "Enter") pick(x.trace_id); } },
        h("td", {}, badge(x.kind)),
        h("td", { title: `${x.action} · ${x.tool} · ${x.agent}` }, h("div", { class: "two" }, h("span", { class: "ell" }, x.action), h("span", { class: "ell muted small" }, x.tool, " · ", x.agent))),
        h("td", { class: "num muted r" }, time(x.ts))))))
      : h("div", { class: "empty" }, "No events match."));
  const right = h("section", { class: "card pane", "data-keep": "edetail" });
  view().replaceChildren(h("div", { class: "md" }, list, right));
  const item = items.find(x => x.trace_id === tid);
  if (!item) return right.replaceChildren(h("div", { class: "empty" }, items.length ? "Select an event to see what happened." : "Nothing to show. Try a longer time range."));
  let e;
  try { e = (await api("/sessions/" + encodeURIComponent(item.session_id))).timeline.find(x => x.trace_id === tid); } catch { e = null; }
  if (!e) return right.replaceChildren(h("div", { class: "empty" }, "The details of this event are not on this laptop any more."));
  const x = e.explain;
  const kv = rows => h("dl", { class: "kv" }, rows.filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  right.replaceChildren(
    h("div", { class: "detail-h" }, h("h2", {}, x.sentence),
      h("div", { class: "meta" }, h("span", { class: "num" }, time(e.ts)), badge(e.kind), h("span", {}, item.agent),
        h("a", { href: stepHref(item.session_id, tid), style: "margin-left:auto", onclick: () => { ui.tab = "overview"; } }, "Open in session"))),
    h("div", { class: "tabpane" },
      kv([["What happened", x.sentence], ["Check", item.check], ["Action", (e.action || "").split(": ").slice(1).join(": ") || e.action], ["Effect on the session", x.effect], ["Why", x.why], ["What you can do", x.todo],
        ["Session", h("a", { href: stepHref(item.session_id, tid) }, item.session_label || item.session_id)]]),
      Object.keys(e.text || {}).length ? h("div", { class: "sect" }, h("h3", {}, "Input and output on this laptop"), tabIO(e)) : null));
}

/* ---------- Setup: the full local agent setup ---------- */
const managed = () => h("span", { class: "managed" }, icon("lock"), "Managed by your security team");
const list = xs => xs.length ? xs.join(", ") : "–";

async function renderSetup() {
  const [c, a, st, se] = await Promise.all([api("/setup"), api("/agent"), api("/status").catch(() => null), api("/settings")]);
  ui.settings = se.settings;
  const result = h("div", {});
  const testBtn = h("button", { class: "btn primary", onclick: async () => {
    testBtn.disabled = true; result.replaceChildren(h("p", { class: "muted small" }, "Asking the gateway for your tools…"));
    try {
      const t = await api("/setup/test");
      result.replaceChildren(t.ok
        ? h("div", { class: "small", style: "margin-top:8px" }, `Connected. Your agent sees ${t.tools.length} tools.`)
        : h("div", { style: "margin-top:8px" }, badge("blocked", "Failed"), " ", t.error));
    } catch (err) { result.replaceChildren(h("div", { style: "margin-top:8px" }, badge("blocked", "Failed"), " ", String(err.message))); }
    testBtn.disabled = false;
  } }, "Test connection");
  const field = (l, v, btn) => h("div", { class: "field" }, h("span", {}, l), typeof v === "string" ? h("code", { title: v }, v) : h("span", {}, v), btn || h("span", {}));
  const copyBtn = text => h("button", { class: "btn sm", onclick: ev => copy(text, ev.currentTarget) }, "Copy");
  const health = st ? [h("span", { class: "cdot" + (st.health.level === "alert" ? " off" : "") }), " ", st.health.message] : [h("span", { class: "cdot off" }), " Unreachable"];
  const snippets = h("details", { class: "snips" }, h("summary", {}, "Client config snippets: Claude Code, Cursor, OpenAI SDK"),
    Object.entries(c.snippets).map(([name, sn]) => h("div", { class: "snip" },
      h("div", { class: "row" }, h("h3", { style: "margin:0;color:var(--ink)" }, name), h("button", { class: "btn sm", onclick: ev => copy(sn.replaceAll("{KEY}", c.key), ev.currentTarget) }, "Copy")),
      h("pre", {}, sn.replaceAll("{KEY}", c.key_masked)))));

  const toolRow = t => h("tr", {}, h("td", { title: t.name }, t.plain, h("span", { class: "sub-l mono" }, t.name)),
    h("td", {}, t.write ? "Write" : "Read"), h("td", { class: "muted", title: (t.limits || []).join("; ") }, (t.limits || []).join("; ") || "No extra limits"));
  const servers = a.servers.map(s => h("div", { class: "srv" },
    h("div", { class: "srv-h" }, h("h3", {}, s.name), h("span", { class: "muted small" },
      s.reachable ? `${s.allowed.length} allowed · ${s.denied.length} hidden from this role` + (s.access === "read" ? " · read-only tools only" : "") : "Not reachable by this role")),
    s.allowed.length ? h("table", { class: "t" }, h("colgroup", {}, h("col", {}), h("col", { style: "width:72px" }), h("col", { style: "width:40%" })),
      h("thead", {}, h("tr", {}, h("th", {}, "Allowed tool"), h("th", {}, "Kind"), h("th", {}, "Limits"))), h("tbody", {}, s.allowed.map(toolRow))) : null,
    s.denied.length ? h("div", { class: "denied" }, h("span", { class: "muted small" }, s.reachable ? "Hidden from this role:" : "Tools on this server:"),
      s.denied.map(t => h("span", { class: "badge", title: t.name }, icon("x"), t.plain))) : null));

  const b = a.budget || {};
  const kv = rows => h("dl", { class: "kv" }, rows.filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  const inj = a.content.injection;

  const ceil = se.ceiling;
  const saveMsg = h("span", { class: "small muted", role: "status" });
  const post = async patch => {
    try {
      const r = await fetch(API + "/settings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(patch) });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error);
      ui.settings = j.settings; saveMsg.textContent = "Saved."; saveMsg.className = "small muted";
      if ("theme" in patch) applyTheme(j.settings.theme);
    } catch (err) { saveMsg.textContent = String(err.message); saveMsg.className = "small err"; }
  };
  const keep = h("input", { type: "checkbox", id: "keep", checked: se.settings.keep_text, disabled: !ceil.keep_text && !se.settings.keep_text,
    onchange: ev => post({ keep_text: ev.target.checked }) });
  const ret = h("input", { type: "number", id: "ret", class: "num-in", min: 1, max: ceil.retention, value: se.settings.retention,
    onchange: ev => post({ retention: Number(ev.target.value) }) });
  const theme = h("select", { id: "thm", class: "sel-in", onchange: ev => post({ theme: ev.target.value }) },
    ["system", "light", "dark"].map(t => h("option", { value: t, selected: se.settings.theme === t }, { system: "Match the system", light: "Light", dark: "Dark" }[t])));

  view().replaceChildren(
    h("div", { class: "stack" },
      h("div", { class: "grid2" },
        card("Connection", h("span", { class: "muted small", title: `How ${a.agent} is connected and what it may do` },
          `${a.agent} · ${a.role} · policy ${String(a.policy.version).slice(0, 7)} · ${a.policy.profile}`), h("div", { class: "card-b" },
          field("Server", c.server), field("Health", health), field("MCP URL", c.mcp_url, copyBtn(c.mcp_url)), field("Model URL", c.model_url, copyBtn(c.model_url)),
          field("Key", c.key_masked, h("button", { class: "btn sm", onclick: ev => copy(c.key, ev.currentTarget) }, "Copy key")),
          field("Expiry", h("span", {}, "No expiry. Your security team can revoke it.")),
          h("div", { style: "margin-top:8px" }, testBtn), result), snippets),
        card("Local settings", h("span", { class: "muted small" }, "Can only be stricter than the company policy"), h("div", { class: "card-b" },
          h("div", { class: "field set" }, h("label", { for: "keep" }, "Keep full text"), h("span", { class: "small muted" }, ceil.keep_text ? "Store prompts, arguments and results on this laptop for the Input/Output tabs." : "Turned off by the company policy."), keep),
          h("div", { class: "field set" }, h("label", { for: "ret" }, "Retention"), h("span", { class: "small muted" }, `Keep the text of the last N calls, at most ${n(ceil.retention)}.`), ret),
          h("div", { class: "field set" }, h("label", { for: "thm" }, "Theme"), h("span", { class: "small muted" }, "This screen only."), theme),
          h("div", { style: "margin-top:8px;min-height:20px" }, saveMsg),
          h("h3", { style: "margin-top:8px" }, "What stays here, what is sent"),
          kv([["Stays on this laptop", "Full text of prompts, arguments and results; originals of masked items; your key."],
            ["Sent to the server", "Decision and reason, tool name, time, session state, and a SHA-256 fingerprint of the text."]])))),
      card("MCP servers and tools", managed(), h("div", { class: "card-b" }, servers)),
      h("div", { class: "grid2" },
        card("Models and budget", managed(), h("div", { class: "card-b" }, kv([
          ["Models allowed", list(a.models)],
          ["Tokens today", b.limit == null ? `${n(b.used)} used · no limit` : `${n(b.used)} of ${n(b.limit)} used · ${n(Math.max(0, b.limit - b.used))} left`],
        ]), b.limit ? h("div", { class: "meter", title: `${Math.round(100 * b.used / b.limit)}% used` }, h("i", { style: `width:${Math.min(100, 100 * b.used / b.limit)}%` })) : null)),
        card("Content checks in force", managed(), h("div", { class: "card-b" }, kv([
          ["Masked", list(a.content.masked)], ["Blocked", list(a.content.blocked)], a.content.asks.length ? ["Asks a human", list(a.content.asks)] : null,
          ["Injection check", `${inj.profile} profile. ${inj.words}`],
          ["Signatures", `${n(a.content.signatures.count)} known attacks · ${a.content.signatures.source}${a.content.signatures.version != null ? " v" + a.content.signatures.version : ""}`],
        ])))),
      card("Data-flow labels", managed(), h("div", { class: "card-b" }, h("p", { class: "flow" }, h("strong", {}, "Rule: "), a.flow_rule.sentence,
        " Action: ", a.flow_rule.action === "approve" ? "ask a human" : "block", ".")),
        h("table", { class: "t" }, h("colgroup", {}, h("col", {}), h("col", { style: "width:160px" }), h("col", { style: "width:44%" })),
          h("thead", {}, h("tr", {}, h("th", {}, "Tool"), h("th", {}, "Label"), h("th", {}, "Why"))),
          h("tbody", {}, a.labels.map(l => h("tr", {}, h("td", { title: l.tool }, l.plain, h("span", { class: "sub-l mono" }, l.tool)),
            h("td", {}, l.words.join(", ")), h("td", { class: "muted", title: l.why }, l.why))))))));
}

/* ---------- Scenario ---------- */
async function renderScenario(note) {
  const { acts } = await api("/scenario");
  const all = acts.flatMap(a => a.steps).filter(st => !st.operator);
  const done = all.filter(st => st.result), passed = done.filter(st => st.result.pass);
  const runSteps = async ids => {
    if (ui.running) return;
    ui.running = true;
    try { for (const id of ids) { await renderScenario(`Running step ${id}…`); await api("/scenario/run/" + encodeURIComponent(id), { method: "POST" }); } }
    finally { ui.running = false; }
    if (ui.view === "scenario") renderScenario();
  };
  const btn = (label, fn, cls) => h("button", { class: "btn " + (cls || ""), disabled: ui.running, onclick: fn }, label);
  const result = r => r.pass ? h("span", { class: "badge" }, icon("check"), "PASS") : h("span", { class: "badge fail" }, icon("x"), "FAIL");
  if (ui.view !== "scenario") return;
  bar(h("span", { class: "muted small" }, note || (done.length ? `${passed.length} of ${done.length} passed` : `${all.length} steps`)),
    btn("Reset", async () => { await api("/scenario/reset", { method: "POST" }); renderScenario(); }),
    btn("Run all", () => runSteps(all.map(x => x.id)), "primary"));
  view().replaceChildren(
    h("div", { class: "stack" }, acts.map(a => card(`Act ${a.id}: ${a.title}`,
      a.operator ? h("span", { class: "muted small" }, "Done in the Server console") : btn("Run act", () => runSteps(a.steps.filter(x => !x.operator).map(x => x.id)), "sm"),
      a.subtitle ? h("p", { class: "muted small", style: "margin:-8px 16px 8px" }, a.subtitle) : null,
      h("table", { class: "t sc" },
        h("colgroup", {}, h("col", { style: "width:56px" }), h("col", { style: "width:136px" }), h("col", {}), h("col", { style: "width:24%" }), h("col", { style: "width:24%" }), h("col", { style: "width:72px" }), h("col", { style: "width:64px" })),
        h("thead", {}, h("tr", {}, ["#", "Agent", "Action", "Expected", "Got", "Result", ""].map(t => h("th", {}, t)))),
        h("tbody", {}, a.steps.map(st => st.operator
          ? h("tr", {}, h("td", { class: "id" }, st.id), h("td", {}, st.agent), h("td", {}, st.text), h("td", { colspan: 4, class: "muted" }, "Operator step: done in the Server console"))
          : h("tr", {},
            h("td", { class: "id" }, st.id), h("td", {}, st.agent),
            h("td", {}, st.text, st.needs ? h("div", { class: "why-f" }, st.needs === "classifier" ? "Needs the injection classifier" : "Needs a model (Ollama or --scripted-model)") : null),
            h("td", { class: "muted" }, st.expected),
            h("td", {}, st.result ? [st.result.got, st.result.why ? h("div", { class: "why-f" }, st.result.why) : null,
              st.result.session_id && st.result.trace_id ? h("div", {}, h("a", { class: "small", href: stepHref(st.result.session_id, st.result.trace_id) }, "Open step")) : null] : h("span", { class: "muted" }, "–")),
            h("td", {}, st.result ? result(st.result) : null),
            h("td", {}, btn("Run", () => runSteps([st.id]), "sm"))))))))));
}

/* ---------- routing + live updates ---------- */
const VIEWS = { overview: renderOverview, sessions: renderSessions, events: renderEvents, setup: renderSetup, scenario: renderScenario };
async function route(focus) {
  const parts = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  ui.view = VIEWS[parts[0]] ? parts[0] : "overview";
  document.querySelectorAll(".nav a").forEach(a => a.dataset.view === ui.view ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"));
  renderRange();
  const keep = Object.fromEntries([...document.querySelectorAll("[data-keep]")].map(el => [el.dataset.keep, el.scrollTop]));
  try {
    if (ui.view === "sessions") await renderSessions(parts[1], parts[2]);
    else if (ui.view === "events") await renderEvents(parts[1]);
    else await VIEWS[ui.view]();
  } catch (err) {
    view().replaceChildren(h("div", { class: "notice" }, h("span", { class: "cdot" }),
      String(err.message).startsWith("404") ? "This session is not on this laptop any more." : "Could not reach the gateway. The page retries when it is back.",
      h("button", { class: "btn sm", style: "margin-left:auto", onclick: () => route(false) }, "Retry")));
  }
  document.querySelectorAll("[data-keep]").forEach(el => { if (keep[el.dataset.keep]) el.scrollTop = keep[el.dataset.keep]; });
  if (focus) view().focus({ preventScroll: true });
}
window.addEventListener("hashchange", () => route(true));

let pending = null;
function onEvent() {  // debounce bursts (Run all) into one refresh
  clearTimeout(pending);
  pending = setTimeout(() => {
    refreshStatus();
    if (["overview", "events", "sessions"].includes(ui.view) && !document.activeElement?.matches?.(".search")) route(false);
  }, 400);
}
function live() {
  const es = new EventSource(API + "/stream");
  es.onmessage = onEvent;
  es.onerror = () => refreshStatus();
  es.onopen = () => { refreshStatus(); if (document.querySelector(".notice")) route(false); };
}

renderThemeBtn();
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", renderThemeBtn);
refreshStatus();
api("/settings").then(j => { ui.settings = j.settings; applyTheme(j.settings.theme); }).catch(() => {});
route(false);
live();
setInterval(refreshStatus, 15000);
