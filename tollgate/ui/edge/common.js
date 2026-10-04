// Shared by the local edge (/edge) and the server console (/console): DOM builder, icons, badges, formatting,
// theme, charts and the check-chain / step-overview renderers. Loaded before each page's app.js.
"use strict";

const VERDICT = { allow: "Allowed", redact: "Masked", approve: "Waiting", block: "Blocked" };
const KIND = { blocked: "Blocked", masked: "Masked", waiting: "Waiting", flagged: "Flagged" };
const STAGE = { key: "Key", role: "Role", arguments: "Arguments", data_flow: "Data flow", content: "Content", budget: "Budget", approval: "Approval" };
const OUTCOME = { ok: "ok", warn: "flagged", fail: "failed", skip: "skipped" };
const STATE = { clean: "Clean", untrusted: "Untrusted", holds_private: "Holds private data" };
const RANGES = { "15m": "15 min", "1h": "1 h", today: "Today", all: "All" };
const PREV = { "15m": "previous 15 min", "1h": "previous hour", today: "yesterday by now" };

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
  back: ["M15 6l-6 6 6 6"], chev: ["M6 9l6 6 6-6"], moon: ["M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9z"],
  sun: ["M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0z", "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"],
};
const icon = (name, cls) => s("svg", { class: "i" + (cls ? " " + cls : ""), viewBox: "0 0 24 24", "aria-hidden": "true" }, ...PATHS[name].map(d => s("path", { d })));
const KIND_ICON = { blocked: "ban", masked: "lock", waiting: "clock", flagged: "flag" };
const badge = (kind, text) => kind ? h("span", { class: "badge " + kind }, icon(KIND_ICON[kind]), text || KIND[kind]) : null;
const STATE_ICON = { clean: "check", untrusted: "warn", holds_private: "lock" };
const stateEl = st => (st || "clean").split("+").map(x => h("span", { class: "state", style: "margin-right:8px" }, icon(STATE_ICON[x] || "dash"), STATE[x] || x));

const sameDay = d => d.toDateString() === new Date().toDateString();
const time = ts => {
  const d = new Date(ts);
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return sameDay(d) ? t : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + t;
};
const dur = sec => sec < 1 ? "<1 s" : sec < 60 ? `${Math.round(sec)} s` : sec < 3600 ? `${Math.floor(sec / 60)} min ${Math.round(sec % 60)} s` : `${(sec / 3600).toFixed(1)} h`;
const ms = v => v == null ? "" : v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`;
const n = v => Number(v || 0).toLocaleString();

const card = (title, right, ...body) => h("section", { class: "card" }, title ? h("div", { class: "card-h" }, h("h2", {}, title), right || null) : null, ...body);

async function copy(text, btn) {
  try { await navigator.clipboard.writeText(text); } catch {
    const t = h("textarea", {}, text); document.body.append(t); t.select(); document.execCommand("copy"); t.remove();
  }
  const old = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = old), 1200);
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

function delta(k, range) {
  if (k.prev == null) return "all time";
  const d = k.value - k.prev;
  return `${d > 0 ? "+" : d < 0 ? "−" : "±"}${n(Math.abs(d))} vs ${PREV[range]}`;
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

const OUTCOME_KIND = { block: "blocked", redact: "masked", approve: "waiting" };
const stateIcons = st => {
  const xs = (st || "clean").split("+"), words = xs.map(x => STATE[x] || x).join(" + ");
  return h("span", { class: "state", title: words, "aria-label": words }, xs.map(x => icon(STATE_ICON[x] || "dash")));
};
const lastOutcome = v => v === "allow" ? h("span", { class: "muted" }, "Allowed") : badge(OUTCOME_KIND[v]);

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

function tabChecks(e) {
  const st = (e.stages || []).filter(x => !(x.name === "approval" && x.outcome === "skip"));
  if (!st.length) return [h("div", { class: "empty" }, "No check details for this action.")];
  const ic = { ok: () => icon("check"), warn: () => icon("flag"), fail: () => icon("x", "fail"), skip: () => icon("dash") };
  return [h("ul", { class: "checks" }, st.map(x => h("li", { class: x.outcome === "skip" ? "skip" : "" },
    (ic[x.outcome] || ic.skip)(), h("span", {}, STAGE[x.name] || x.name), h("span", { class: "oc " + x.outcome }, OUTCOME[x.outcome] || x.outcome),
    h("span", { class: "dt", title: x.detail || "" }, x.detail || ""), h("span", { class: "ms" }, ms(x.ms)))))];
}

// MCP servers this role reaches: allowed tools (kind, limits) and the tools hidden from it.
const toolRow = t => h("tr", {}, h("td", { title: t.name }, t.plain, h("span", { class: "sub-l mono" }, t.name)),
  h("td", {}, t.write ? "Write" : "Read"), h("td", { class: "muted", title: (t.limits || []).join("; ") }, (t.limits || []).join("; ") || "No extra limits"));
const serverList = servers => servers.map(s => h("div", { class: "srv" },
  h("div", { class: "srv-h" }, h("h3", {}, s.name), h("span", { class: "muted small" },
    s.unreachable ? "Unreachable: the upstream MCP server did not answer at startup" : s.reachable ? `${s.allowed.length} allowed · ${s.denied.length} hidden from this role` + (s.access === "read" ? " · read-only tools only" : "") : "Not reachable by this role")),
  s.allowed.length ? h("table", { class: "t" }, h("colgroup", {}, h("col", {}), h("col", { style: "width:72px" }), h("col", { style: "width:40%" })),
    h("thead", {}, h("tr", {}, h("th", {}, "Allowed tool"), h("th", {}, "Kind"), h("th", {}, "Limits"))), h("tbody", {}, s.allowed.map(toolRow))) : null,
  s.denied.length ? h("div", { class: "denied" }, h("span", { class: "muted small" }, s.reachable ? "Hidden from this role:" : "Tools on this server:"),
    s.denied.map(t => h("span", { class: "badge", title: t.name }, icon("x"), t.plain))) : null));
