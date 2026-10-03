// Tollgate local edge UI. Vanilla JS, no build step, no network beyond this gateway.
"use strict";

const API = "/edge/api";
const VERDICT = { allow: "Allowed", redact: "Masked", approve: "Waiting", block: "Blocked" };
const STAGE = { key: "Key", role: "Role", arguments: "Arguments", data_flow: "Data flow", content: "Content", budget: "Budget", approval: "Approval" };
const ICON = { ok: "✓", warn: "!", fail: "✕", skip: "–" };
const MASK_RE = /\[(?:EMAIL|SECRET|PESEL|NIP|SIG|INJ|IBAN:[^\]]*|CARD:[^\]]*)\]/g;
const ORDER = ["allow", "redact", "approve", "block"];

const ui = { view: "sessions", session: null, openTrace: null, since: load("since") || "", status: null };

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
const svgNS = "http://www.w3.org/2000/svg";
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  for (const c of kids) el.append(c.nodeType ? c : document.createTextNode(String(c)));
  return el;
}

async function api(path, opts) {
  const r = await fetch(API + path, opts);
  if (!r.ok) throw new Error(`${r.status} ${path}`);
  return r.json();
}
const time = ts => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const ago = ts => {
  const m = Math.round((Date.now() - new Date(ts)) / 60000);
  return m < 1 ? "just now" : m < 60 ? `${m} min ago` : m < 1440 ? `${Math.round(m / 60)} h ago` : new Date(ts).toLocaleDateString();
};
const pill = (cls, text, title) => h("span", { class: "pill " + cls, title }, text);
const verdictPill = v => pill(v, VERDICT[v] || v);
const statePills = st => (st || "clean").split("+").map(x => pill(x, { clean: "Clean", untrusted: "Untrusted", holds_private: "Holds private data" }[x] || x));
const view = () => document.getElementById("view");
const empty = () => h("div", { class: "empty" }, "No actions yet. Connect your agent (", h("a", { href: "#setup" }, "Setup"), ") or run the ", h("a", { href: "#scenario" }, "scenario"), ".");

async function copy(text, btn) {
  try { await navigator.clipboard.writeText(text); } catch {
    const t = h("textarea", {}, text); document.body.append(t); t.select(); document.execCommand("copy"); t.remove();
  }
  const old = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = old), 1200);
}

/* ---------- shell: health + status ---------- */
async function refreshStatus() {
  let st;
  try { st = await api("/status?since=" + encodeURIComponent(ui.since)); } catch {
    renderHealth({ level: "alert", message: "Gateway unreachable" });
    document.getElementById("status").replaceChildren(h("div", { class: "conn" }, h("span", { class: "cdot off" }), "Not connected"));
    return;
  }
  ui.status = st;
  renderHealth(st.health);
  const person = s("svg", { viewBox: "0 0 24 24" }, s("circle", { cx: 12, cy: 8, r: 4 }), s("path", { d: "M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6" }));
  const host = st.server.url.replace(/^https?:\/\//, "");
  document.getElementById("status").replaceChildren(
    h("div", { class: "acct", title: `Key ${st.account.key_id}` }, person, st.account.agent, h("span", { class: "muted", style: "font-weight:400" }, st.account.role)),
    h("div", { class: "conn" }, h("span", { class: "cdot" }), `Connected · ${host}`),
    h("div", { class: "vers", title: `Injection check: ${st.classifier}` },
      `app ${st.app_version} · policy ${st.policy.version} (${st.policy.profile}) · feed ${st.feed.version ?? "local"}`));
}

function renderHealth(hl) {
  const b = document.getElementById("health");
  b.className = "health " + (hl.level === "ok" ? "" : hl.level);
  b.querySelector(".msg").textContent = hl.message;
  b.title = hl.detail || (hl.level === "ok" ? "Nothing needs your attention" : "Open the event");
  b.onclick = hl.level === "ok" ? null : () => {
    if (hl.ts) { ui.since = hl.ts; save("since", hl.ts); }
    if (hl.session_id) { ui.openTrace = hl.trace_id; location.hash = "#sessions/" + encodeURIComponent(hl.session_id); route(true); }
    refreshStatus();
  };
}

/* ---------- Sessions ---------- */
async function renderSessions() {
  const open = new Set([...document.querySelectorAll(".card[open]")].map(c => c.dataset.trace));
  const { sessions } = await api("/sessions");
  if (!sessions.length) return view().replaceChildren(h("h1", {}, "Sessions"), h("p", { class: "sub" }, "Every session of agents on this laptop."), empty());
  if (!ui.session || !sessions.some(x => x.id === ui.session)) ui.session = sessions[0].id;
  const list = h("div", { class: "slist", role: "list" }, sessions.map(x =>
    h("button", { class: "sitem", role: "listitem", "aria-current": x.id === ui.session ? "true" : "false", onclick: () => { location.hash = "#sessions/" + encodeURIComponent(x.id); } },
      h("div", { class: "name" }, x.agent, h("small", {}, ago(x.last_ts))),
      x.label ? h("div", { class: "label" }, x.label) : null,
      h("div", { class: "row" }, pill(x.active ? "ghost active" : "ghost", x.active ? "Active" : "Ended"), statePills(x.state), verdictPill(x.last_verdict)),
      h("div", { class: "tools", title: x.tools.join(", ") }, `${x.n} action${x.n === 1 ? "" : "s"} · ` + x.tools.join(", ")))));
  const detail = h("div", {}, h("div", { class: "muted" }, "Loading…"));
  view().replaceChildren(h("h1", {}, "Sessions"), h("p", { class: "sub" }, "Every session of agents on this laptop. A session is one key: what it read stays with it."),
    h("div", { class: "sessions" }, list, detail));
  const d = await api("/sessions/" + encodeURIComponent(ui.session));
  detail.replaceChildren(renderTimeline(d, open));
  if (ui.openTrace) {
    const c = document.querySelector(`[data-trace="${CSS.escape(ui.openTrace)}"]`);
    if (c) { c.open = true; c.classList.add("flash"); c.scrollIntoView({ block: "center" }); }
    ui.openTrace = null;
  }
}

function renderTimeline({ session: x, timeline }, open) {
  return h("div", {},
    h("div", { class: "shead" },
      h("div", {}, h("h2", { style: "margin:0" }, x.agent, " ", h("span", { class: "muted", style: "font-weight:400" }, x.label || "")),
        h("div", { class: "muted mono" }, `session ${x.id} · ${x.role} · started ${time(x.first_ts)}`)),
      h("div", { class: "row" }, statePills(x.state))),
    h("div", { class: "timeline" }, timeline.slice().reverse().map(e => card(e, open.has(e.trace_id)))));
}

function chain(e) {
  return h("div", { class: "chain", "aria-label": "Checks" }, (e.stages || [])
    .filter(st => !(st.outcome === "skip" && (st.name === "budget" && e.door === "tool" || st.name === "approval")))
    .map(st => h("span", { class: "st", title: st.detail || STAGE[st.name] },
      h("span", { class: "ic " + st.outcome, "aria-hidden": "true" }, ICON[st.outcome]),
      h("span", { class: st.outcome === "skip" ? "skip-l" : "" }, STAGE[st.name]),
      h("span", { class: "sr", style: "position:absolute;left:-9999px" }, ` ${st.outcome}`))));
}

function highlight(text, spans, masked) {
  const pre = h("pre", { class: "text" });
  if (masked) {
    let last = 0;
    for (const m of text.matchAll(MASK_RE)) { pre.append(text.slice(last, m.index), h("mark", { class: "m" }, m[0])); last = m.index + m[0].length; }
    pre.append(text.slice(last));
    return pre;
  }
  const sp = (spans || []).filter(Boolean).sort((a, b) => a[0] - b[0]);
  let last = 0;
  for (const [a, b] of sp) { if (a < last) continue; pre.append(text.slice(last, a), h("mark", {}, text.slice(a, b))); last = b; }
  pre.append(text.slice(last));
  return pre;
}

const PART = { args: ["Arguments the agent sent", "What the tool received"], result: ["Original result", "What the agent got"],
  prompt: ["Original prompt", "What the model got"], response: ["Original reply", "What the agent got"] };

function textBlock(name, t, verdict) {
  const stopped = verdict === "block" && name === "args";
  const [origL, sentL] = PART[name] || [name, name];
  const masked = t.sent !== t.original;
  const box = h("div", {});
  const toks = masked ? [...new Set(t.sent.match(MASK_RE) || [])] : [];
  const show = which => {
    const on = box.dataset.show === which ? "" : which;
    box.dataset.show = on;
    box.querySelector("pre")?.remove();
    if (on) box.append(on === "orig" ? highlight(t.original, t.spans, false) : highlight(t.sent, null, true));
    box.querySelectorAll("button").forEach(b => b.setAttribute("aria-pressed", b.dataset.w === on ? "true" : "false"));
  };
  box.append(h("div", { class: "masked" }, h("h3", { style: "margin:0 8px 0 0" }, name === "args" ? "Arguments" : name === "result" ? "Result" : name === "prompt" ? "Prompt" : "Reply"),
    masked ? ["Masked:", toks.map(x => h("span", { class: "tok" }, x))] : h("span", { class: "muted" }, stopped ? "stopped, not sent" : "nothing masked"),
    masked ? [h("button", { class: "btn small", "data-w": "orig", onclick: () => show("orig") }, "Show original"),
      h("button", { class: "btn small", "data-w": "sent", onclick: () => show("sent") }, `Show ${sentL.toLowerCase()}`)]
      : h("button", { class: "btn small", "data-w": "orig", onclick: () => show("orig") }, stopped ? "Show what the agent tried to send" : "Show text")));
  return box;
}

function card(e, isOpen) {
  const x = e.explain;
  const parts = Object.entries(e.text || {});
  const fp = (e.content_sha256 || "").slice(0, 12);
  const body = h("div", { class: "body" },
    h("div", { class: "why2" },
      h("div", { class: "why" }, h("b", {}, "Why"), x.why),
      h("div", { class: "why" }, h("b", {}, "What you can do"), x.todo)),
    parts.length ? parts.map(([k, t]) => textBlock(k, t, e.verdict)) : h("div", { class: "muted" }, "Full text not stored on this laptop for this action."),
    h("div", { class: "why" }, h("b", {}, "Sent to server"),
      `The decision (${VERDICT[e.verdict] || e.verdict}), the reason, the session state and a fingerprint of the text (`, h("code", {}, fp + "…"), "). Never the text itself."),
    h("details", { class: "tech" }, h("summary", {}, "Technical details"),
      h("table", {}, h("tbody", {},
        h("tr", {}, h("td", {}, "Rules"), h("td", { class: "mono" }, (e.reasons || []).map(r => h("div", {}, `${r.rule} (tier ${r.tier})${r.detail ? ": " + r.detail : ""}`)))),
        h("tr", {}, h("td", {}, "Tool"), h("td", { class: "mono" }, `${e.door} door · ${e.tool}`)),
        h("tr", {}, h("td", {}, "Trace ID"), h("td", { class: "mono" }, e.trace_id || "–")),
        h("tr", {}, h("td", {}, "Session"), h("td", { class: "mono" }, `${e.session_id || e.key_id} · ${e.state_before || "?"} → ${e.state_after || "?"}`)),
        h("tr", {}, h("td", {}, "Timing (ms)"), h("td", { class: "mono" }, Object.entries(e.latency_ms || {}).map(([k, v]) => `${k} ${v}`).join(" · ") || "–")),
        h("tr", {}, h("td", {}, "Checks"), h("td", { class: "mono" }, (e.stages || []).map(st => `${st.name}=${st.outcome}${st.ms != null ? ` ${st.ms}ms` : ""}`).join(" · "))),
        e.t2_score != null ? h("tr", {}, h("td", {}, "Injection score"), h("td", { class: "mono" }, e.t2_score.toFixed(3))) : null,
        h("tr", {}, h("td", {}, "Policy"), h("td", { class: "mono" }, e.policy_version || "–")),
        h("tr", {}, h("td", {}, "Fingerprint"), h("td", { class: "mono" }, e.content_sha256 || "–"))))));
  return h("details", { class: "card " + e.verdict, "data-trace": e.trace_id, open: isOpen },
    h("summary", {},
      h("span", { class: "time" }, time(e.ts)),
      h("span", { class: "row" }, verdictPill(e.verdict), h("span", { class: "sentence" }, x.sentence)),
      h("span", { class: "chev", "aria-hidden": "true" }, "›"),
      h("span", { class: "effect" }, x.effect),
      chain(e)),
    body);
}

/* ---------- Analytics ---------- */
function stackedChart(series, bucket) {
  const W = 720, H = 220, L = 32, B = 22, T = 8;
  const max = Math.max(1, ...series.map(r => ORDER.reduce((a, k) => a + r[k], 0)));
  const step = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000].find(st => max / st <= 4) || Math.ceil(max / 4);
  const nice = step * Math.ceil(max / step);
  const n = series.length, slot = (W - L) / Math.max(n, 1), bw = Math.min(28, slot * 0.7);
  const y = v => T + (H - T - B) * (1 - v / nice);
  const g = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Actions over time by verdict" });
  for (let v = 0; v <= nice; v += step) {
    g.append(s("line", { class: "grid", x1: L, x2: W, y1: y(v), y2: y(v) }), s("text", { x: L - 6, y: y(v) + 4, "text-anchor": "end" }, v));
  }
  const fmt = t => new Date(t).toLocaleTimeString([], bucket < 60 ? { hour: "2-digit", minute: "2-digit", second: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
  series.forEach((r, i) => {
    const x = L + slot * i + (slot - bw) / 2;
    let acc = 0;
    for (const k of ORDER) {
      if (!r[k]) continue;
      const rect = s("rect", { class: "f-" + k, x, width: bw, y: y(acc + r[k]), height: Math.max(0, y(acc) - y(acc + r[k])), rx: 2 });
      rect.append(s("title", {}, `${fmt(r.t)}: ${r[k]} ${VERDICT[k].toLowerCase()}`));
      g.append(rect); acc += r[k];
    }
    if (n <= 12 || i % Math.ceil(n / 8) === 0) g.append(s("text", { x: x + bw / 2, y: H - 6, "text-anchor": "middle" }, fmt(r.t)));
  });
  return g;
}

function legend() {
  return h("div", { class: "legend" }, ORDER.map(k => h("span", {}, h("i", { style: `background:var(--${k})` }), VERDICT[k])));
}

async function renderAnalytics() {
  const a = await api("/analytics");
  const head = [h("h1", {}, "Analytics"), h("p", { class: "sub" }, "This laptop only: what your agents did and what Tollgate changed.")];
  if (!a.n) return view().replaceChildren(...head, empty());
  const kpi = (n, l, cls) => h("div", { class: "panel kpi " + (cls || "") }, h("div", { class: "n" }, n), h("div", { class: "l" }, l));
  const maxR = Math.max(1, ...a.top_reasons.map(r => r.count));
  const maxS = Math.max(1, ...a.per_session.map(x => ORDER.reduce((t, k) => t + x.counts[k], 0)));
  view().replaceChildren(...head,
    h("div", { class: "kpis" }, kpi(a.n, "actions checked"), kpi(a.blocked, "blocked", "block"), kpi(a.masked, "went through masked", "redact"), kpi(a.per_session.length, "sessions")),
    h("div", { class: "panel" }, h("h2", {}, "Actions over time"), legend(), stackedChart(a.series, a.bucket_s),
      h("div", { class: "muted", style: "font-size:12px" }, `One bar per ${a.bucket_s >= 3600 ? a.bucket_s / 3600 + " h" : a.bucket_s >= 60 ? a.bucket_s / 60 + " min" : a.bucket_s + " s"}.`)),
    h("div", { class: "grid2" },
      h("div", { class: "panel" }, h("h2", {}, "Blocked vs masked"),
        h("div", { class: "bars" }, [["block", "Blocked", a.blocked], ["redact", "Masked", a.masked], ["allow", "Allowed", a.totals.allow]].map(([k, l, n]) =>
          h("div", { class: "bar" }, h("div", { class: "lab" }, h("span", {}, l), h("span", {}, n)),
            h("div", { class: "track" }, h("div", { style: `width:${100 * n / Math.max(1, a.n)}%;background:var(--${k})` })))))),
      h("div", { class: "panel" }, h("h2", {}, "Top reasons"),
        a.top_reasons.length ? h("div", { class: "bars" }, a.top_reasons.map(r =>
          h("div", { class: "bar", title: r.rule }, h("div", { class: "lab" }, h("span", {}, r.label), h("span", {}, r.count)),
            h("div", { class: "track" }, h("div", { style: `width:${100 * r.count / maxR}%;background:var(--accent)` })))))
          : h("div", { class: "muted" }, "Nothing flagged yet."))),
    h("div", { class: "panel", style: "margin-top:14px" }, h("h2", {}, "Per session"), legend(),
      h("div", { class: "bars" }, a.per_session.map(x => {
        const tot = ORDER.reduce((t, k) => t + x.counts[k], 0);
        return h("div", { class: "bar" },
          h("div", { class: "lab" }, h("span", {}, h("a", { href: "#sessions/" + encodeURIComponent(x.id), style: "color:inherit" }, x.agent), " ", h("span", { class: "muted" }, x.label || x.id)), h("span", {}, tot)),
          h("div", { class: "track", style: `width:${100 * tot / maxS}%` }, ORDER.filter(k => x.counts[k]).map(k =>
            h("div", { style: `width:${100 * x.counts[k] / tot}%;background:var(--${k})`, title: `${x.counts[k]} ${VERDICT[k].toLowerCase()}` }))));
      }))));
}

/* ---------- Setup ---------- */
async function renderSetup() {
  const c = await api("/setup");
  const result = h("div", {});
  const testBtn = h("button", { class: "btn primary", onclick: async () => {
    testBtn.disabled = true; result.replaceChildren(h("span", { class: "muted" }, "Asking the gateway for your tools…"));
    try {
      const t = await api("/setup/test");
      result.replaceChildren(t.ok
        ? h("div", {}, h("div", { class: "row" }, pill("allow", "Connected"), `Your agent can use ${t.tools.length} tools:`),
          h("div", { class: "tools" }, t.tools.map(x => h("span", { class: "pill ghost", title: x.name }, x.plain))))
        : h("div", {}, pill("block", "Failed"), " ", t.error));
    } catch (err) { result.replaceChildren(pill("block", "Failed"), " ", String(err)); }
    testBtn.disabled = false;
  } }, "Test connection");
  const keyBtn = h("button", { class: "btn small", onclick: ev => copy(c.key, ev.currentTarget) }, "Copy key");
  const field = (l, v, extra) => h("div", { class: "field" }, h("span", {}, l), h("span", { class: "row" }, h("code", {}, v), extra));
  view().replaceChildren(h("h1", {}, "Setup"), h("p", { class: "sub" }, `Point your agent at Tollgate. It runs as ${c.agent} (${c.role}).`),
    h("div", { class: "setup" },
      h("div", { class: "panel" }, h("h2", {}, "Connection"),
        field("Server", c.server), field("MCP URL", c.mcp_url, h("button", { class: "btn small", onclick: ev => copy(c.mcp_url, ev.currentTarget) }, "Copy")),
        field("Model URL", c.model_url), field("Key", c.key_masked, keyBtn),
        h("div", { style: "margin-top:12px" }, testBtn), result),
      h("div", { class: "panel local-sent" }, h("h2", {}, "What stays here, what is sent"),
        h("div", { class: "why2" },
          h("div", {}, h("h3", {}, "Stays on this laptop"), h("ul", {}, h("li", {}, "Full text of prompts, arguments and results"), h("li", {}, "The original of every masked item"), h("li", {}, "Your key"))),
          h("div", {}, h("h3", {}, "Sent to the server"), h("ul", {}, h("li", {}, "Decision and reason for each action"), h("li", {}, "Tool name, time, session state"), h("li", {}, "A fingerprint (SHA-256) of the text, never the text"))))),
      h("div", { class: "panel wide" }, h("h2", {}, "Config snippets"), h("p", { class: "muted", style: "margin:0" }, "The key is shown masked; Copy puts the real key on your clipboard."),
        Object.entries(c.snippets).map(([name, sn]) => h("div", { class: "snip" },
          h("div", { class: "row" }, h("h3", { style: "margin:0" }, name), h("button", { class: "btn small", onclick: ev => copy(sn.replaceAll("{KEY}", c.key), ev.currentTarget) }, "Copy")),
          h("pre", {}, sn.replaceAll("{KEY}", c.key_masked)))))));
}

/* ---------- Scenario ---------- */
let running = false;
async function renderScenario() {
  const { acts } = await api("/scenario");
  const all = acts.flatMap(a => a.steps).filter(st => !st.operator);
  const done = all.filter(st => st.result), passed = done.filter(st => st.result.pass);
  const runSteps = async ids => {
    if (running) return; running = true;
    for (const id of ids) { await api("/scenario/run/" + encodeURIComponent(id), { method: "POST" }); await renderScenario(); }
    running = false; renderScenario();
  };
  const btn = (label, fn, cls) => h("button", { class: "btn " + (cls || ""), disabled: running, onclick: fn }, label);
  view().replaceChildren(h("h1", {}, "Scenario"),
    h("p", { class: "sub" }, "The Acme story run through the real gateway, step by step: expected vs what actually happened."),
    h("div", { class: "sc-bar" }, btn("Run all", () => runSteps(all.map(x => x.id)), "primary"),
      btn("Reset", async () => { await api("/scenario/reset", { method: "POST" }); renderScenario(); }),
      h("span", { class: "score" }, done.length ? `${passed.length} of ${done.length} passed` : `${all.length} steps`)),
    ...acts.map(a => h("section", { class: "panel act" },
      h("div", { class: "act-h" }, h("div", {}, h("h2", {}, `Act ${a.id}: ${a.title}`), a.subtitle ? h("div", { class: "muted" }, a.subtitle) : null),
        a.operator ? pill("ghost", "Server console") : btn("Run act", () => runSteps(a.steps.filter(x => !x.operator).map(x => x.id)), "small")),
      h("table", { class: "steps" },
        h("thead", {}, h("tr", {}, h("th", {}, "#"), h("th", { class: "who" }, "Agent"), h("th", {}, "Action"), h("th", {}, "Expected"), h("th", {}, "Got"), h("th", {}, "Result"), h("th", {}))),
        h("tbody", {}, a.steps.map(st => st.operator
          ? h("tr", { class: "op" }, h("td", { class: "id" }, st.id), h("td", { class: "who" }, st.agent), h("td", {}, st.text), h("td", { colspan: 3 }, "Operator step: done in the Server console"), h("td", {}))
          : h("tr", {},
            h("td", { class: "id" }, st.id), h("td", { class: "who" }, st.agent),
            h("td", {}, st.text, st.needs ? h("div", { class: "muted", style: "font-size:12px" }, st.needs === "classifier" ? "needs the injection classifier" : "needs a model (Ollama or --scripted-model)") : null),
            h("td", { class: "exp" }, st.expected),
            h("td", { class: "got" }, st.result ? [st.result.got, st.result.why ? h("div", { class: "why-f" }, st.result.why) : null,
              st.result.session_id && st.result.trace_id ? h("div", {}, h("a", { href: "#sessions/" + encodeURIComponent(st.result.session_id), onclick: () => (ui.openTrace = st.result.trace_id) }, "Open in Sessions")) : null] : h("span", { class: "muted" }, "–")),
            h("td", { class: "res" }, st.result ? pill(st.result.pass ? "pass" : "fail", st.result.pass ? "PASS" : "FAIL") : null),
            h("td", { class: "act-c" }, btn("Run", () => runSteps([st.id]), "small")))))))));
}

/* ---------- routing + live updates ---------- */
const VIEWS = { sessions: renderSessions, analytics: renderAnalytics, setup: renderSetup, scenario: renderScenario };
async function route(focus) {
  const [v, arg] = (location.hash.slice(1) || "sessions").split("/");
  ui.view = VIEWS[v] ? v : "sessions";
  if (ui.view === "sessions" && arg) ui.session = decodeURIComponent(arg);
  document.querySelectorAll(".nav a").forEach(a => a.dataset.view === ui.view ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"));
  try { await VIEWS[ui.view](); } catch (err) { view().replaceChildren(h("div", { class: "empty" }, "Could not load: " + err.message)); }
  if (focus) view().focus({ preventScroll: true });
}
window.addEventListener("hashchange", () => route(true));

let pending = null;
function onEvent() {  // debounce bursts (Run all) into one refresh
  clearTimeout(pending);
  pending = setTimeout(() => {
    refreshStatus();
    if (ui.view === "sessions" || ui.view === "analytics") route(false);
  }, 400);
}
function live() {
  const es = new EventSource(API + "/events");
  es.onmessage = onEvent;
  es.onerror = () => refreshStatus();
}

refreshStatus();
route(false);
live();
setInterval(refreshStatus, 15000);
