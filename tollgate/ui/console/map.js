// Access map (top of the console Overview): peers -> agents -> servers & tools, from /console/api/map.
// Hand-rolled SVG, CSS tokens only. Uses h, s, n, card (common.js) and api, ui, sessHref, ago (app.js; called at run time).
"use strict";

const MAP = { sel: null, data: null, prev: null, prevRange: null, fresh: new Set() };
const MAP_TOP = { p: 12, r: 8, s: 10 };  // per column; the rest fold into one "N more" node
const COL_NAME = { p: "Peers", r: "Agents", s: "Servers & tools" };
const trunc = (t, k) => (t = String(t ?? "")).length > k ? t.slice(0, k - 1) + "…" : t;
const plu = (k, w) => `${n(k)} ${w}${k === 1 ? "" : "s"}`;

async function mapCard() {
  let d;
  try { d = await api("/map?range=" + ui.range); } catch {
    MAP.data = null;
    return card("Access map", null, h("div", { class: "empty" }, "Could not load the access map. The page retries every 10 seconds."));
  }
  // links whose calls grew since the last refresh pulse once (same range only)
  const now = Object.fromEntries(d.links.map(l => [l.from + ">" + l.to, l.calls]));
  MAP.fresh = new Set(MAP.prev && MAP.prevRange === ui.range ? Object.keys(now).filter(k => now[k] > (MAP.prev[k] || 0)) : []);
  MAP.prev = now; MAP.prevRange = ui.range; MAP.data = d;
  const sw = (cls, l) => h("span", {}, h("i", { class: cls }), l);
  return card("Access map", h("div", { class: "legend amap-legend" }, sw("lg-line", "Calls"), sw("lg-line red", "Blocked"),
    sw("lg-ring", "Blocked in range"), sw("lg-off", "Offline")),
    h("div", { class: "amap", id: "amap" }, h("div", { class: "amap-plot" }), h("aside", { class: "amap-side" })));
}

// Model: filter paths to the selection, fold long columns, aggregate links and node totals.
function mapModel(d, sel) {
  const paths = sel ? d.paths.filter(x => [`p:${x.peer}`, `r:${x.role}`, `s:${x.server}`].includes(sel)) : d.paths;
  const base = {
    p: d.peers.map(x => ({ key: "p:" + x.id, label: x.label, online: x.online, revoked: x.revoked, unenrolled: x.id === "unenrolled" })),
    r: d.roles.map(x => ({ key: "r:" + x.role, label: x.agent, sub: x.role })),
    s: d.servers.map(x => ({ key: "s:" + x.id, label: x.label })),
  };
  const tot = {};
  const add = (k, x) => { const t = tot[k] ||= { calls: 0, blocked: 0, last: "" }; t.calls += x.calls; t.blocked += x.blocked; if (x.last_ts > t.last) t.last = x.last_ts; };
  for (const x of paths) { add("p:" + x.peer, x); add("r:" + x.role, x); add("s:" + x.server, x); }
  const cols = {}, disp = {};
  for (const c of "prs") {
    let list = base[c].filter(x => !sel || tot[x.key] || x.key === sel).map(x => ({ ...x, ...(tot[x.key] || { calls: 0, blocked: 0, last: "" }) }));
    list.sort((a, b) => b.calls - a.calls || (c === "p" ? a.unenrolled - b.unenrolled : 0));
    if (list.length > MAP_TOP[c]) {
      const rest = list.slice(MAP_TOP[c] - 1);
      const more = { key: c + ":+", more: true, label: `${rest.length} more ${COL_NAME[c].toLowerCase()}`, calls: 0, blocked: 0, last: "" };
      for (const x of rest) { disp[x.key] = more.key; more.calls += x.calls; more.blocked += x.blocked; if (x.last > more.last) more.last = x.last; }
      list = [...list.slice(0, MAP_TOP[c] - 1), more];
    }
    for (const x of list) disp[x.key] ||= x.key;
    cols[c] = list;
  }
  const links = {}, touch = {};
  const link = (a, b, x) => {
    const k = a + ">" + b, l = links[k] ||= { key: k, a, b, calls: 0, blocked: 0, lb: null };
    l.calls += x.calls; l.blocked += x.blocked;
    if (x.last_blocked && (!l.lb || x.last_blocked.ts > l.lb.ts)) l.lb = x.last_blocked;
    return k;
  };
  for (const x of paths) {
    const [p, r, s2] = [disp["p:" + x.peer], disp["r:" + x.role], disp["s:" + x.server]];
    const ks = [link(p, r, x), link(r, s2, x)];
    for (const node of [p, r, s2]) { const t = touch[node] ||= new Set(); ks.forEach(k => t.add(k)); [p, r, s2].forEach(k => t.add(k)); }
  }
  return { cols, links: Object.values(links), touch };
}

function drawMap() {
  const box = document.getElementById("amap"), d = MAP.data;
  if (!box || !d) return;
  const plot = box.querySelector(".amap-plot"), side = box.querySelector(".amap-side");
  if (MAP.sel && !d.paths.some(x => [`p:${x.peer}`, `r:${x.role}`, `s:${x.server}`].includes(MAP.sel))) MAP.sel = null;
  const M = mapModel(d, MAP.sel);
  const W = Math.max(560, plot.clientWidth), top = 36, rowH = 48;
  const most = Math.max(2, ...Object.values(M.cols).map(c => c.length));
  const H = Math.max(380, top + most * rowH + 8);
  const padL = Math.min(240, W * 0.28), padR = Math.min(200, W * 0.24);
  const X = { p: padL, r: (padL + W - padR) / 2, s: W - padR };
  const pos = {};
  for (const c of "prs") {
    const list = M.cols[c], gap = Math.min(110, (H - top - 8) / list.length), y0 = top + (H - top - 8 - gap * list.length) / 2;
    const max = Math.max(1, ...list.map(x => x.calls));
    list.forEach((x, i) => pos[x.key] = { x: X[c], y: y0 + gap * (i + .5), r: 5 + (c === "p" ? 10 : 12) * Math.sqrt(x.calls / max), node: x, c });
  }
  const lmax = Math.max(1, ...M.links.map(l => l.calls));
  const lw = k => 1.5 + 13 * (k / lmax);

  const svg = s("svg", { class: "amap-svg", width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "group",
    "aria-label": `Access map, ${RANGES[ui.range] || ui.range}: ${plu(M.cols.p.length, "peer")}, ${plu(M.cols.r.length, "agent")}, ` +
      `${plu(M.cols.s.length, "server")}; ${plu(M.links.filter(l => l.a.startsWith("p")).reduce((a, l) => a + l.calls, 0), "call")}, ` +
      `${n(M.links.filter(l => l.a.startsWith("p")).reduce((a, l) => a + l.blocked, 0))} blocked. The list beside it has the latest sessions.` });
  for (const c of "prs") svg.append(s("text", { class: "amap-col", x: X[c], y: 14, "text-anchor": c === "p" ? "end" : c === "r" ? "middle" : "start" }, COL_NAME[c]));
  const gLinks = s("g", {}), gNodes = s("g", {});
  svg.append(gLinks, gNodes);
  const tip = h("div", { class: "amap-tip", role: "tooltip", hidden: true });
  const showTip = (el, lines) => {
    tip.replaceChildren(...lines.map((t, i) => h("div", { class: i ? "muted" : "t" }, t)));
    tip.hidden = false;
    const b = el.getBoundingClientRect(), p = plot.getBoundingClientRect();
    tip.style.left = Math.min(W - 220, Math.max(0, b.left - p.left + b.width / 2 - 100)) + "px";
    tip.style.top = (b.bottom - p.top + 6) + "px";
  };
  const hl = keys => {
    svg.classList.toggle("hl", !!keys);
    svg.querySelectorAll("[data-k]").forEach(el => el.classList.toggle("on", !!keys && keys.has(el.dataset.k)));
  };
  const leave = () => { hl(null); tip.hidden = true; };

  for (const l of M.links) {
    const A = pos[l.a], B = pos[l.b], x1 = A.x + A.r, x2 = B.x - B.r, mx = (x1 + x2) / 2;
    const dd = `M${x1},${A.y} C${mx},${A.y} ${mx},${B.y} ${x2},${B.y}`, w = lw(l.calls);
    const g = s("g", { "data-k": l.key, class: "amap-link" + (MAP.fresh.has(l.key) ? " pulse" : "") });
    g.append(s("path", { d: dd, class: "ln", "stroke-width": w }));
    if (l.blocked) g.append(s("path", { d: dd, class: "ln-b", "stroke-width": Math.max(1.5, w * l.blocked / l.calls) }));
    const hit = s("path", { d: dd, class: "hit", "stroke-width": Math.max(12, w + 6) });
    const words = `${A.node.label} → ${B.node.label}`, stat = `${plu(l.calls, "call")}` + (l.blocked ? ` · ${n(l.blocked)} blocked` : "");
    const go = () => { if (l.lb) location.hash = sessHref(l.lb.session_id, l.lb.trace_id); };
    if (l.lb) { hit.setAttribute("tabindex", "0"); hit.setAttribute("role", "link"); hit.setAttribute("aria-label", `${words}: ${stat}. Open the latest blocked session.`); }
    const enter = () => { hl(new Set([l.key, l.a, l.b])); showTip(hit, [words, stat, l.lb ? "Click: latest blocked session" : ""].filter(Boolean)); };
    hit.addEventListener("mouseenter", enter); hit.addEventListener("focus", enter);
    hit.addEventListener("mouseleave", leave); hit.addEventListener("blur", leave);
    hit.addEventListener("click", go);
    hit.addEventListener("keydown", ev => { if (ev.key === "Enter") go(); });
    g.append(hit);
    gLinks.append(g);
  }
  MAP.fresh = new Set();  // pulse once per refresh, not on every redraw

  for (const [key, P] of Object.entries(pos)) {
    const x = P.node, c = P.c, r = P.r, off = c === "p" && !x.unenrolled && !x.more && (!x.online || x.revoked);
    const g = s("g", { "data-k": key, class: `amap-node n-${c}` + (off ? " off" : "") + (c === "p" && x.online && !x.revoked ? " live" : "")
      + (key === MAP.sel ? " sel" : "") + (x.more ? " more" : ""), tabindex: "0", role: "button",
      transform: `translate(${P.x},${P.y})`, "aria-pressed": String(key === MAP.sel),
      "aria-label": `${x.more ? "" : COL_NAME[c].replace(/s( &.*)?$/, "") + " "}${x.label}: ${plu(x.calls, "call")}, ${n(x.blocked)} blocked` + (off ? x.revoked ? ", revoked" : ", offline" : "") });
    const shape = (rr, cls) => c === "p" ? s("circle", { r: rr, class: cls }) : s("rect", { x: -rr, y: -rr, width: 2 * rr, height: 2 * rr, rx: c === "r" ? rr * .45 : 3, class: cls });
    if (x.blocked) g.append(shape(r + 4, "ring"));
    g.append(shape(r, "shape"));
    const status = c !== "p" || x.more || x.unenrolled ? "" : x.revoked ? "Revoked" : x.online ? "Online" : "Offline";
    const meta = [status, plu(x.calls, "call")].filter(Boolean).join(" · ");
    const t1 = trunc(x.label, c === "r" ? 26 : 30);
    if (c === "r") {
      g.append(s("text", { class: "lbl halo", y: -r - 18, "text-anchor": "middle" }, t1),
        s("text", { class: "sub halo", y: -r - 6, "text-anchor": "middle" }, `${x.sub} · ${meta}` + (x.blocked ? ` · ${n(x.blocked)} blocked` : "")));
    } else {
      const ax = c === "p" ? -r - 10 : r + 10, anchor = c === "p" ? "end" : "start";
      const sub = s("text", { class: "sub", x: ax, y: 13, "text-anchor": anchor }, meta);
      if (x.blocked) sub.append(s("tspan", { class: "bl" }, ` · ${n(x.blocked)} blocked`));
      g.append(s("text", { class: "lbl", x: ax, y: -1, "text-anchor": anchor }, t1), sub);
    }
    const lines = [x.label, `${plu(x.calls, "call")} · ${n(x.blocked)} blocked`, x.last ? `Last call ${ago(x.last).toLowerCase()}` : "No calls in this range",
      status && status !== "Online" ? status : "", x.more ? (c === "p" ? "Click: all peers" : "") : key === MAP.sel ? "Click: show everything" : "Click: only this"].filter(Boolean);
    const enter = () => { hl(M.touch[key] || new Set([key])); showTip(g, lines); };
    const pick = () => {
      if (x.more) { if (c === "p") location.hash = "#/peers"; return; }
      MAP.sel = MAP.sel === key ? null : key;
      drawMap();
      document.querySelector(`#amap [data-k="${CSS.escape(key)}"][role=button]`)?.focus({ preventScroll: true });
    };
    g.addEventListener("mouseenter", enter); g.addEventListener("focus", enter);
    g.addEventListener("mouseleave", leave); g.addEventListener("blur", leave);
    g.addEventListener("click", pick);
    g.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pick(); } });
    gNodes.append(g);
  }
  svg.addEventListener("keydown", ev => { if (ev.key === "Escape" && MAP.sel) { MAP.sel = null; drawMap(); } });
  if (!d.paths.length) svg.append(s("text", { class: "amap-empty", x: X.r, y: H / 2 + 40, "text-anchor": "middle" }, "No calls in this time range"));
  plot.replaceChildren(svg, tip);
  drawMapSide(side, d, pos);
  side.style.maxHeight = H + 20 + "px";
}

function drawMapSide(side, d, pos) {
  const node = MAP.sel && pos[MAP.sel]?.node;
  const rows = d.sessions[MAP.sel || "*"] || [];
  side.replaceChildren(
    h("div", { class: "amap-side-h" }, h("h3", { class: "ell", title: node ? node.label : "" }, node ? node.label : "Latest sessions"),
      node ? h("button", { class: "btn sm", type: "button", onclick: () => { MAP.sel = null; drawMap(); } }, "Show all") : null),
    h("div", { class: "muted small" }, node ? `${plu(node.calls, "call")} · ${n(node.blocked)} blocked · latest sessions` : "Click a peer, agent or server to follow it."),
    rows.length ? h("ul", { class: "amap-list" }, rows.map(x => h("li", {}, h("a", { href: sessHref(x.id) },
      h("span", { class: "ell" }, `${x.agent} · ${x.peer_label}`),
      h("span", { class: "muted small" }, `${ago(x.last_ts)} · ${plu(x.n, "call")}`, x.blocked ? h("span", { class: "bl" }, ` · ${n(x.blocked)} blocked`) : null)))))
      : h("div", { class: "muted small amap-none" }, "No sessions in this time range."));
}

let mapRaf = 0;
window.addEventListener("resize", () => { cancelAnimationFrame(mapRaf); mapRaf = requestAnimationFrame(drawMap); });
