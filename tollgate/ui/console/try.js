// Tollgate server console: "Try it" view. Dry-run the role's content check on ad-hoc text (POST /console/api/try).
// Loaded before app.js; uses its api/post/view/bar helpers at call time.
"use strict";

const TRY_MASK_RE = /\[(?:EMAIL|SECRET|PESEL|NIP|SIG|INJ|IBAN:[^\]]*|CARD:[^\]]*)\]/g;  // same as edge MASK_RE
const tryState = { meta: null, role: null, point: "prompt", text: "", result: null, busy: false, error: null };
const TRY_VERDICT = { block: ["blocked", "Blocked"], redact: ["masked", "Masked"], flag: ["flagged", "Flagged"], allow: [null, "Allowed"] };

function maskedPre(text) {
  const pre = h("pre", { class: "text" });
  let last = 0;
  for (const m of text.matchAll(TRY_MASK_RE)) { pre.append(text.slice(last, m.index), h("mark", {}, m[0])); last = m.index + m[0].length; }
  pre.append(text.slice(last));
  return pre;
}

async function tryCheck() {
  const s = tryState;
  if (s.busy || !s.text.trim()) return;
  s.busy = true; s.error = null; tryPaint();
  try { s.result = await post("/try", { role: s.role, point: s.point, text: s.text }); } catch (err) { s.error = err.message; s.result = null; }
  s.busy = false; tryPaint();
}

function tryResult() {
  const s = tryState, r = s.result;
  if (s.busy) return card("Result", null, h("div", { class: "empty", role: "status" }, "Checking…"));
  if (s.error) return card("Result", null, h("div", { class: "card-b" }, h("div", { class: "rejected boxed", role: "alert" }, icon("warn"), s.error)));
  if (!r) return card("Result", null, h("div", { class: "empty" }, "Pick an example or type text, then Check."));
  const [kind, word] = TRY_VERDICT[r.verdict] || [null, r.verdict];
  const main = r.reasons.filter(x => !x.info);
  const big = kind ? h("span", { class: "badge try-big " + kind }, icon(KIND_ICON[kind]), word) : h("span", { class: "badge try-big" }, icon("check"), word);
  const sent = r.sent == null ? h("p", { class: "muted", style: "margin:0" }, "Nothing: the text is stopped before it reaches the agent or model.") : maskedPre(r.sent);
  return h("div", { class: "stack" },
    card("Result", h("span", { class: "muted small" }, "Dry run: nothing forwarded, nothing logged"),
      h("div", { class: "card-b" }, h("div", { class: "try-v" }, big, h("span", { class: "muted" }, `${ms(r.total_ms)} total`)),
        h("p", { class: "muted small", style: "margin:8px 0 0" }, r.classifier_note))),
    card("What the agent would get", null, h("div", { class: "card-b" }, sent)),
    card("Why", null, main.length ? h("div", { class: "card-b" }, h("ul", { class: "try-reasons" }, main.map(x =>
      h("li", {}, h("div", {}, h("strong", {}, x.check), " · ", x.plain), h("div", { class: "muted small mono" }, `${x.rule}: ${x.detail}`)))))
      : h("div", { class: "card-b muted" }, "Every check passed.")),
    card("Check chain", null, h("div", { class: "card-b" }, kv(r.stages.map(st => [st.name, `${st.outcome}${st.ms == null ? "" : " · " + ms(st.ms)}`])))));
}

function tryPaint() {
  const box = document.getElementById("try-res");
  if (box) box.replaceChildren(tryResult());
  const btn = document.getElementById("try-go");
  if (btn) { btn.disabled = tryState.busy; btn.textContent = tryState.busy ? "Checking…" : "Check"; }
}

async function renderTry() {
  if (document.getElementById("try")) return;  // 10 s poll: keep the form and result as they are
  const s = tryState;
  if (!s.meta) s.meta = await api("/try");
  s.role = s.role || s.meta.roles[0]?.id;
  bar(h("span", { class: "bar-t" }, "Dry run of the content check"));
  const sel = (id, label, opts, val, set) => h("label", { class: "try-f", for: id }, h("span", {}, label),
    h("select", { id, onchange: ev => set(ev.target.value) }, opts.map(([v, l]) => h("option", { value: v, selected: v === val }, l))));
  const ta = h("textarea", { id: "try-text", rows: "10", spellcheck: "false", placeholder: "Type or paste text to check",
    oninput: ev => { s.text = ev.target.value; },
    onkeydown: ev => { if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); tryCheck(); } } });
  ta.value = s.text;
  const roleSel = sel("try-role", "Role", s.meta.roles.map(r => [r.id, `${r.name} (${r.id})`]), s.role, v => { s.role = v; });
  const pointSel = sel("try-point", "Where the text appears", s.meta.points.map(p => [p.id, p.label]), s.point, v => { s.point = v; });
  const chips = h("div", { class: "try-chips", role: "group", "aria-label": "Examples" }, s.meta.presets.map(p =>
    h("button", { class: "btn sm", type: "button", onclick: () => {
      s.role = p.role; s.point = p.point; s.text = p.text; ta.value = p.text;
      roleSel.querySelector("select").value = p.role; pointSel.querySelector("select").value = p.point;
      tryCheck();
    } }, p.label)));
  const go = h("button", { id: "try-go", class: "btn primary", type: "button", onclick: tryCheck }, "Check");
  view().replaceChildren(h("div", { id: "try", class: "try" },
    card("Text to check", null, h("div", { class: "card-b try-form" }, h("div", { class: "try-row" }, roleSel, pointSel),
      h("label", { class: "try-f", for: "try-text" }, h("span", {}, "Text")), ta,
      h("div", { class: "try-row" }, go, h("span", { class: "muted small" }, "Ctrl+Enter")),
      h("div", {}, h("div", { class: "muted small", style: "margin-bottom:6px" }, "Examples"), chips))),
    h("div", { id: "try-res", tabindex: "-1", role: "region", "aria-label": "Result", "aria-live": "polite" }, tryResult())));
}
