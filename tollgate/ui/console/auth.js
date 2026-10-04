// Console accounts (docs/ui-spec.md "Server console, accounts"): sign-in, owner setup and invite screens, Users view.
// Loaded before app.js; uses its globals (API, ui, api, post, h, ...) at call time. The server enforces every rule here:
// hiding a button for a viewer is presentation only.
"use strict";

const authBox = () => document.getElementById("auth");
function authShell(on) { authBox().hidden = !on; document.querySelector(".shell").hidden = on; }
const jsonHeaders = () => ({ "Content-Type": "application/json", "X-CSRF-Token": (ui.me && ui.me.csrf) || "" });

async function boot() {
  const acc = location.hash.match(/^#\/accept\/([A-Za-z0-9_-]+)$/);
  if (acc) return authForm("accept", acc[1]);
  let r = null, me = null;
  try { r = await fetch(API + "/auth/me", { cache: "no-store" }); me = await r.json(); } catch { /* server down */ }
  if (me && me.setup) return authForm(me.can_setup ? "setup" : "nosetup");
  if (!r || !r.ok) return authForm("login", null, r ? "" : "Could not reach the server.");
  signedIn(me);
}

function signedIn(me) {
  ui.me = me;
  document.documentElement.dataset.role = me.role;
  authShell(false);
  if (!/^#\/[a-z]/.test(location.hash) || location.hash.startsWith("#/accept")) history.replaceState(null, "", "#/overview");
  if (!ui.started) { ui.started = true; start(); } else { refreshStatus(); route(false); }
}

function showAuth() {  // any 401: the session ended (expired, signed out elsewhere, disabled)
  if (!authBox().hidden) return;
  ui.me = null;
  document.querySelectorAll("dialog[open]").forEach(d => d.close());
  authForm("login", null, "Your session ended. Sign in again.");
}

async function signOut() {
  try { await fetch(API + "/auth/logout", { method: "POST", headers: jsonHeaders(), body: "{}" }); } catch { /* cookie expires anyway */ }
  ui.me = null;
  authForm("login");
}

function authForm(kind, token, note) {
  authShell(true);
  const [title, action, lead] = {
    login: ["Sign in", "Sign in", "Tollgate server console."],
    setup: ["Create the owner account", "Create account", "No account exists yet. The owner is an admin and can invite others."],
    accept: ["Join Tollgate", "Create account", "You were invited to the Tollgate console. Choose your password."],
    nosetup: ["No account yet", null, null],
  }[kind];
  const err = h("p", { class: "auth-err", role: "alert" }, note || "");
  const input = (id, label, type, ac, hint) => {
    const el = h("input", { id: "a-" + id, name: id, type, autocomplete: ac, required: true, spellcheck: "false",
      ...(type === "password" && kind !== "login" ? { minlength: "12" } : {}) });
    return { el, row: h("div", { class: "fld" }, h("label", { for: el.id }, label), el, hint ? h("span", { class: "muted small" }, hint) : null) };
  };
  const f = {};
  if (kind !== "login") f.name = input("name", "Your name", "text", "name");
  if (kind === "login" || kind === "setup") f.email = input("email", "Email", "email", "username");
  f.password = input("password", "Password", "password", kind === "login" ? "current-password" : "new-password",
    kind === "login" ? null : "At least 12 characters.");
  if (kind !== "login") f.again = input("again", "Password again", "password", "new-password");
  if (kind === "accept") f.name.el.required = false;
  if (kind === "setup") f.name.el.required = false;

  const go = h("button", { class: "btn primary", type: "submit" }, action);
  const form = h("form", { novalidate: true, onsubmit: async ev => {
    ev.preventDefault();
    err.textContent = "";
    const v = k => f[k] ? f[k].el.value : undefined;
    if (f.email && !v("email").trim()) { err.textContent = "Enter your email."; return f.email.el.focus(); }
    if (!v("password")) { err.textContent = "Enter your password."; return f.password.el.focus(); }
    if (kind !== "login" && v("password").length < 12) { err.textContent = "The password needs at least 12 characters."; return f.password.el.focus(); }
    if (f.again && v("again") !== v("password")) { err.textContent = "The passwords differ."; return f.again.el.focus(); }
    const body = kind === "accept" ? { token, name: v("name"), password: v("password") }
      : { email: v("email").trim(), name: v("name"), password: v("password") };
    go.disabled = true;
    let r, j = {};
    try {
      r = await fetch(API + "/auth/" + kind, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), cache: "no-store" });
      j = await r.json().catch(() => ({}));
    } catch { err.textContent = "Could not reach the server."; go.disabled = false; return; }
    go.disabled = false;
    if (!r.ok) { err.textContent = j.error || `Failed (${r.status}).`; f.password.el.value = ""; if (f.again) f.again.el.value = ""; return f.password.el.focus(); }
    signedIn(j);
  } }, Object.values(f).map(x => x.row), err, go);

  const brand = h("div", { class: "brand" }, s("svg", { class: "i", viewBox: "0 0 24 24", "aria-hidden": "true" }, s("path", { d: "M12 3 4 6v6c0 4.5 3.4 8.2 8 9 4.6-.8 8-4.5 8-9V6z" })), "Tollgate");
  const body = kind === "nosetup"
    ? [h("p", {}, "Create the owner account on the server itself: open this page there (", h("code", {}, "http://127.0.0.1:…/console/"), "), or run:"),
       h("pre", { class: "mono auth-cmd" }, "uv run tollgate admin create --email you@company.com")]
    : [lead ? h("p", { class: "muted" }, lead) : null, form];
  authBox().replaceChildren(h("main", { class: "auth-card", "aria-labelledby": "auth-t" }, brand, h("h1", { id: "auth-t" }, title), ...body));
  (Object.values(f)[0] || {}).el?.focus();
}

/* ---------- Users (admin only; the API refuses viewers) ---------- */
async function renderUsers() {
  const d = await api("/users");
  bar(h("button", { class: "btn adm", type: "button", onclick: inviteDialog }, icon("plus"), "Invite user"));
  const msg = h("p", { class: "small err", role: "alert", style: "margin:0;min-height:20px" });
  const roleSel = u => {
    const s = h("select", { class: "style-pick", "aria-label": `Role of ${u.email}`, disabled: u.disabled, onchange: async () => {
      msg.textContent = "";
      try { await post(`/users/${enc(u.email)}/role`, { role: s.value }); route(false); } catch (e) { msg.textContent = e.message.replace(/^\d+ /, ""); s.value = u.role; }
    } }, ["admin", "viewer"].map(r => h("option", { value: r, selected: u.role === r }, r === "admin" ? "Admin" : "Viewer")));
    return s;
  };
  const rows = d.users.map(u => h("tr", {},
    h("td", { title: u.email }, h("div", { class: "two" }, h("span", { class: "ell" }, u.name, u.email === d.me ? h("span", { class: "muted small" }, " (you)") : null), h("span", { class: "ell muted small" }, u.email))),
    h("td", {}, roleSel(u)),
    h("td", { class: "num" }, time(u.created_at)),
    h("td", { class: "num", title: u.last_login ? time(u.last_login) : "" }, u.last_login ? ago(u.last_login) : "Never"),
    h("td", {}, u.disabled ? h("span", { class: "badge" }, icon("x"), "Disabled") : "Active"),
    h("td", { class: "r" }, u.email === d.me ? null : h("button", { class: "btn sm" + (u.disabled ? "" : " danger"), type: "button",
      onclick: () => u.disabled ? setDisabled(u, false, msg) : disableDialog(u, msg) }, u.disabled ? "Enable" : "Disable"))));
  const log = d.log.length ? tbl(["150px", "200px", null], ["When", "Who", "What"], d.log.map(x => h("tr", {},
    h("td", { class: "num", title: time(x.ts) }, ago(x.ts)), h("td", { class: "ell", title: x.who }, x.who), h("td", {}, x.what))))
    : h("div", { class: "empty" }, "No admin actions yet.");
  view().replaceChildren(h("div", { class: "stack" },
    card("Users", h("span", { class: "muted small" }, `${n(d.users.length)} account${d.users.length === 1 ? "" : "s"} · admins change things, viewers only look`),
      tbl([null, "120px", "150px", "110px", "100px", "96px"], ["Name", "Role", "Created", "Last sign-in", "Status", ["", "r"]], rows), h("div", { class: "card-b" }, msg)),
    card("Recent admin actions", h("span", { class: "muted small" }, "Last 50"), log)));
}

async function setDisabled(u, disabled, msg) {
  try { await post(`/users/${enc(u.email)}/disabled`, { disabled }); route(false); return true; }
  catch (e) { msg.textContent = e.message.replace(/^\d+ /, ""); return false; }
}

function disableDialog(u, msg) {
  const cancel = h("button", { class: "btn", type: "button", autofocus: true, onclick: () => d.close() }, "Cancel");
  const go = h("button", { class: "btn danger-fill", type: "button", onclick: async () => { go.disabled = true; await setDisabled(u, true, msg); d.close(); } }, `Disable ${u.name}`);
  const d = dialog(`Disable ${u.email}?`, [h("p", {}, `${u.name} is signed out everywhere now and cannot sign in until an admin enables the account again.`)], [cancel, go]);
}

function inviteDialog() {
  const email = h("input", { id: "inv-email", type: "email", autocomplete: "off", required: true, spellcheck: "false" });
  const role = h("select", { id: "inv-role" }, h("option", { value: "viewer" }, "Viewer: sees everything, changes nothing"), h("option", { value: "admin" }, "Admin: can change policy, access, peers and users"));
  const err = h("p", { class: "err small", role: "alert" });
  const cancel = h("button", { class: "btn", type: "button", onclick: () => d.close() }, "Cancel");
  const go = h("button", { class: "btn primary", type: "submit", form: "invform" }, "Create invite link");
  const form = h("form", { class: "pub", id: "invform", novalidate: true, onsubmit: async ev => {
    ev.preventDefault();
    err.textContent = "";
    if (!email.value.trim()) { err.textContent = "Enter an email."; return email.focus(); }
    go.disabled = true;
    try {
      const t = await post("/users/invite", { email: email.value.trim(), role: role.value });
      const copyBtn = h("button", { class: "btn sm", type: "button", onclick: e => copy(t.link, e.currentTarget) }, "Copy");
      form.replaceChildren(h("p", {}, `Send this link to ${t.email} privately. It creates their ${t.role === "admin" ? "admin" : "viewer"} account.`),
        h("div", { class: "cmd" }, h("pre", { class: "mono" }, t.link), copyBtn),
        h("p", { class: "muted small", style: "margin:12px 0 0" }, `One use only. Expires ${time(t.expires_at)}. Anyone holding the link can use it.`));
      go.remove(); cancel.textContent = "Close"; copyBtn.focus();
      if (ui.view === "users") route(false);
    } catch (e) { err.textContent = e.message.replace(/^\d+ /, ""); go.disabled = false; }
  } },
    h("div", { class: "fld" }, h("label", { for: "inv-email" }, "Email"), email),
    h("div", { class: "fld" }, h("label", { for: "inv-role" }, "Role"), role), err);
  const d = dialog("Invite a user", form, [cancel, go]);
  email.focus();
}
