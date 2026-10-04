# UI spec (agreed in review, 2026-10-03)

Two interfaces, same visual style:
- **Server console**: the company's security lead.
- **Local edge**: the developer whose agent runs on their laptop.

## Local edge (developer's laptop)

**Shell, shared with the server console**
- A left navigation strip to switch views, as in the first mockup.
- **Top-right status area**: a small rectangle with
  - the account icon and agent role;
  - connection status and which server it is connected to;
  - the app version, policy version and threat-feed version.
  
  Minimal; no full-width status strip.
- **Top-left health indicator**: a green "All good" dot when nothing needs attention. It turns amber or red with a short message only when something happened: an action blocked, waiting for approval, server unreachable, policy changed. Clicking it opens the event.
- **No big banner by default.** A compact notice appears only when something actually happened.

**Views (left nav)**
1. **Sessions** (default)
   - a list of **all sessions** on this laptop, each with its status (active/ended; Clean / Untrusted / Holds private data; last verdict) and the tools it used;
   - selecting a session shows its timeline: one plain sentence per action, a verdict pill, the effect on the session, masked items with "show original / show what the agent got", the check chain, Why, What you can do, Sent to server, and technical details hidden by default.
   - Optional, low priority: per-session stats (model, sources touched such as files and tickets, counts).
2. **Analytics** (local): charts like the server's, but for this laptop only: actions over time by verdict, blocked and masked counts, top reasons, per-session breakdown.
3. **Setup**: connection details, key (masked, copy), config snippets for Claude Code / Cursor / OpenAI SDK, Test connection, and what stays local vs. what is sent to the server.
4. **Scenario** (to be confirmed after a walkthrough): the Acme steps from SCENARIO.md run through the real gateway, expected vs. actual, PASS/FAIL.

**Dropped:** the "My agent" panel (tools/model/budget sidebar).

**Deferred:** analytics on classifier confidence per rule ("how sure was the injection check").

### Local edge, revision 2 (review of the first build, 2026-10-03 22:40)

**Feedback (Andrey):**
- **Too childish and generic.** Element sizes are inconsistent: some are huge and grab attention, others are properly small.
- **Too colourful** ("Christmas Eve"): red, green, amber and purple are everywhere. There should be only a couple of contrasting colours.
- **Add a general Dashboard** that shows basic analytics, not as a separate "Analytics" tab.
- Finalise and debug the local version before the server console.
- Base the style on proven AI usage/session tracking products (research running; findings get appended here).

**Visual rules, until the research refines them:**
- **Grey is the default, colour is information.**
  - Neutral greys for text, borders and charts.
  - **One accent (blue)**, for interactive elements and selection only.
  - **One alert colour (red)**, only for *blocked* and for real problems.
- **Allowed has no colour**: plain text or a neutral dot.
- **Masked** is a neutral outlined badge with a lock icon. No purple.
- **Waiting** is a neutral badge with a clock icon. No amber fills.
- Session states (Clean / Untrusted / Holds private data) are neutral text with a small icon, not coloured pills.
- Remove coloured left borders on every card, coloured progress bars and filled pill backgrounds. A small dot or icon carries status.
- Charts: grey series; only the *blocked* series in red. One chart type per question.
- **A compact type scale:**
  - 13px body, 12px secondary/labels, 15px section titles, 18px page title;
  - KPI values 22–24px, never bigger;
  - row height ~32–36px;
  - consistent 8px spacing grid.
- Tables and lists over big cards where data is tabular (the session list = a compact table/list).
- Everything the same size family: no element should be visually louder than its importance.

**Navigation, revised:**
1. **Dashboard** (new home)
2. Sessions
3. Setup
4. Scenario

The separate **Analytics tab is removed**; its useful parts move into Dashboard.

**Dashboard: the decisions it serves (decision inventory):**
1. *Is my agent OK right now?* A status line: connected, policy/feed versions, and "nothing needs attention" or the 1–3 latest things that do.
2. *Did Tollgate stop or change anything today?* A KPI strip, each with a delta vs the previous period: actions checked, blocked, masked, sessions.
3. *What happened over time?* One trend: actions per time bucket, grey, with blocked in red. The time range is selectable (15 min / 1 h / today).
4. *Why were things stopped?* Top reasons, plain English, a sorted horizontal bar, grey.
5. *What is my agent using?* Top tools / sources (GitHub, tickets, files, model), as a sorted list with counts.
6. *Where do I look next?* Recent events needing a look (blocked/flagged), each linking into its session timeline.

Order on the page, top to bottom: status line → KPI strip → trend → (reasons | tools side by side) → recent events.

### Research-backed standard (AI observability and guardrail products, 2026-10-03)

**Sources:** Langfuse (open-source code gives exact sizes), LangSmith, W&B Weave, Arize Phoenix, Datadog LLM Observability, Lakera Guard, Pangea AIDR, Microsoft Defender for Cloud AI. Full report and URLs are in the session log. The rules below are adopted for both UIs.

**Products to imitate:**
- **Local edge:** Langfuse first, then Weave, then LangSmith.
- **Server console:** Lakera Guard first, then Pangea AIDR, then Defender.

**Rules:**
1. **Neutral surface, one accent.** Status hues appear only on small badges and dots, never on numbers, card backgrounds or borders.
2. **Badges are tinted:**
   - pale background + dark text of the same hue, no border;
   - 12px text, ~20px tall, radius 4–6px.
   
   Only *Blocked* uses a hue (red). Masked, Waiting and Flagged use neutral tints with an icon.
3. **KPI tiles:**
   - a 12–13px muted label, a 22–24px value (deliberately smaller than Langfuse's 30px, per Andrey's feedback), and a small delta vs the previous period;
   - 4 tiles in one row: Actions checked · Blocked · Masked · Sessions.
4. **One global time-range picker at top right** (15 min / 1 h / today / all), applying to the whole page.
5. **Charts:** a line or stacked area over time; breakdowns as a sorted horizontal bar or top-5 table. No pies. Grey series, blocked in red.
6. **Dense tables:** 12–13px body, a muted header, ~36px rows, 8px cell padding, a hover tint.
7. **Session page is the trace layout:**
   - a summary strip on top (agent, role, started, duration, state, counts);
   - **left:** the step list (each row: tool in plain words, duration, a small badge only if blocked/masked/flagged), with a toggle to a timeline view;
   - **right:** a detail pane with tabs **Overview** (what happened + why + what you can do) · **Input/Output** (original vs what the agent got, masked spans highlighted) · **Checks** (the key → role → arguments → data flow → content chain with ms) · **Sent to server**.
8. **Guardrail hits appear in two places:** on the step (the Checks tab plus a badge), and in an **Events** list of blocked/masked/flagged items only (like Lakera's "Threats").
9. **Security wording:** name the check, then the action as a past-tense verb ("Data-flow rule: blocked", "Secret detector: masked 2 values", "Injection check: flagged"). Redactions show inline as `[SECRET]`, `[EMAIL]`, `[IBAN:…2874]`.
10. **Filters as pills** under a search box, combined with AND.
11. **Light and dark**, light by default.

**Local edge nav, final:**
1. **Overview** (the Dashboard above)
2. **Sessions** (table → trace page)
3. **Events** (blocked/masked/flagged only, filterable)
4. **Setup**
5. **Scenario**

### Local edge, revision 3 (review of v2, 2026-10-03 23:10)

**Verdict:** style and conventions are much better. Keep them.

**Changes:**
1. **Sessions = one screen (master–detail).**
   - The session list stays on the left.
   - Clicking a session opens its detail **in the right pane of the same screen**: session metadata at the top right, then the steps and the tabs.
   - No separate session page.
2. **Events: the same pattern.** The event list on the left, the selected event's detail in the right pane (with a link into its session).
3. **Setup becomes the full local agent setup**: everything about how this agent is connected and what it may do:
   - connection (server, key, expiry, clients and config snippets, test);
   - **MCP servers this agent reaches** and, per server, **allowed tools** (read/write, limits such as SELECT only and /workspace only) and **denied tools** (hidden from this role);
   - models allowed and the token budget (used / left);
   - data-flow labels per tool (outside text / private data / public destination) and what the data-flow rule does;
   - content checks in force (what is masked, what is blocked, injection strictness, signature feed version);
   - **local settings this layer may change**: keep full text locally on/off, retention, theme. Local settings may only make things *stricter or more private*, never looser than the company policy, which stays authoritative and read-only here.

### Local edge, revision 4 (audit, 2026-10-04)

- **No page titles or subtitles.** The highlighted nav item names the view. Content starts right under the top bar.
- **The top bar carries the view's controls.** From the left, aligned to the content gutter: the health indicator, then on the right the view's controls (the time range on Overview and Events, the runner on Scenario, nothing elsewhere), a compact status chip, and the theme toggle. Every control is 28px tall.
- **The status chip** shows the agent, role, a connection dot and the server. The app, policy, feed and classifier versions are in its tooltip.
- **Health counts only the last hour** (or since the last click). An all-time count kept it red forever.
- **Content is full width**, so its right edge lines up with the top bar's (24px). Master–detail views fill the viewport height. In a session, the steps take up to 40% of the pane and the step detail scrolls in the rest.

## Server console (security lead)

**Purpose:** govern and oversee **all peers** (laptops/edges running agents) and all agents in the company. This is the complex side and the primary UI.

**Shell:** the same as the edge. Left navigation, top-right status area (admin account, server health, policy version, feed version), and a top-left health indicator ("All good", or e.g. "1 attack stopped" → click to jump there).

**Views (left nav)**
1. **Overview**: "are we safe?" at a glance: actions today by verdict, attacks stopped, peers online, policy and feed status.
2. **Peers & roles** (new, central). The structure of the system:
   - **which peers exist** (laptop/edge, owner, online/offline, last seen, app version, feed version);
   - **which role each peer's agent runs as**;
   - **how many peers per role**, and **how roles are distributed across peers** (a chart);
   - **per role: which MCP servers it is connected to and exactly which tools** (the role × server × tool view, with limits).
   
   It answers "who is out there, as what, with access to what".
3. **Sessions**: all sessions **across all peers**, filterable by peer, role and status. The same timeline as the edge, with **fingerprints instead of text**.
4. **Policy**: profile switch (Strict / Balanced / Lenient), role × tool matrix, rules in plain words, version history, rejected-edit warning.
5. **Agents & keys**: issue and revoke role keys, expiry, which peer uses which key. This may merge into Peers & roles.
6. **Analytics**: company-wide charts: verdicts over time, blocks by reason, by role, by peer, by tool; masked data by type; latency.
7. **Threat feed**: signatures in plain words, versions, which peers are up to date, publish.
8. **Self-test**: test-suite and evaluation results in plain words, misses stated plainly.
9. **Approvals: open question, may be refactored.**
   - **Concern (Andrey):** a human approval only makes sense where the agent can wait a long time (up to an hour or more). For real-time agents, waiting for a human adds unacceptable delay, and nobody may be there.
   - **Options to decide later:**
     - (a) keep it only for long-running/async agents, with a long timeout;
     - (b) turn "approve" into "block now, notify the human, allow a one-time override for a retry";
     - (c) drop it from the UI and keep it as an API.
   - Until decided: do not invest further UI in approvals.

### Server console, revision 1 (agreed 2026-10-04)

**Decisions (Andrey):**
- **Approvals:** dropped from the UI. They stay as an API (`/admin/approvals`).
- **Policy:** read-only, plus the Strict / Balanced / Lenient profile switch.
- **Build order:** Overview, Peers & roles and Sessions first. Policy, Threat feed and Self-test follow as time allows.
- **Merged views:** Analytics merges into Overview, and Agents & keys into Peers & roles.

#### Identity: peers and keys
- **A peer is a laptop running the local edge.** It enrolls once:
  - command: `tollgate enroll <token> --owner <name> --device <name>`;
  - the token is one-time, created in the console (or with `tollgate enroll-token`), and expires after 24 h.
- **The admin sets which roles each peer may run** (in Peers & roles). A role is what the agent is, not who owns the laptop. One laptop can run several roles.
- **Agent keys are minted automatically, one per agent launch.**
  - `tollgate connect <client> --role R --peer P` (clients: `claude-code`, `cursor`, `print`) mints a key and prints or writes the client config.
  - The key is `tg_<role>_<peer>-<n>_<mac>`. The format is unchanged and `<peer>-<n>` is the key ID, so enforcement doesn't change.
  - Minting is refused if the peer is revoked or the role isn't allowed for it.
  - Nobody issues keys by hand any more. `tollgate key issue` stays for tests and dev.
- **A key is still one session.** A key per launch means clean taint per agent run.
- **Revocation:**
  - revoking a peer kills every key it minted;
  - removing a role from a peer kills that peer's keys for that role;
  - `verify()` checks the registry.
  - Legacy keys whose ID has no `-` (no peer) keep working and show as the peer **"Unenrolled"**.
- **Registry:** `audit/peers.json` (gitignored runtime):
  ```json
  {"peers": {"p3f9a": {"owner": "Andrey", "device": "andrey-thinkpad", "roles": ["role-2"], "enrolled_at": "...Z",
                        "revoked_at": null, "minted": 4}},
   "tokens": {"<sha256 of token>": {"expires_at": "...Z", "used_at": null, "peer": null}}}
  ```
  Peer IDs are `p` + 4 hex characters (no `_`, `:` or `-`).
- **Online and last seen:**
  - online means an audit event from any of the peer's keys in the last 5 minutes;
  - last seen is the newest such event.
  - There are no heartbeats, and per-peer app/feed versions are not shown (no data).
- **Demo fleet:** `tollgate seed-fleet` enrolls about 6 peers across both roles, with believable owners and devices. It then drives a mix of normal calls and the Acme attack through the **real in-process gateway** with minted keys, so every number in the console is real.

#### Console API (`/console/api/*`; loopback or the admin token, like `/admin/*`)
| Method / path | Returns |
|---|---|
| `GET status` | `{health: {level, message, ts?, session_id?, trace_id?}, admin, policy: {version, profile}, feed: {version}, app_version}`. Health counts the last hour, like the edge. "N attacks stopped" counts blocked injection/signature/data-flow events. |
| `GET overview?range=15m\|1h\|today\|all` | `{kpis: {checked, blocked, attacks, peers_online} (each {value, prev}), series, bucket_s, by_reason: [{label, count}], by_role: [{role, agent, count}], attacks: [item]}`. `item` = the edge `_item` + `peer`, `peer_label`. |
| `GET peers` | `{roles: [{role, agent, peers, servers: [{name, allowed: n, hidden: n}], actions, blocked}], peers: [{id, owner, device, roles, online, last_seen, sessions, actions, blocked, revoked}]}`, including the "Unenrolled" row when legacy keys exist. |
| `GET peers/{id}` | the peer + `sessions` (edge session shape) + `keys: [{key_id, role, first_ts, last_ts, n}]` |
| `POST peers/{id}/roles` `{roles: [...]}` | the updated peer (roles must exist in the policy) |
| `POST peers/{id}/revoke` | the updated peer |
| `POST enroll-token` | `{token, expires_at, command: "tollgate enroll <token> --owner … --device …"}` |
| `GET roles/{role}` | the edge `agent(...)` shape for that role (servers, allowed/hidden tools with limits, models, budget, content, labels) + `peers: [...]` |
| `GET sessions?peer=&role=&state=` | edge session list items + `peer`, `peer_label` |
| `GET sessions/{id}` | the edge timeline **without `text`**. Each step keeps `content_sha256` (the fingerprint). |

#### Views (revision 1 builds the first three)
**Shell:** the same as the edge.
- Left nav: Overview · Peers & roles · Sessions, then Policy · Threat feed · Self-test greyed until built.
- Top bar, 28 px: health on the left; on the right the view's controls, a status chip (Admin · hub, with policy, feed and app versions in the tooltip) and the theme toggle.
- The same CSS tokens, badges and type scale as the edge. Red only for Blocked.

1. **Overview** answers "are we safe?":
   - KPI strip: Actions checked · Blocked · Attacks stopped · Peers online (with deltas);
   - a verdict trend (grey, blocked in red);
   - **Blocked by reason | Blocked by role**, side by side as sorted bars;
   - **Attacks stopped**: a table (time, what happened, peer, agent, tool) linking into Sessions.
   - The time range sits in the top bar.
2. **Peers & roles** has two tabs, **Peers | Roles**.
   - **Peers** is master–detail:
     - left: a peers table (device + owner, roles, online dot + last seen, sessions, blocked);
     - right: the peer detail: a strip (owner, device, enrolled, last seen, keys minted), **Roles this laptop may run** (checkboxes, Save), its sessions (click → Sessions), its keys (key ID, role, active window, calls), and **Revoke this laptop** (destructive, with a confirm naming the device).
     - The top bar has an **Enroll a laptop** button: a dialog with the one-time command, a Copy button and the expiry.
   - **Roles**:
     - left: a roles table (agent name, role, peers running it, tools allowed/hidden, actions, blocked) and a "Peers per role" sorted bar;
     - right: the role detail: MCP servers → allowed tools (kind, limits) and hidden tools (the edge Setup rendering), models/budget, content checks, and the peers running it.
3. **Sessions**: master–detail across all peers.
   - Filter pills: Peer · Role · State.
   - Each list row: agent + peer, started, steps, state icons, last outcome.
   - The detail is the edge trace layout with tabs **Overview · Checks · Fingerprint**. Fingerprint shows the SHA-256, plus the line "The text stays on the peer's laptop".
   - There is no Input/Output tab: the hub never has the text.

### Server console, revision 2: Policy view (2026-10-04)

The view is read-only except for the profile switch. It answers four questions: "what is in force", "who may do what", "what do the rules say", and "what would a different profile change".

**Top bar:**
- `Profile: Balanced` as plain text;
- a **Switch profile…** button that opens a dialog. The dialog:
  - shows the three profiles side by side, but only the settings that differ, with the current profile highlighted;
  - lists, as plain sentences, what would get stricter or looser;
  - has a confirm button naming the target ("Switch to Strict").
- Switching writes `policies/<name>.yaml` over the active policy file. The old file is first saved to `audit/policy-backups/<UTC time>-<version>.yaml`. Hot reload applies it on the next call.

**Content, top to bottom:**
1. **In force:** a strip with version, profile, loaded at, and file. A line says "Live: edits to the policy file apply on the next call".
   - If the last edit was rejected, a red notice says "Edit rejected at <time>: <message>. Still enforcing <version>." This is a real problem, so red is allowed.
2. **Who may do what:** the role × tool matrix.
   - Rows are tools, grouped by MCP server: the plain name plus a mono ID, and the data-flow labels in words (outside text / private data / public destination).
   - There is one column per role (agent name + role ID).
   - Each cell is Read, Write, Hidden (muted dash) or Asks a human. Limits (SELECT only, /workspace only) are a small second line in the cell.
   - A sticky header and first column.
3. **Rules in plain words:** one card per rule family. Each has a title, one or two plain sentences, and the action.
   - Families: data-flow rule, masked data, blocked data, injection check, signatures, loop guard, budgets and models per role, approval timeout.
4. **Version history:** each version this hub has seen since it started (version, time, profile, Applied/Rejected + reason), newest first.
   - Kept in memory, and also appended to `audit/policy_history.jsonl` so it survives restarts.

**API:**
- `GET /console/api/policy` returns:
  ```
  {status: {version, profile, loaded_at, path, last_error},
   matrix: {roles: [{role, agent}],
            servers: [{name, tools: [{name, plain, write, labels: [words],
                       cells: {<role>: {access: "read"|"write"|"hidden"|"asks", limits: [..]}}}]}]},
   rules: [{id, title, sentence, action}],
   history: [{version, at, profile, ok, error}],
   profiles: {current, names: ["strict","balanced","lenient"],
              diff: [{setting, plain, values: {strict, balanced, lenient}}],
              changes: {<name>: [{plain, direction: "stricter"|"looser"}]}}}
  ```
  `current` is the active policy's `mode` when it names a profile, otherwise null. `status.modified` is true when the active file's gateway sections differ from that profile's file. The UI then says "Balanced (edited)" and warns in the switch dialog that the edits will be replaced; they are kept in the backup.
- `POST /console/api/policy/profile` with `{profile}` returns `{status, backup}`. Unknown profile → 400; not admin → 401.

These texts will be revised, and both frontends rebuilt, several times. This spec is the source of truth for each rebuild.
