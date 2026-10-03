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

These texts will be revised, and both frontends rebuilt, several times. This spec is the source of truth for each rebuild.
