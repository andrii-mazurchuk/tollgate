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
