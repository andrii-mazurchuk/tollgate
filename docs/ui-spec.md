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

To be specified next, in the same shell and style.
