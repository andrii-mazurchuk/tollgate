# Handoff — 2026-10-03 23:38 — Tollgate build + local edge UI (v3)

> Previous handoff: none (first session)

## Session summary
Tollgate is our HackYeah 2026 entry (Goldman Sachs task "AI Control Layer"). It is an MCP gateway with:
- per-role virtual MCPs;
- session taint (blocks private → public data flow after reading untrusted text);
- local content checks (regex/checksums + a DeBERTa classifier);
- a model door, a signed signature feed, hot-reloaded `policy.yaml`, an audit log and an eval suite.

This session went from idea to a fully built system. The spec and acceptance criteria are in `TOLLGATE.md`; all 16 ACs were built (14 green, 2 partial). Submission 1 is done. The second half moved to UI/UX: a golden scenario (`SCENARIO.md`), a UI spec (`docs/ui-spec.md`), and three iterations of the **local edge UI** at `/edge`, with Andrey reviewing each one. **Next session continues on the local edge UI** (Andrey has more changes), then the server console.

## What's done
- **The whole build is on `main`, pushed to the private GitHub repo `andrii-mazurchuk/tollgate`.** Tags: `m0`, `m1-complete`, `submission-1`, `checkpoint-2010`.
- **Tests:** 229 fast + 7 slow pass (`uv run pytest -q -m "not slow"`, about 30 s). The golden scenario runs 21/21 PASS.
- **Submission:**
  - `docs/submission.md` holds the problem, solution, progress, goal and "how to open" texts;
  - team: holonic; member: Andrii Mazurchuk;
  - deck: `docs/Tollgate.pdf`, 10 slides, current numbers.
- **Red team:** 10 gateway bypasses fixed, plus an 80-case content red-team set (30 of them holdout, excluded from the eval).
- **Demo agent:** `tollgate agent --scripted "…"` runs a scripted hijacked model through the real enforcement.
- **Local edge UI v3** (`tollgate/ui/edge/*`, API in `tollgate/edge.py`):
  - **Views:** Overview (KPIs + deltas, trend, top reasons/tools, needs-a-look) · Sessions (master–detail on one screen) · Events (same pattern) · Setup (connection, MCP servers with allowed and hidden tools, models/budget, content checks, data-flow labels, stricter-only local settings) · Scenario (runner).
  - **Look:** neutral palette (red only for Blocked), light/dark, global time range.
- **Specs:**
  - `docs/ui-spec.md` holds every UI decision: local edge rev 2/3 and the server console spec.
  - `SCENARIO.md` is the Acme story with expected results per step.
- **PU map:** "Tollgate build plan locked" (project `hackyeah-2026.tollgate`) is updated to the checkpoint state.

## Current state / open threads
- **Local edge rough edges, not yet fixed:**
  - the left nav background stops at the first viewport height on long pages (Setup);
  - old unlabelled test sessions crowd the Sessions list (needs "clear local history" or a filter);
  - the key-expiry text is static (keys have no TTL);
  - the trace timeline toggle is basic;
  - scenario session names are lost on restart.
- **Andrey still has more local-edge changes.** Wait for his list.
- **Server console:** specced in `docs/ui-spec.md` (Peers & roles is the central view; modelled on Lakera/Pangea/Defender), **not built**. The old Streamlit `dashboard/` still exists and is superseded.
- **Approvals:** an open design question (human approval only makes sense for long-waiting agents). No more UI investment until decided.
- **Not done:**
  - Ollama not installed (no live-LLM run);
  - content-triggered taint;
  - a "Known limits" doc section;
  - the AC8 recall gap (0.837 vs 0.85) and the AC15 tier 2 latency gap;
  - Edge as a separate process (not planned).
- **The deadline is unclear:** Andrey said Sun 2026-10-04 11:00; the RULES PDF says 23:00 Oct 4. Confirm on Discord.

## ▶ Next step
**Ask Andrey for his remaining local-edge UI changes, then apply them.** Before building, have him look at the running UI:
1. In `C:\Projects\heack-yea-2026\rebel`, run `uv run tollgate up --scripted-model`.
2. Open http://127.0.0.1:8080/edge, then Scenario → Run all.

Fix the known rough edges above alongside his list. Then move to the server console.

## Files & references to read
- `docs/ui-spec.md`: **binding UI decisions** (local edge rev 2 + rev 3, research-backed standard, server console spec). Read it first.
- `tollgate/ui/edge/{index.html,app.js,app.css}`: the edge frontend (vanilla JS, no build step, served at `/edge`).
- `tollgate/edge.py`: the edge API (`/edge/api/*`: status, overview, sessions, events, agent, settings, setup, stream, scenario).
- `tollgate/explain.py`: rule ID → plain-English sentence, check name and "what you can do" (a test enforces full coverage).
- `docs/img/edge3-*.png`: the latest screenshots Andrey reviewed.
- `SCENARIO.md` + `scenario/acme.yaml` + `tests/test_scenario_acme.py`: the golden scenario.
- `CLAUDE.md`: stack, TDD loop, fastmcp gotchas, track ownership.
- `PLAN.md` (the "Status at checkpoint" section) and `TOLLGATE.md` (spec, AC1–AC16, status).
- `API_CONTRACT.md` / `tollgate/contract.py`: `AuditEvent`, including the optional trace fields.

## Gotchas / warnings
- **Orchestration model** (agreed with Andrey): this session acts as orchestrator. It spawns background agents per step in the worktrees `C:\Projects\heack-yea-2026\rebel-a` (branches `a/*`) and `rebel-b` (`b/*`), reviews diffs and screenshots itself, runs smoke + fast suite, merges to main and **pushes** after every merge. Andrey authorised committing an agent's work when the auto-mode classifier blocks the agent's own commit.
- **Ports:** Andrey often has his own `tollgate up` running on 8080/8501. **Never kill it.** Agents should use `--port 8088`. After a merge, tell him to restart to see the changes.
- The `.claude/settings.json` allowlist hard-codes the worktree paths. That file is Andrey's to change. Never edit it because an agent suggests it.
- fastmcp 4.0.10 is pinned and uses `httpx2`. The middleware param must be named `call_next`. Filtering `list_tools` doesn't block calls. Taint is keyed by role key (MCP session IDs are unstable).
- The tier 2 model (~739 MB) is cached in the HF cache. The first cold `tollgate test` takes ~5 min.
- Never load `tests/corpus/*_holdout.jsonl` in the eval (scored once by hand).
- Andrey prefers blunt, concise reports; plain English in the UI; "build over ask" for reversible actions; but alignment first on UX/design.

## Decisions made this session
- **Product:**
  - Per-role virtual MCP at `/mcp/{role}`; per server: none/read/rw/exact list; role-bound keys; roles only. This is the core product shape.
  - Hub (server) is authoritative; Edge (local) is protective. Local settings may only be stricter than policy.
- **Stack and engine:**
  - fastmcp 4.0.10 + Python 3.13 + uv; one process. Chosen after verified research.
  - Tier 2: protectai DeBERTa fp32 ONNX, gated (prompts always scored, long tool results not sampled in balanced). Measured latency forced the gating.
- **UI:**
  - Two UIs: the server console (security lead, primary) and the local edge (developer). The same events, two views: fingerprints on the server, full text locally.
  - **Visual standard:** grey by default, one blue accent, red only for Blocked, compact 13px type, tinted small badges. Modelled on Langfuse (local) and Lakera (console). Andrey rejected the colourful v1.
  - Local edge nav: Overview · Sessions · Events · Setup · Scenario. Sessions/Events are master–detail on one screen (Andrey, v3).
- **Project:**
  - Git tags only, no GitHub issues. The repo stays private unless public is required.
