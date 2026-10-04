# Tollgate: presentation brief (for Claude Design)

**Format:** 16:9, 10 slides, a 3-minute talk with a live demo in the middle. Andrey tells the story; slides carry keywords only.
**Rules:** text ≥ 26 px, AA contrast, one idea per slide, no paragraphs, no underlines.
**Brand:**
- **Logo:** castle-gate logo, `docs/brand/tollgate-logo.svg`.
- **Colors:** ink `#0f172a`, muted `#475569`, blue `#1d4ed8` (Tollgate / allowed), red `#b91c1c` (attack / blocked), soft background `#f1f5f9`.

**Judging criteria** (GS "AI Control Layer"): put the matching one as a small tag in the top-right corner of its slide.
- Robustness 30%
- Architecture 20%
- Security reporting 20%
- Self-test suite 20%
- Performance 20%
- Implementability 10%
- Security / scalability 10%

---

## 1. Title
- **Tollgate**, with the logo large.
- Subtitle: *An AI control layer for agents that use MCP tools.*
- Team **holonic** · Andrii Mazurchuk · HackYeah 2026 · Goldman Sachs "AI Control Layer".
- Small: `github.com/andrii-mazurchuk/tollgate` · public · MIT.

## 2. Problem: one real incident
- Kicker: *May 2025 · GitHub MCP · Claude*.
- Headline: **One public issue. Private life, published.**
- A 3-step chain:
  1. Read an issue in a public repo ✓ allowed
  2. Read the owner's private repos ✓ allowed
  3. Open a public pull request ✓ allowed
- Below the chain, a red "leaked PR" card with the redacted lines: private repo "J██████ Star", moving to "South Am█████", salary "$███,███".
- Punchline (spoken): *Nothing was hacked. The agent obeyed.*

## 3. Problem: it keeps happening, and why
**Top: a grid of 6 incident tiles** (date · product · one line):

| Date | Product | Line | Note |
|---|---|---|---|
| May 2025 | GitHub MCP | private repos leaked into a public PR | |
| Jul 2025 | Supabase MCP | support ticket pulled out secret tokens | |
| Jul 2025 | Replit Agent | production DB deleted during a code freeze | |
| Jul 2025 | Amazon Q (VS Code) | shipped a prompt to wipe disk and cloud | |
| Jul 2025 | Gemini CLI | README silently sent credentials away | |
| Sep 2025 | postmark-mcp | every email BCC'd to an attacker | 1,643 installs |

Sources are in the comment at the end of `docs/deck.md`.

**Bottom: the gap**, as one equation:
- **untrusted text** + **private data** + **public write** = **leak**.
- Caption: *Permissions check calls one by one. Nobody watches the session.*

## 4. Solution overview
- Headline: **Every agent call passes one gate.**
- Diagram: **Agents** (Claude Code, Codex, Cursor, Gemini CLI, any MCP client) → **Tollgate** (blue box) → **Tools & models** (GitHub, databases, files, LLMs).
- Three pillars, as icons with one line each:
  1. **Tools per role.** One policy file generates one MCP server per role; hidden tools are refused.
  2. **Content checked on the laptop.** Injection, PII and secrets checks, plus an on-device classifier.
  3. **Data-flow guard (session taint).** After untrusted text and private data, a public write is blocked, and the block names the reason.
- **Screenshot:** `docs/img/deck-blocked-steps.png` (step 3 "Blocked", with the quote *"The session read outsiders' text and holds private data, so sending data out could leak it."*).

## 5. Solution: what the security team sees (screenshots / mockups)
- Headline: **Every laptop. Every agent. Every block.**
- **Hero:** `docs/img/console-access-map.png` (live access map: laptops → agents → servers, blocked flows in red).
- Thumbnails, if space allows:
  - `docs/img/hook-console-session.png`: a session's steps; the server keeps only a fingerprint.
  - `docs/img/console-try-it.png`: paste any text and see the verdict.
  - `docs/img/hook-console-policy.png`: who may do what, built-in tools included.
- Caption: **Text never leaves the laptop.** The server keeps the decision plus a fingerprint.

## 6. Tech stack and architecture
**Left: the architecture diagram.** Redraw `docs/img/arch-simple.svg` cleanly.
- The agent talks to Tollgate through **three doors**:
  - **MCP door:** a virtual MCP server per role.
  - **Hook door:** the agent's built-in tools (shell, files, web) via hooks.
  - **Model door:** an OpenAI-compatible proxy with a model allow-list, token budgets and a loop cut-off.
- A **local content pipeline** runs on every call: normalise → validators → signatures → classifier.
- **Session taint** sits in front of the doors.
- To the right of Tollgate: the upstream MCP servers and LLMs.
- Underneath:
  - the **server console** (admins);
  - a **signed threat feed**, HMAC-signed and pulled by hubs.

**Right: the stack, as chips:**
- Python 3.13 · uv · FastMCP 4 · Starlette / uvicorn
- ONNX Runtime with an on-device DeBERTa injection classifier
- HMAC-SHA256-signed signature feed · YAML policy with hot reload
- Plain-JS UIs (console, edge) · pytest (408 tests)

**Footer:** fails closed · per-install secrets · one key per agent launch · revocation per laptop.

## 7. Demo flow (live; a recorded video as backup)
- Headline: **Install in one line. Then just work.**
- 4 steps, left to right:
  1. **Install:** `irm …/install.ps1 | iex` (or `uv tool install agent-tollgate`), ~30 s, no admin rights.
  2. **Enroll:** the laptop joins once; the admin sets its roles.
  3. **Connect:** `tollgate connect claude-code`.
  4. **Work:** every call is checked; the developer sees only the blocks.
- The live beat is a real, unmodified Claude Code session:
  - `curl` ✓
  - read `payroll.txt` ✓
  - `git push` **blocked**, with the reason
  - the same block shows on the console map seconds later
  - revoke the laptop → its key is dead immediately
- Agent badges: ✓ Claude Code ✓ Codex ✓ Cursor ✓ Gemini CLI ✓ Hermes ✓ any MCP server.
- **Video:** record the `DEMO.md` run (screen + voice, ≤ 90 s) as a fallback and for the submission. Put a QR code or link on this slide if it gets uploaded.

## 8. Proof and performance (self-test)
- Headline: **Proof: `uv run tollgate test`**.
- 6 big numbers:

| Number | Meaning |
|---|---|
| **408** | automated tests (397 fast + 11 slow) |
| **1,411** | eval cases, 30% held out |
| **< 1 ms** | hub checks, p95 |
| **0.967** | PII recall |
| **0.009** | injection false-positive rate |
| **0.837** | injection recall, shown greyed out, labelled **"missed target 0.85"** (honesty earns trust) |

- Small line: all checks FPR 0.048 · posture 0.931 · tier 1 p95 ~2.5 ms · 14 of 16 acceptance criteria green.

## 9. Impact and future plans
**Left, "Why it holds":**
- fails closed (hub down or a bad key = denied)
- per-install secrets
- signed threat feed
- one key per agent launch
- console accounts, every change attributed
- company-wide rollout via managed settings

**Middle, "Who buys":**
- security teams rolling out coding agents
- banks, fintech and other regulated industries
- anyone letting agents near private data

**Right, "Next":**
- edge/hub split + policy sync
- model door v2 (Anthropic API, streaming)
- budgets in money
- memory controls
- SSO

## 10. Try it / links (instead of a live preview)
- Headline: **Try it in 5 minutes.**
- Code box:
  - `irm https://raw.githubusercontent.com/andrii-mazurchuk/tollgate/main/install.ps1 | iex`
  - `uv tool install agent-tollgate` (PyPI)
  - `tollgate up` → open `/console`
- **QR codes:** the GitHub repo · the PyPI page `pypi.org/project/agent-tollgate` · the video (if recorded).
- **Live preview: don't host one.** Tollgate is local-first and its console is an admin surface; a public instance would be an attack target. Say so: *"It runs on your laptop in 30 seconds. That is the live preview."*
- Logo again, and "holonic · public · MIT".

---

## Must-haves vs nice-to-haves
- **Must:** 1, 2, 4, 5, 6, 7, 9, 10. Together they cover every required section.
- **Nice:**
  - **3:** the incident grid. It can be folded into 2 as a single line.
  - **8:** proof. The self-test is worth 20% of the score, so keep it if there is time.
- **Video:** a backup, not a blocker. Live first.
- **Timing:** about 15 s per slide, except 7 (≈ 60 s live) and 5 (≈ 20 s).

## Source files
- **Current deck:** `docs/deck.md` (Marp) and `docs/Tollgate.pdf`. They already hold this content, so reuse their wording.
- **Run sheet:** `DEMO.md`.
- **Submission texts:** `docs/submission.md`.
- **Images:** `docs/img/` and `docs/brand/`.
