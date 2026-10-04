# HackTribe submission (final)

Copy each field as-is into HackTribe.

**Project title:** Tollgate: an AI control layer for agents that use MCP tools

**Challenge:** HackYeah 2026, Goldman Sachs, "AI Control Layer"

**Team name:** holonic

**Members:** Andrii Mazurchuk

**Repository:** https://github.com/andrii-mazurchuk/tollgate (public, MIT)

**Presentation:** `docs/Tollgate.pdf` (10 slides; upload the PDF)

## Project description (1,393 characters)

May 2025: an AI agent read one GitHub issue and published its owner's private code. Every step it took was allowed. Nothing was hacked; the agent was obeyed. Per-tool permissions can't see this, because the danger is the sequence.

Tollgate is a local AI control layer for agents that use MCP tools and LLMs. One policy file generates a virtual MCP server per role that exposes exactly the tools that role may use. Every tool call, tool result and prompt is checked on the machine: normalisation, PII and secret validators, injection rules, an HMAC-signed signature feed and an on-device classifier. Session taint blocks the private-to-public flow once a session has read untrusted content, and names the cause. Fail-closed hooks cover built-in tools (shell, files, web) in Claude Code, Codex, Cursor, Gemini CLI and Hermes. A model door enforces model allow-lists, token budgets and loop cut-offs. Laptops enroll once, the admin sets their roles, and every agent launch gets its own revocable key. A server console shows an access map of attacks stopped, sessions as fingerprints (the text stays on the laptop), live policy edits, the threat feed and a self-test.

On a held-out 30% of 1,411 cases: injection recall 0.837 (our 0.85 target, missed) at 0.9% false positives, posture score 0.931, hub checks under 1 ms p95. 384 automated tests; judges run everything with `uv run tollgate test`.

## The problem

AI agents reach real company systems (code repositories, databases, ticketing, file stores) through MCP servers. An agent usually holds one broad credential and sees every tool on every connected server, and anything it reads (an issue, a ticket, an email) can carry hidden instructions that the model cannot reliably tell apart from commands.

In May 2025 a poisoned public GitHub issue made an agent copy private repository content into a public pull request. In July 2025 hidden instructions in a Supabase support ticket made an agent read private customer tables and post them back into the ticket. In both, every individual call was allowed; the attack was the *sequence*: read untrusted text, read private data, write somewhere public.

## The solution

- **One virtual MCP server per role**, generated from `policy.yaml`: per source server no access, read, read-write or an exact tool list; argument limits (only `SELECT`, paths under `/workspace`). Hidden tools are refused, not just hidden.
- **Session taint**: untrusted read + private read → a public write is blocked (or held for a human, in the lenient profile), with the cause named.
- **Local content checks** on every call, result and prompt: Unicode/encoding normalisation, checksum-validated PII (IBAN, PESEL, NIP, card), secrets, English and Polish injection rules, an HMAC-signed external signature feed (incl. model supply-chain IOCs), an on-device DeBERTa classifier.
- **Hook door** (`/hook`): `tollgate connect claude-code|codex|cursor|gemini|hermes` mints a key per launch and writes the agent's MCP entry and hooks; every built-in call (shell, file read/write, web fetch), each result and the user's prompt go through the same policy and taint. Fails closed. Verified live with Claude Code.
- **Model door**: OpenAI-compatible proxy with per-role model allow-list, token budgets and loop cut-off; prompts are scanned before any upstream call.
- **Identity**: laptops enroll once with a one-time token, the admin sets roles per laptop, a key is minted per agent launch, revocation kills every key a laptop minted.
- **Governance**: hot-reloaded policy with invalid edits rejected; three commented profiles; tool-description pinning against rug pulls; audit log with fingerprints, never raw text, exportable as JSONL and CSV; console accounts (Admin/Viewer), every change attributed.
- **Hardening**: per-install secrets, Host/Origin/JSON guards on every write, chunked full-text scan, ReDoS checks on signatures, unenrolled keys refused.
- **Two UIs**: `/edge` for the developer (overview, sessions trace, checks in ms per stage, events, setup) and `/console` for the security lead (access map, peers & roles, sessions, Try it, policy view/switch/edit, threat feed, self-test, users).

## Results (held-out 30%, thresholds tuned on the other 70%)

- 1,411 eval cases; held-out split `sha256(id) % 100 >= 70`; a 30-case red-team holdout scored once by hand, never re-run.
- Injection (272 held-out): recall **0.837** (target 0.85, **missed**), false-positive rate **0.009** (1 of 113 harmless).
- All checks (390 held-out): recall 0.891, FPR 0.048. Personal-data recall 0.967. Posture score 0.931.
- Normalisation ablation: obfuscated attacks caught 1.00 with normalisation, 0.67 without.
- Latency p95: hub checks under 1 ms, tier 1 2.5 ms, classifier on short text ~65–90 ms vs an 80 ms target (borderline; gated so long tool results skip it in the balanced profile).
- 377 fast + 7 slow automated tests pass. 14 of 16 acceptance criteria green; the two partial ones are the recall and classifier-latency targets above.

## How to open the project

Needs Git and [uv](https://docs.astral.sh/uv/) (it installs Python 3.13). Ollama is optional.

```bash
git clone https://github.com/andrii-mazurchuk/tollgate
cd tollgate
uv sync
uv run tollgate test                    # suite + eval report (first run downloads the ~739 MB classifier, ~5 min)
uv run tollgate seed-fleet              # demo fleet with real traffic
uv run tollgate up --scripted-model     # http://127.0.0.1:8080/console and http://127.0.0.1:8080/edge
```

The full judge guide (PowerShell and bash, ad-hoc prompts, live policy edits) is at the top of `README.md`; the 3-minute run sheet is `DEMO.md`.

## Deliverables

| Deliverable | Path | Status |
|---|---|---|
| Presentation (10 slides) | `docs/Tollgate.pdf` (source `docs/deck.md`) | done |
| Product page, judges' start | `README.md` | done |
| Spec, AC1–AC16, status | `TOLLGATE.md` | 14 green, 2 partial |
| 3-minute run sheet | `DEMO.md` | done |
| Architecture | `docs/architecture.md` | done |
| Policy with 3 profiles | `policy.yaml` (balanced); `policies/strict.yaml`, `balanced.yaml`, `lenient.yaml` | done |
| Gateway: role MCPs, taint, pinning, model door, hot reload, peers and keys | `tollgate/gateway/`, `tollgate/cli.py` | done |
| UIs: local edge and server console | `tollgate/edge.py`, `tollgate/console*.py`, `tollgate/ui/` | done |
| Demo agent (scripted hijacked model or Ollama) | `tollgate/agent/` | done |
| Content pipeline and signed signature feed | `tollgate/content/`, `signatures.yaml`, `tollgate/feed/` | done |
| Eval suite, corpus, red-team sets, latency bench | `tollgate/eval/`, `tests/corpus/`, `tollgate perf` | done |
| Automated tests | `tests/` | 377 fast + 7 slow |
| Mock MCP servers | `mocks/` (github, tickets, files) | done |
| License | `LICENSE` (MIT) | done |
