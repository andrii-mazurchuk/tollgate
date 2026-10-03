# HackTribe submission (submission 1)

**Project title:** Tollgate: an AI control layer for agents that use MCP tools

**Challenge:** HackYeah 2026, Goldman Sachs, "AI Control Layer"

**Team name:** holonic

**Members:** Andrii Mazurchuk

**Repository:** https://github.com/andrii-mazurchuk/tollgate (private; access on request)

**Presentation:** `docs/Tollgate.pdf` (10 slides)

## The problem

AI agents now reach real company systems (code repositories, databases, ticketing, file stores) through MCP servers. Two facts make this dangerous. First, an agent usually holds one broad credential and can see every tool on every connected server. Second, anything the agent reads (an issue, a ticket, an email, a web page) can carry hidden instructions, and language models cannot reliably tell data from commands.

This is not theoretical. In May 2025 a poisoned public GitHub issue made a developer's agent copy private repositories into a public pull request. In July 2025 hidden instructions in a Supabase support ticket made an agent read private customer tables and post them back into the ticket. In both cases every individual call was allowed. Role-based access control alone would not have stopped either attack, because the attack was the *sequence*: read untrusted text, then read private data, then write to a public place.

## The solution

Tollgate is a local AI control layer that sits between agents and everything they use.

- **One virtual MCP server per role.** A role is generated from a single `policy.yaml`, and the admin chooses, per source server, no access, read, read-write, or an exact list of tools. Role keys are signed. Argument limits restrict tool inputs: only `SELECT` queries, paths under `/workspace`, recipients in the company domain.
- **Session taint.** Once a session reads untrusted content and then private data, any write to a public destination is blocked, or held until a human approves or denies it. The verdict names the cause.
- **Hybrid content inspection on every call and result, run locally.** Unicode and encoding normalisation, then PII validators with checksums (IBAN, PESEL, NIP, card), then secret detection, then injection rules in English and Polish, then an HMAC-signed external signature feed (including model supply-chain attacks such as pickle, `torch.load` and LangChain CVE-2023-36258), then an on-device DeBERTa injection classifier.
- **A model door.** An OpenAI-compatible proxy to local Ollama, with a per-role model allow-list, token budgets and a runaway-loop cut-off.
- **Governance:**
  - the policy hot-reloads, and an invalid edit is rejected while the old policy keeps enforcing;
  - three strictness profiles;
  - tool-description pinning against rug-pull servers;
  - an audit log of every decision;
  - a live dashboard;
  - a self-testing suite judges can run with one command.

## What's done so far

The working system runs locally, and all required deliverables exist: the control layer, a demo agent, an architecture diagram, documented policy profiles, a dashboard, an executable test suite and a 10-slide deck.

- **Both real attacks are reproduced and stopped.** The GitHub and Supabase incidents leak data with roles only and are blocked by session taint, with the cause named. A tool-calling demo agent shows the same result through both of Tollgate's interfaces.
- **Measured on 1,411 evaluation cases, including 50 hand-written red-team cases (30% held out):**
  - injection recall 0.837 at a 0.9% false-positive rate;
  - security posture score 0.931;
  - normalisation lifts recall on obfuscated attacks from 0.67 to 1.00.
- **Latency:**
  - policy, role and taint checks under 1 ms p95;
  - regex tier under 1 ms p95;
  - classifier about 84 ms on short text.
- **Red-teamed:**
  - 10 gateway bypasses found and fixed (tool-name aliases, path traversal, key-format ambiguity, open admin endpoints, malicious feed regexes);
  - 80 hand-written adversarial content cases, 30 of them held back and scored once;
  - a regex denial-of-service case fixed.
- **207 automated tests pass. 14 of 16 acceptance criteria are met.** The open two are stated plainly: injection recall is 1.3 points under our 85% target, and classifier latency is 4 ms over our 80 ms target.

## The goal

Make it safe for a company to give AI agents real access. Every agent should get exactly the tools its role needs, every call should be checked, and once an agent has read anything from outside, private data should not be able to leave, even when the model itself has been fooled. Security teams should be able to change the rules in one file and watch the effect live.

## How to open the project

**Needs:** Git, and [uv](https://docs.astral.sh/uv/) (it installs Python 3.13 itself). Ollama is optional and only needed for a live LLM. The repo is private, so whoever runs it needs access granted on GitHub.

```bash
git clone https://github.com/andrii-mazurchuk/tollgate
cd tollgate
uv sync

# 1. See the attack get stopped (offline, about 10 s)
uv run tollgate agent --scripted "check the open issues on acme/website and handle them"
uv run tollgate replay github
uv run tollgate replay supabase

# 2. Gateway + dashboard
uv run python dashboard/seed_demo.py      # fills the dashboard with real events
uv run tollgate up                         # gateway http://127.0.0.1:8080, dashboard http://localhost:8501
uv run tollgate key issue --role role-1    # key + MCP URL for any MCP client

# 3. The test suite (first run downloads the ~739 MB classifier, about 5–6 min; later about 30 s)
uv run tollgate test
```

To edit live, change `policy.yaml` while `tollgate up` is running; the next call follows the new rules. To switch strictness, run `cp policies/strict.yaml policy.yaml`.

The full judge guide is in `README.md`, and the 3-minute demo script is in `DEMO.md`.

## Deliverables

| Deliverable | Path | Status |
|---|---|---|
| Presentation (10 slides) | `docs/Tollgate.pdf` (source `docs/deck.md`) | done |
| Product page, quick start, judge commands | `README.md` | done |
| Spec, AC1–AC16, status | `TOLLGATE.md` | 14 green, 2 partial |
| 3-minute demo script | `DEMO.md` | done |
| Architecture diagram | `docs/architecture.md`, `docs/img/arch-simple.svg` | done |
| Policy with 3 profiles | `policy.yaml` (balanced); `policies/strict.yaml`, `balanced.yaml`, `lenient.yaml` | done |
| Gateway: role MCPs, taint, approvals, pinning, model door, hot reload, `tollgate up` | `tollgate/gateway/`, `tollgate/cli.py` | done |
| Demo agent (scripted hijacked model, or live Ollama) | `tollgate/agent/` | done |
| Content pipeline (tier 1 + tier 2) and signed signature feed | `tollgate/content/`, `signatures.yaml`, `tollgate/feed/` | done |
| Eval suite, corpus, red-team sets, latency bench | `tollgate/eval/`, `tests/corpus/`, `tollgate perf` | done |
| Automated tests | `tests/` | 207 fast pass, +6 slow |
| Mock MCP servers | `mocks/` (github, tickets, files) | done |
| Dashboard (incl. approval panel) | `dashboard/app.py`, `dashboard/seed_demo.py` | done |
| Snapshots | `docs/img/*.png` | done |
| Research and judging analysis | `RESEARCH.md` | done |
