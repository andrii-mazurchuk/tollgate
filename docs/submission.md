# HackTribe submission draft (submission 1)

**Project title:** Tollgate: an AI control layer for agents that use MCP tools

**Challenge:** HackYeah 2026, Goldman Sachs, "AI Control Layer"

**Team name:** [TEAM]

**Members:** [MEMBERS]

**Repository:** [REPO]

## Description (≤ 150 words)

Agents reach real systems through MCP servers with broad tokens, and anything they read can carry instructions. In 2025 poisoned GitHub issues and Supabase tickets made agents leak private data, and every call was allowed. Roles alone do not stop that.

Tollgate generates one MCP server per role from a single hot-reloaded `policy.yaml`, with argument limits, budgets and a loop cut-off. Every tool call and result is checked locally: normalisation, PII and secret validators, regex, a signed signature feed and an on-device DeBERTa classifier. Session taint blocks private → public flows after untrusted reads, or parks them for a human Approve/Deny. Tool descriptions are pinned against rug pulls. Every decision is audited and shown on a dashboard.

Measured: both attack replays leak without taint and are blocked with it; held-out injection recall 0.837 at 0.9% false positives across 1355 cases; Hub checks p95 0.52 ms, tier 1 p95 0.40 ms.

## Deliverables

| Deliverable | Path | Status |
|---|---|---|
| Product page, quick start, judge commands | `README.md` | done |
| Spec, AC1–AC16, status at submission 1 | `TOLLGATE.md` | done (13 green, 3 partial) |
| 3-minute demo script | `DEMO.md` | done |
| Slide outline (10 slides) | `docs/slides.md` | done; PDF missing |
| Architecture diagram | `docs/architecture.md`, `docs/architecture.svg` | done |
| Policy with 3 profiles | `policy.yaml` (balanced); `policies/strict.yaml`, `balanced.yaml`, `lenient.yaml` | done |
| Gateway: role MCPs, taint, approvals, pinning, model door, hot reload, `tollgate up` | `tollgate/gateway/`, `tollgate/cli.py` | done |
| Content pipeline (tier 1 + tier 2) and signature feed | `tollgate/content/`, `signatures.yaml`, `tollgate feed` | done |
| Eval suite, corpus, latency bench | `tollgate/eval/`, `tests/corpus/`, `tollgate perf` | done |
| Acceptance and unit tests | `tests/` | 112 fast pass, 5 slow |
| Mock MCP servers | `mocks/` (github, tickets, files) | done |
| Dashboard (incl. approval panel) | `dashboard/app.py`, `dashboard/seed_demo.py` | done |
| Research and judging analysis | `RESEARCH.md` | done |
