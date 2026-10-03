# HackTribe submission draft (submission 1)

**Project title:** Tollgate: an AI control layer for agents that use MCP tools

**Challenge:** HackYeah 2026, Goldman Sachs, "AI Control Layer"

**Team name:** [TEAM]

**Members:** [MEMBER 1], [MEMBER 2]

**Repository:** [REPO URL]

## Description (≤ 150 words)

Agents reach real systems through MCP servers with broad tokens, and anything they read can carry instructions. In 2025 a poisoned GitHub issue made an agent copy private repositories into a public PR, and every call was allowed. Roles alone do not stop that.

Tollgate generates one MCP server per role from a single hot-reloaded `policy.yaml`, exposing only that role's tools, with argument limits, token budgets and a loop cut-off. Every tool call and result is checked locally: normalisation, PII and secret validators, regex and an on-device DeBERTa classifier. Session taint blocks private → public flows once a session has read untrusted content, and names the cause. Every decision is audited.

Measured: the GitHub attack replay leaks without taint and is blocked with it; held-out injection recall 0.837 at 0.9% false positives across 1355 cases; tier 1 p95 2.9 ms.

## Deliverables

| Deliverable | Path | Status |
|---|---|---|
| Product page, quick start, judge commands | `README.md` | done |
| Spec, AC1–AC16, status at submission 1 | `TOLLGATE.md` | done |
| 3-minute demo script | `DEMO.md` | done |
| Slide outline (10 slides) | `docs/slides.md` | done; PDF planned |
| Architecture diagram | `docs/architecture.md` | in progress |
| Policy with 3 profiles | `policy.yaml` (balanced); `policies/*.yaml` | profiles in progress |
| Gateway: role MCPs, taint, model door, hot reload | `tollgate/gateway/`, `tollgate/cli.py` | done |
| Content pipeline (tier 1 + tier 2) | `tollgate/content/`, `signatures.yaml` | done |
| Eval suite and corpus | `tollgate/eval/`, `tests/corpus/` | done |
| Acceptance and unit tests | `tests/` | 98 fast pass, 5 slow |
| Mock MCP servers | `mocks/` (github, tickets, files) | done |
| Dashboard | `dashboard/app.py`, `dashboard/seed_demo.py` | done |
| Research and judging analysis | `RESEARCH.md` | done |
