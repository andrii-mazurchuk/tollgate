# Tollgate: product spec and acceptance criteria

**Task:** HackYeah 2026, partner task Goldman Sachs, "AI Control Layer".
**Status:** aligned 2026-10-03 (revision 2). Built through M1 + most of M2; see [Status at submission 1](#status-at-submission-1-2026-10-03).
**Team:** 1 person, about 30 hours, full Python.
**Visual walkthrough:** [Tollgate product map](https://claude.ai/artifact/VScYMyEP8mAdALTqa3jxq6). It includes a role builder, an attack replay and a tier 1 playground. Background research is in [RESEARCH.md](RESEARCH.md).

**One-liner:** every role gets its own MCP server, generated from one policy file, that exposes exactly the tools that role may use. Every tool call is checked locally for malicious content before it leaves the machine. The server also blocks the private → public data flow once a session has read untrusted content.

---

## Status at submission 1 (2026-10-03)

Measured on `main` (commit `6c62e7f`) on the day. Fast suite: `uv run pytest -q -m "not slow"` → **98 passed, 5 deselected** (slow = real tier 2 model / full eval). Eval: `uv run tollgate test --eval-only` on **1355 corpus cases**, 30% held out (374 cases).

| AC | Status | Evidence |
|---|---|---|
| AC1 one command | partial | `tollgate serve` starts role MCPs, 3 in-process mocks, model door, `/healthz` (`test_ac07_hot_reload.py::test_ac01_app_serves_healthz_and_roles`). Dashboard is a separate `streamlit run`; Ollama is external; no separate Edge process. |
| AC2 role scoping | green | `tests/acceptance/test_ac02_role_scoping.py` |
| AC3 exact tools | green | `tests/acceptance/test_ac03_exact_tools.py` |
| AC4 argument limits | green | `tests/acceptance/test_ac04_argument_limits.py` |
| AC5 attack replay | partial | GitHub: `tollgate replay github` leaks with taint off (PR body carries `SALARY_ALICE=182000`), blocks step 3 with `taint.flow: … tainted by github.issues.read #12` with taint on; `test_ac05_taint_replay.py`. **Supabase trace: in progress, not on `main`.** |
| AC6 benign flow | green | `tests/acceptance/test_ac06_benign_flow.py` |
| AC7 hot reload | green | `test_ac07_hot_reload.py`; checked by hand: adding `files: { tools: [fs.read] }` to role-1 shows `files.fs.read` on the next `tools/list`; an invalid file sets `/healthz` `policy.last_error`, old version kept; dashboard shows the REJECTED banner |
| AC8 content | partial | Held-out injection recall **0.837** (target 0.85, **missed**), FPR **0.009** (target ≤ 0.05, met), same at all three profiles (`high` = 0.50). IBAN redacted, PESEL blocked: `test_ac08_pii.py`, `test_ac08_injection.py`. PII control held-out pass rate 0.978; a separate PII recall/FPR figure is not reported. |
| AC9 normalisation | green | eval report: obfuscated recall 1.000 vs plain 1.000 with normalisation on (0.667 with it off) |
| AC10 signatures | green | `tests/acceptance/test_ac10_signatures.py` |
| AC11 budget + loops | green | `tests/acceptance/test_ac11_budget_loops.py` (429, `loop.cutoff`) |
| AC12 model allow-list | green | `tests/acceptance/test_ac12_model_allowlist.py`; live: `qwen3:4b` for role-1 → 403 `model.denied` |
| AC13 suite | green | `tollgate test`: 1355 cases, pass rate 0.920, FPR 0.035, posture **0.899**; `content.injection: off` → posture 0.727. `test_ac13_suite_summary.py`, `test_eval_posture.py`. Per-pattern P1–P10 coverage is not audited. |
| AC14 dashboard | green | `dashboard/app.py` (verdicts, tainted sessions, budget burn, latency, posture, policy banner, JSONL/CSV export); `tests/test_dashboard_data.py` |
| AC15 latency | partial | Tier 1 p95 **2.91 ms** (met). Tier 2 short text (≤ 64 tokens) p50 38 ms, **p95 84 ms** (target 80, just missed); all texts p95 1603 ms, so tier 2 is only fit for sync on short text. Sync share reported: 0.779. Hub checks are timed per event in the audit (`latency_ms.role/taint`) but not summarised. `tollgate test --perf` not built; numbers are in the eval report. |
| AC16 deliverables | partial | README quick start: done. `docs/slides.md` outline: done, PDF not yet. `docs/architecture.md` and commented `policies/*.yaml` profiles: in progress. |

**Count:** 11 green, 5 partial, 0 not built.

**Known gaps, stated plainly:**
- Injection recall 83.7% is below the 85% target. Misses concentrate in the `deepset` source (recall 0.371 held-out).
- Tier 2 meets latency only on short text; long tool results are deferred, not blocked synchronously.
- No approval flow: `action: approve` is accepted and treated as block (the message says so).
- Supabase replay not merged at submission 1.
- No separate Edge process: content checks run in the gateway process today.

---

## 1. Goal

> Ship one local control layer with two halves:
> - a server (**Hub**) that serves per-role virtual MCPs and is the authority for access, taint, budgets and audit;
> - a client (**Edge**) that inspects every tool call and result locally with regex and a classifier.
>
> One hot-reloaded `policy.yaml` drives both. The headline is **session taint**, which stops the GitHub MCP attack where role-based access alone fails. Every control the brief requires works live, at minimum depth.

**Win condition:**
1. Clear the Phase 1 bar of ≥50% of points with margin. To do that, every deliverable in §3 exists and works when a judge runs it.
2. Reach the finalist pitch on the taint demo, which other teams' role-based gateways cannot match.

---

## 2. Problem

AI agents reach real systems through MCP servers. Two facts combine badly:

1. **Broad credentials.** An agent holds one powerful token and sees every tool on every connected server.
2. **Data acts as instructions.** Anything the agent reads (an issue, a ticket, an email) can carry hidden commands, and models cannot reliably tell the two apart.

| When | Incident | Why access control failed |
|---|---|---|
| May 2025, GitHub MCP (Invariant Labs) | A malicious public issue made the agent read private repos and leak them in a public PR. | The token covered public and private repos. Every single call was allowed. |
| Jul 2025, Supabase MCP (General Analysis) | Hidden instructions in a support ticket made the agent read private tables with `service_role` and write the data back into the ticket. | The agent ran with admin privilege. |

Sources: [heise](https://www.heise.de/en/news/Attack-via-GitHub-MCP-server-Access-to-private-data-10400040.html) · [Docker](https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/) · [General Analysis](https://generalanalysis.com/blog/supabase-mcp-blog) · [Pomerium](https://www.pomerium.com/blog/when-ai-has-root-lessons-from-the-supabase-mcp-data-leak)

**Gap we target.** Role-based MCP gateways already exist (Obot, MS MCP Gateway, Bifrost and others). Fixed roles would not have stopped the GitHub attack: the role legitimately needed *read issue*, *read private repo* and *create PR*. Only the **sequence** was the attack.

---

## 3. What the brief demands

| # | Requirement | Where Tollgate covers it |
|---|---|---|
| P1 | Authentication and access control for agents | Role keys, per-role virtual MCPs, argument limits (Hub) |
| P2 | Prompt injection | Content pipeline tiers 1 and 2 (Edge), taint (Hub) |
| P3 | Output filtering and data leakage | PII and secret redaction on results and responses (Edge) |
| P4 | Runaway loops | Loop cut-off (Hub) |
| P5 | Budgets for commercial and local models | Token budgets per role at the model door (Hub) |
| P6 | Known-attack signatures from an external feed | `signatures.yaml`, hot reloaded (Edge) |
| P7 | One central policy config, edited live by judges | `policy.yaml`, hot reloaded |
| P8 | Hybrid defence: deterministic and AI | Tier 1 regex and validators + tier 2 classifier |
| P9 | Reporting: metrics, exportable audit, dashboard, telemetry | Hub audit log, dashboard, per-tier latency |
| P10 | Self-testing suite that judges run | `tollgate test` |

**Weights:**

| Criterion | RULES.pdf | CRITERIA.pdf |
|---|---|---|
| Robustness | 30 | 30 |
| Architecture and performance | 20 | 20 |
| Reporting | 20 | 20 |
| Test suite | 20 | 15 |
| Scalability | 10 | 15 |

**Deliverables:**
- working layer
- demo agent
- architecture diagram
- documented sample policy with strictness levels and budgets
- interactive dashboard
- executable test suite
- PDF of 10 slides or fewer

**Constraints:**
- no paid APIs; everything runs locally on Ollama
- we bring our own test data
- the demo agent is not graded

---

## 4. Product

### 4.1 Two halves

| | **Hub** (server) | **Edge** (client, local) |
|---|---|---|
| Role | Authoritative. The client cannot bypass it. | Protective. Guards the user's own agent and keeps data local. |
| Owns | Per-role virtual MCPs, key → role, argument limits, credential per role, session taint, budgets, loop cut-off, model door, audit log, dashboard, test runner | Content pipeline on tool arguments, tool results, prompts and responses: normalisation, tier 1 regex and validators, signatures, tier 2 classifier, redaction |
| Sends / receives | Receives Edge verdicts (hashes, spans, rule IDs; no raw content by default) | Sends calls with the role key and its content verdict |

Rule for the split: anything the client could skip (access, taint, budgets, audit) lives on the Hub. MVP: both are modules of one Python package and run as one process, `tollgate serve`.

### 4.2 The two doors
- **Tool door, `/mcp/{role}`.** The agent's MCP config points at its role URL. This is the core of the product.
- **Model door, `/v1/chat/completions`.** An OpenAI-compatible proxy to Ollama. It handles:
  - token budgets
  - the allowed-model list
  - prompt and response scanning
  - the entry point for judges' ad-hoc prompts

### 4.3 Per-role virtual MCPs
1. The Hub connects to each source MCP server (A, B, C) and runs `tools/list`.
2. Each tool is classified as `read` or `write` from its MCP annotations (`readOnlyHint`, `destructiveHint`). The admin can override, because the server supplies those hints and they are not trusted.
3. For each role and each source server, the policy picks what the role's MCP ships:
   - `none`
   - `access: read` (all read tools)
   - `access: rw` (all tools)
   - `tools: [...]` (an exact list, for maximum control)
4. The Hub serves the merged, namespaced tool set at `/mcp/{role}`. It is built at runtime, so a policy edit changes the next `tools/list`.
5. Inside each virtual MCP, on every `tools/call`:
   - the key must be bound to this role, because the URL alone grants nothing;
   - argument limits are checked for tools that both read and write (SQL verb, path glob, recipient domain);
   - the call uses the role's own credential for that server, and the agent never sees it;
   - an optional `approval` waits for a dashboard click.

Example from the alignment session: role-1 = read on A; role-2 = read and write on A, B and C.

### 4.4 Session taint (Hub)
- Tools carry labels: `untrusted_source`, `private_data`, `public_sink`.
- A session starts clean. An `untrusted_source` call marks it **tainted** and records the cause. A `private_data` call marks it as **holding private data**.
- A `public_sink` call is `block`ed (or sent to `approve`) only when **both** flags are set. Requiring both keeps benign flows working.
- Taint never clears inside a session. **A session = one issued role key** (short TTL, e.g. 8h), tracked on the Hub. MCP session IDs are not stable in the current protocol (verified with fastmcp 4.0.10 / mcp 2.3.0), and a client-chosen header could be rotated to escape taint. Reset = issue a new key, or an admin reset from the dashboard.
- The verdict names its cause, for example: `blocked: session tainted by github.issues.read #12; private data from github.repo.read`.

### 4.5 Content pipeline (Edge)

**Scan points:**

| Scan point | Main threat | Default action (`balanced`) |
|---|---|---|
| Prompt in | direct injection | block |
| Model response out | leakage | redact |
| Tool arguments out | exfiltration, code-exec payloads | block |
| Tool results in | indirect injection, PII | redact; flag injection and rely on taint |

**Stages, in order:**
1. **Normalise:**
   - NFKC
   - strip zero-width and bidi characters
   - fold homoglyphs
   - decode base64, hex and URL runs (bounded)

   Each transform that fires is recorded, because obfuscation is itself a signal.
2. **Tier 1, deterministic:**
   - **PII:** a regex finds candidates and a checksum confirms them (IBAN mod-97, PESEL, NIP, Luhn), plus email and phone.
   - **Secrets:** gitleaks-style prefixes plus an entropy check.
   - **Injection heuristics:** EN and PL phrases, chat-template tokens, markdown-image exfiltration.
   - **Signatures:** from `signatures.yaml`.

   Spans already matched by an earlier rule are not re-reported by later rules.
3. **Tier 2, classifier:**
   - model: `protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0), ONNX on CPU
   - runtime: the repo's own `onnx/model.onnx` (fp32, 739 MB) via onnxruntime + tokenizers; no torch. Labels: 0 = SAFE, 1 = INJECTION
   - input: 256-token chunks, 32 overlap; the score is the highest chunk score
   - **measured on the demo laptop (i7-1255U):** about 50 ms p95 at 30 tokens, about 0.5 s at 256 tokens, 1–2 s at 512 tokens. Naive int8 quantisation breaks it (an injection scored 0.02), so it is not used.
   - **so tier 2 is gated.** It runs synchronously on short text (≤ 64 tokens) and on any text tier 1 escalates. Other long tool results get tier 2 asynchronously (audit only), because taint still protects the flow.
   - it catches Polish injections (1.00), but it false-positives on benign instruction-like text ("ignore the previous version's config…" scored 0.9985). Start with `high` at 0.99 and tune it on the clean corpus.
   - the policy sets `low` and `high` thresholds per profile
4. **Tier 3, judge (helper):** Qwen3Guard-Gen-0.6B via Ollama, only for scores between `low` and `high`.
5. **Fusion:** the most severe action wins (block > approve > redact > allow). Redaction replaces only the span. The verdict carries all reasons and the latency of each tier.

### 4.6 `policy.yaml` (sketch)

```yaml
mode: balanced                    # strict | balanced | lenient

servers:
  github:  { url: http://localhost:7001/mcp }
  tickets: { url: http://localhost:7002/mcp }
  files:   { command: ["python", "-m", "mocks.files"] }

roles:
  role-1:
    servers:
      github: { access: read, credential: env:GH_RO_TOKEN }
  role-2:
    servers:
      github:  { access: rw, credential: env:GH_RW_TOKEN }
      tickets: { access: rw }
      files:   { tools: [fs.list, fs.read, fs.write] }    # exact pick, no fs.delete
    constrain:
      files.fs.read:  { path: "/workspace/**" }
      tickets.reply:  { to_domain: "@acme.pl" }
    approval: [github.pr.create]
    budget:   { tokens_per_day: 500000 }
    models:   [qwen3:4b]

labels:
  github.issues.read: [untrusted_source]
  github.repo.read:   [private_data]
  github.pr.create:   [public_sink]

taint:
  block_flow: { from: private_data, to: public_sink, action: block }   # block | approve

content:
  pii:       { iban: redact, pesel: block, card: redact, email: redact }
  secrets:   block
  injection: { low: 0.50, high: 0.99, sync_max_tokens: 64 }
  signatures: signatures.yaml

loops: { max_identical_calls: 5 }
```

---

## 5. Features by importance

| Tier | Feature | Feeds |
|---|---|---|
| **Core** | 1. Per-role virtual MCPs (discovery, read/write classification, per-server none/read/rw/exact list, role keys, argument limits, credential per role) | Rob, Arch, Scale |
| **Core** | 2. Session taint and flow block (Hub) | Rob |
| **Core** | 3. Local content pipeline, tiers 1 and 2 (Edge) | Rob, Arch |
| **Core** | 4. `policy.yaml` hot reload with validation | Rob, Rep |
| **Core** | 5. Hub audit log and evaluation suite | Rep, Test |
| Required, thin | Model door with model allow-list | Rob, Rep |
| Required, thin | Token budgets per role, loop cut-off | Rob, Rep |
| Required, thin | Dashboard | Rep |
| Required, thin | `signatures.yaml` feed | Rob |
| Required, thin | Three strictness profiles | Rob |
| Helper | Approval flow (dashboard button) | Rob |
| Helper | Tier 3 judge | Rob |
| Helper | Tool description pinning | Rob |
| Helper | Admin UI role builder (until then, YAML) | Scale |
| Helper | OSV pull into the feed | Rob |
| Cut | Member and team hierarchy, SSO/OAuth, multi-tenancy, cloud, real GitHub/Supabase | — |

---

## 6. Statistics

**Runtime (per decision, stored on the Hub).** Each event records:
- `role`, `key_id`, `session`
- `door`, `source`, `tool`, `scan_point`
- `verdict` and `reasons` (rule, tier, span, cause)
- `t2_score`, `transforms`
- `latency_ms` per stage
- taint flags, `tokens`, `content_sha256`

The dashboard aggregates these into:
- verdicts over time by action and scan point
- top rules with OWASP tags
- tainted sessions and their causes
- budget burn per role
- p50/p95/p99 latency per tier, and how often calls escalate to tiers 2 and 3
- the policy version behind each verdict
- JSONL and CSV export

**Offline evaluation (`tollgate test`):**

| Corpus | Measures |
|---|---|
| deepset/prompt-injections (662) | precision, recall, F1, PR curve |
| Lakera/gandalf_ignore_instructions (777) | recall |
| jackhhao/jailbreak-classification (1,306) | benign false-positive rate |
| JailbreakBench JBB-Behaviors (200) | over-blocking on near misses |
| gretel synthetic_pii_finance (5,594) | span precision and recall per PII type |
| Own: poisoned tool results (~100) | recall on indirect injection |
| Own: clean instruction-like tool results (~100) | FPR where it hurts |
| Own: obfuscated variants (auto) | recall with and without normalisation |
| Own: Polish attacks (~50) | language gap |
| Own: attack traces (~10) | taint, roles, argument limits, budgets, loops |

**Thresholds:**
1. Split each corpus 70/30.
2. On the 70, set `high` to the lowest threshold that meets the profile's FPR target, and `low` to the point where recall flattens.
3. Report only the held-out 30.

**Posture score:**

```
posture = Σ(weight_c × enabled_c × passrate_c) / Σ weight_c
```

Disabling a control visibly drops the score.

---

## 7. Acceptance criteria (definition of done)

Each criterion is checked by a command or by an action a judge can repeat.

| # | Criterion | Check |
|---|---|---|
| AC1 | One command starts the Hub, Edge, 3 mock MCP servers and the dashboard on a clean machine with Python and Ollama | `tollgate serve` → all endpoints healthy |
| AC2 | `/mcp/role-1` lists only role-1's tools. Calling any other tool, or using role-1's key on `/mcp/role-2`, is rejected. | test cases + manual curl |
| AC3 | An exact tool list in the policy (`tools: [...]`) is honoured: excluded tools are absent from `tools/list` and rejected on call | test case |
| AC4 | Argument limits: `SELECT` passes and `DELETE` is blocked on the same tool; a path outside the glob is blocked | test cases |
| AC5 | Replaying the GitHub attack trace: it **leaks** with taint disabled and is **blocked with the named cause** with taint enabled. Same for the Supabase trace. | `tollgate replay github` |
| AC6 | Benign flow: read a public issue, then open a PR with no private read → **allowed** | test case |
| AC7 | Hot reload: a policy edit (role tools, action, threshold) takes effect on the next call within 2 s with no restart. An invalid file is rejected, the old policy is kept, and the error is visible on the dashboard. | manual edit + test |
| AC8 | Content, `balanced` held-out: injection recall ≥ 85%, benign FPR ≤ 5%. Validated PII recall ≥ 95%, FPR ≤ 1%. IBAN redacted, PESEL blocked. | `tollgate test` report |
| AC9 | Normalisation: recall on obfuscated variants is within 10 points of recall on the plain originals | `tollgate test` report |
| AC10 | A new line in `signatures.yaml` blocks a previously allowed input without a restart | test case |
| AC11 | Budget: a role exceeding `tokens_per_day` gets a 429 from the model door. N identical tool calls trigger the loop cut-off. | test cases |
| AC12 | A model not in the role's `models` list is rejected | test case |
| AC13 | `tollgate test` runs ≥ 500 cases (positive and negative, every P1–P10 covered) and prints pass rate, FPR and posture score. Disabling a control lowers the posture score. | command |
| AC14 | Dashboard shows live verdicts, tainted sessions, budget burn, per-tier latency, posture score. Audit exports to JSONL and CSV. | manual |
| AC15 | Latency at p95: Hub checks < 5 ms; tier 1 < 5 ms; tier 2 < 80 ms on short text (≤ 64 tokens); share of calls reaching tier 2 synchronously reported | `tollgate test --perf` |
| AC16 | Deliverables: architecture diagram, documented `policy.yaml` with 3 profiles and budgets, 10-slide PDF, README quick start | files exist |

Targets in AC8, AC9 and AC15 are proposals. They stand until the first held-out measurement, and then get adjusted with justification.

---

## 8. Build order (superseded: original 30h solo plan; the live 15h two-track plan is the PU map "Tollgate build plan locked", soon PLAN.md)

| # | Block | h | Unlocks |
|---|---|---|---|
| 1 | Spike: fastmcp proxy, one mock server, list/call pass-through | 3 | everything |
| 2 | Mock MCP servers: github, tickets (SQLite), files | 2 | AC2–AC6 |
| 3 | `policy.yaml` loader, validation, hot reload | 2 | AC7 |
| 4 | Per-role virtual MCPs, keys, access/exact list, argument limits, credentials | 4 | AC2–AC4 |
| 5 | Taint labels and flow block, attack replay traces | 2 | AC5–AC6 |
| 6 | Audit log (JSONL / SQLite) | 1 | AC14 |
| 7 | Tier 1: normalisation, PII validators, secrets, injection, signatures | 3 | AC8–AC10 |
| 8 | Tier 2 classifier (ONNX) | 2 | AC8 |
| 9 | Model door, budgets, model allow-list, loop cut-off | 3 | AC11–AC12 |
| 10 | Eval suite: corpora, own cases, report, posture score | 4 | AC13, AC15 |
| 11 | Dashboard (Streamlit) | 3 | AC14 |
| 12 | Diagram, slides, README | 1 | AC16 |

Helpers start only after AC1–AC16 pass. Their order is: approval → tier 3 → pinning → admin UI.

Stack:
- Python 3.12
- fastmcp 4.0.10 (pinned; on mcp 2.3.0)
- FastAPI and httpx
- PyYAML and watchdog
- ONNX Runtime and transformers
- SQLite
- Streamlit
- pytest
- Ollama

---

## 9. Demo (3 min)

1. **Roles only:** role-2 runs "check open issues". Poisoned issue #12 leads to a private repo read, then a public PR. **Leak.**
2. **Tollgate:** the same run. The PR is **blocked**: *"session tainted by github.issues.read #12"*.
3. **Role scoping:** role-1's `tools/list` shows only A's read tools. A judge adds `fs.read` to role-1 in the YAML, and the next `tools/list` includes it.
4. **Content:** a ticket containing an IBAN comes back redacted. A base64-hidden injection is decoded and flagged.
5. **Live policy:** the judge switches `action: block` to `approve` (or lowers a threshold). The next call follows the new rule.
6. **Suite:** `tollgate test` shows pass rate, FPR and posture. The judge disables `injection` and the posture score drops.

---

## 10. Risks

| Risk | Sev. | Mitigation |
|---|---|---|
| MCP protocol details (streamable HTTP, stdio, sessions) eat time | High | Spike in block 1. Keep mocks tiny. Use the SDK's client and server classes. |
| Taint blocks benign work | High | Block only when tainted **and** holding private data. AC6 measures it. Allow-list trusted sources. |
| Judges' ad-hoc attacks bypass the content tiers | High | Normalise first, Polish rules, classifier on chunks. Taint still holds if detection misses. |
| Classifier false positives on instruction-like tool results | Medium | Own clean corpus, thresholds per profile, `flag` instead of `block` on results in `balanced`. |
| Seen as "just another MCP gateway" | Medium | Open the demo with the roles-only leak. |
| Local models slow on demo hardware | Medium | ONNX tier 2. Tier 3 optional. |
| Licence traps | Low | Avoid LLM Guard (archived) and Phoenix (ELv2). |

---

## 11. Decision log

| Date | Decision |
|---|---|
| 2026-10-03 | Tollgate chosen as the #1 project |
| 2026-10-03 | One virtual MCP per role at `/mcp/{role}`, generated at runtime from policy. Per server: none, read, rw, or an exact tool list. |
| 2026-10-03 | Role-bound keys; the URL alone grants nothing |
| 2026-10-03 | Roles only; no member or team hierarchy |
| 2026-10-03 | Hub (server) is authoritative: access, argument limits, taint, budgets, audit. Edge (client) is protective: local content checks. |
| 2026-10-03 | Full Python, one process for the MVP, team of one |
| 2026-10-03 | Content targets per AC8 until measured |
| 2026-10-03 | Stack: fastmcp 4.0.10 (pinned): `create_proxy` + `mount(tool_names=…)`, `Middleware.on_list_tools/on_call_tool`, one Starlette app mounting `/mcp/{role}`, in-memory `Client` for tests |
| 2026-10-03 | Tier 2: protectai fp32 ONNX (no torch), 256-token chunks, gated (short text + tier 1 escalations sync, the rest async), `high` 0.99. Llama-Prompt-Guard-2 rejected (gated, missed Polish). |
| 2026-10-03 | Taint keyed by role key, not MCP session ID (not stable in the current protocol) |
| 2026-10-03 | Two parallel tracks: A Gateway, B Content and evidence; git tags only; submission 1 = docs + code snapshot |

**Open:**
- Confirm the start time on Discord (RULES says "11:00 PM Oct 3", probably a typo).
- Exact Ollama chat model for the demo agent (e.g. `qwen3:4b`). Decide in the block 1 spike.
