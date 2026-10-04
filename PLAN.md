# PLAN.md

## Status (final, 2026-10-04; first written at checkpoint 20:21, tag `checkpoint-2010`)

**The whole 15h schedule below is built.** M0 was done at 16:53, M1 at 17:25, the M2 scope at about 19:00, and red-teaming at 19:30. `submission-1` is tagged, and the repo is public at https://github.com/andrii-mazurchuk/tollgate (MIT). Since then: local edge UI `/edge`, server console `/console` (access map, peers, key per launch, revocation, sessions, Try it, policy view/switch/edit, threat feed, self-test, JSONL/CSV export), console accounts (Admin/Viewer), the hook door (`/hook`, `tollgate hook`, `tollgate connect` for Claude Code, Codex, Cursor, Gemini CLI, Hermes), hardening (per-install secrets, fail-closed hooks, Host/Origin guards), `seed-fleet`.

**Tests:**
- 377 fast tests pass, plus 7 slow ones (`uv run pytest -q -m "not slow"`).
- All 53 acceptance tests pass (48 fast + 5 slow).
- AC1–AC16: 14 green, 2 partial. AC8 injection recall is 0.837 against 0.85 (FPR 0.009). AC15 tier 2 short-text p95 is ~65–90 ms against 80 ms (borderline).

**Done since the first status:** "Known limits" section (README); admin UI (console Policy → Edit access, Peers & roles, Users); MCP-door injection taint (a flagged tool result taints the session).

**Open (after the hackathon):**
1. Target misses (AC8 recall, AC15 classifier latency).
2. Edge/hub split (`--role edge|hub`) with policy sync from the hub.
3. Model door v2: Anthropic Messages / OpenAI Responses, streaming.
4. Budgets in money, memory controls, SSO for the console.
5. Tier 3 judge, OSV auto-sync.

**TDD loop unchanged:**
1. Write a failing test.
2. Make it green.
3. Run `scripts/smoke.sh` + `pytest -m "not slow"`.
4. Merge to main and push.

The schedule below is the historical plan.

15h build, one operator (Andrey) driving **two Claude sessions**, one per track. The spec and AC1–AC16 are in `TOLLGATE.md`.
The planning record is the PU map "Tollgate build plan locked". Progress is tracked with **git tags only**.

## Clock (Europe/Warsaw)

| Hour | Wall clock | Checkpoint |
|---|---|---|
| h0 | Sat 16:40 | Start |
| h1 | 17:40 | **M0 gate**: proxy pass-through green, tag `m0` |
| h5.3 | 22:00 | Track B switches to the docs snapshot |
| h6.3 | **23:00** | **Submission 1**: docs + idea + code snapshot, tag `submission-1`. The hackathon rules say 11:00 PM Oct 3; confirm the exact time. |
| h7 | 23:40 | M2 starts |
| h15 | Sun 07:40 | Feature work ends |
| — | 08:30 | **Hard freeze.** Only fixes and rehearsal after this. |
| — | 10:00 | Submit final, tag `final` |
| — | **11:00** | Deadline. Do not submit in the last hour. |

There are 3h20 of buffer between h15 and the deadline. Overruns eat buffer, never the freeze.

## Tracks

| | Track A: Gateway | Track B: Content and evidence |
|---|---|---|
| Owns | `tollgate/gateway/`, `mocks/`, `tollgate/cli.py` | `tollgate/content/`, `tollgate/eval/`, `tests/corpus/`, `signatures.yaml` (the Streamlit `dashboard/` was removed) |
| Session | Claude session 1, worktree `rebel/` | Claude session 2, worktree `rebel-b/` |
| Branches | `a/<feature>` | `b/<feature>` |

Shared files are `tollgate/contract.py`, `API_CONTRACT.md`, `PLAN.md`, `policy.yaml` (per the section ownership in the contract) and `tests/test_smoke.py`. Edit them only on `main`, and in small commits.

## Schedule

| Hours | Wall clock | Track A | Track B |
|---|---|---|---|
| 0–1 | 16:40–17:40 | M0 spike: mock github MCP + fastmcp proxy (AC: m0 test) | Tier 1 start: normalise, PII validators |
| 1–2.5 | –19:10 | Policy loader, `/mcp/{role}`, role keys, exact tools, argument limits (AC2–AC4) | PII + secrets done (AC8 PII part) |
| 2.5–3.5 | –20:10 | Taint keyed by role key, GitHub replay (AC5, AC6) | Injection rules, `signatures.yaml` hot reload (AC10) |
| 3.5–5 | –21:40 | Wire `scan()` on args/results, audit JSONL writer | Corpora download + own cases, eval runner. **Pre-fetch the tier 2 model now** (739 MB) |
| 5–6.3 | –23:00 | Hot reload + invalid-file guard (AC7); merge; smoke | **Docs snapshot** (README, TOLLGATE, description); `tollgate test` summary (AC13 small) |
| 7–8.5 | 23:40–01:10 | Model door: Ollama proxy, model allow-list (AC12) | Tier 2 classifier (gated, per TOLLGATE §4.5; tested sketch in the PU ticket), thresholds, held-out metrics (AC8, AC9). Cache scores in eval: 500 cases × up to 0.5 s. |
| 8.5–10 | –02:40 | Token budgets, loop cut-off (AC11) | Posture score; suite grows live (AC13) |
| 10–12 | –04:40 | Supabase trace, perf (AC15), one-command `tollgate serve` (AC1) | Dashboard over audit JSONL (AC14) |
| 12–13 | –05:40 | Commented `policy.yaml` with 3 profiles, architecture diagram | 10 slides, demo script |
| 13–15 | –07:40 | Joint: integrate, rehearse, buffer | Joint |

## AC → test → owner

| AC | Test | Owner | Milestone |
|---|---|---|---|
| M0 | `tests/acceptance/test_m0_proxy_passthrough.py` | A | M0 |
| AC2 | `test_ac02_role_scoping.py` | A | M1 |
| AC3 | `test_ac03_exact_tools.py` | A | M1 |
| AC4 | `test_ac04_argument_limits.py` | A | M1 |
| AC5 | `test_ac05_taint_replay.py` | A | M1 |
| AC6 | `test_ac06_benign_flow.py` | A | M1 |
| AC7 | `test_ac07_hot_reload.py` | A | M1 |
| AC8 (PII) | `test_ac08_pii.py` | B | M1 |
| AC10 | `test_ac10_signatures.py` | B | M1 |
| AC13 (small) | `test_ac13_suite_summary.py` | B | M1 |
| AC1, AC11, AC12, AC15 | add at M2 | A | M2 |
| AC8 (full), AC9, AC14 | add at M2 | B | M2 |
| AC16 | checklist at the final gate | both | M2 |

## TDD loop (every step)
1. The step's AC test exists and is red (strict `xfail`). If the AC has no test yet, write it first.
2. Build until it passes, then **remove the `xfail` marker**. Strict mode fails the suite if a passing test keeps it.
3. `bash scripts/smoke.sh` and `uv run pytest -q` both pass.
4. Merge to `main` and push. Small commits. `main` is never broken.

The test suite stays large and grows with the data: size it live, don't fix it in advance.

## Cut order if M1 slips (apply in this order)
1. AC4 argument limits → M2.
2. AC10 signatures → M2.
3. AC13 summary → M2. Submission 1 only needs docs + snapshot, so never trade the docs for a feature.

## Later (only if M2 finishes early, in this order)
1. Approval flow (built: API/CLI).
2. Tier 3 judge.
3. Tool description pinning.
4. Admin UI role builder.
5. OSV feed pull.

## Gates
- **M0 (17:40):** m0 test green, tag `m0`. **If it is not green by 18:10, stop and re-plan.**
- **Submission 1 (23:00):** docs final, smoke green on `main`, tag `submission-1`, submit.
- **Final (10:00):** AC1–AC16 green or each gap consciously accepted and written here, rehearsed twice from a cold start, tag `final`, submit.
