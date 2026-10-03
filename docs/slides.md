# Tollgate: 10-slide outline

Numbers are from `uv run tollgate test --eval-only` and `uv run tollgate replay github` on `main` at submission 1 (2026-10-03). Status per AC: [TOLLGATE.md › Status at submission 1](../TOLLGATE.md#status-at-submission-1-2026-10-03).

## 1. Problem: agents hold the keys, and data talks back
- Agents reach real systems through MCP servers with one broad token.
- Anything the agent reads (issue, ticket, email) can carry instructions.
- Models cannot reliably tell data from commands.
- **Visual:** agent → one token → every tool on every server.

## 2. Two real incidents (2025)
- May 2025, GitHub MCP: a poisoned public issue made the agent copy private repos into a public PR.
- Jul 2025, Supabase MCP: hidden instructions in a support ticket made the agent read private tables with `service_role` and write them back into the ticket.
- In both, every individual call was allowed.
- **Visual:** two incident cards with date, source, "every call allowed".

## 3. The gap: roles alone leak
- Role-based MCP gateways exist (Obot, MS MCP Gateway, Bifrost).
- The GitHub role legitimately needs *read issue*, *read private repo*, *create PR*.
- The attack is the **sequence**, not any single call.
- **Visual:** `tollgate replay github`, taint OFF half: 3 × ALLOW, "PRs created: 1, body leaks: SALARY_ALICE=182000".

## 4. The product: per-role MCPs + Edge/Hub
- One `policy.yaml` → one virtual MCP server per role (`/mcp/role-1/`, `/mcp/role-2/`), exact tools only, role-bound keys.
- Hub: argument limits (SQL `select_only`, path globs), session taint keyed by role key, token budgets, loop cut-off, audit log.
- Content checks on every tool call and result: normalise → regex/validators → local DeBERTa classifier (today in-process; separate Edge process planned).
- Model door: OpenAI-compatible `/v1/chat/completions` → Ollama, per-role model allow-list.
- **Visual:** the README architecture diagram (Agent → Edge → Hub → MCP servers A/B/C; `/v1/chat` → Ollama).

## 5. Live demo: taint
- Same run, taint ON: steps 1–2 ALLOW, step 3 **BLOCK**.
- Reason shown: `taint.flow: session tainted by github.issues.read #12; private data from github.repo.read acme/payroll:.env`.
- PRs created: 0. Benign flow (public read → PR, no private read) stays allowed (AC6).
- **Visual:** terminal, `uv run tollgate replay github`, taint ON half.

## 6. Content pipeline, real numbers
- 1355 corpus cases (deepset, gandalf, gretel, jackhhao, jbb + own PII / secrets / obfuscation / signatures), fixed 70/30 split.
- Held-out injection recall **0.837** (target 0.85: missed), FPR **0.009**.
- Obfuscated recall 1.000 with normalisation, 0.667 without (AC9).
- Tier 1 p95 **2.91 ms**; tier 2 short-text p95 **84 ms** (target 80), long text p95 1.6 s → tier 2 sync only on short text.
- **Visual:** per-source table from the eval report; IBAN `[IBAN:…2874]` and base64 injection → `block [inj.ignore_prev, t2.injection]`.

## 7. Policy, live
- Add `files: { tools: [fs.read] }` to role-1 → next `tools/list` includes `files.fs.read`, no restart.
- Invalid YAML → rejected, old policy keeps enforcing, `/healthz` shows `last_error`, dashboard shows a red banner.
- Signatures: one line in `signatures.yaml` blocks a new input without restart (AC10).
- **Visual:** split screen: editor + `tools/list` output + dashboard banner.

## 8. Test suite and posture
- `tollgate test`: pytest (98 fast tests pass, 5 slow) + eval report.
- Overall pass rate 0.920, FPR 0.035, posture **0.899**.
- Disable `injection` → posture **0.727**: you see exactly what a control is worth.
- **Visual:** the control/weight/posture table, before and after.

## 9. Dashboard and audit
- Streamlit, read only: verdict tiles and series, top rules, tainted sessions, budget burn, latency, posture, policy version.
- Every event has its reason, no raw content (sha256 only); export JSONL / CSV.
- **Visual:** dashboard screenshot after `seed_demo.py`.

## 10. Scale and what's next
- Stateless checks per request; taint state keyed by role key; one policy file for all roles.
- Status: 11 of 16 acceptance criteria green, 5 partial (Supabase replay, AC8 recall, AC15 tier 2 latency, one-command start, deliverables).
- Next: approval flow, separate Edge process, Supabase replay, tier 3 judge, tool description pinning.
- **Visual:** AC status table (green / partial).
