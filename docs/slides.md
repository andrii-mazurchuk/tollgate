# Tollgate: 10-slide outline

> **Superseded.** This is the early 10-slide outline. The final deck is [`docs/deck.md`](deck.md) → [`docs/Tollgate.pdf`](Tollgate.pdf); it supersedes the numbers and the dashboard references below (the server console at `/console/` replaced the Streamlit dashboard). Current status per AC: [TOLLGATE.md › Status (final, 2026-10-04)](../TOLLGATE.md#status-final-2026-10-04).

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
- Tool pinning: each tool's description + schema is hashed at startup; a changed tool (rug pull) is hidden, blocked (`pin.changed`) and alerted in red on the dashboard.
- One command: `tollgate up` (gateway + dashboard).
- **Visual:** `docs/architecture.svg`.

## 5. Live demo: a hijacked agent, stopped by taint
- `tollgate agent --scripted "check the open issues on acme/website and handle them"`: a real tool-calling loop through both doors (model `scripted-hijacked`, offline; `--model qwen3:4b` with Ollama).
- Turn 1 reads issue #12 (hidden instruction), turn 2 reads `acme/payroll/.env` → `AWS_ACCESS_KEY_ID=[SECRET] AWS_SECRET_ACCESS_KEY=[SECRET]`, turn 3's PR → **BLOCKED** `taint.flow`.
- `tollgate replay github`, taint ON: steps 1–2 ALLOW, step 3 **BLOCK**.
- Reason shown: `taint.flow: session tainted by github.issues.read #12; private data from github.repo.read acme/payroll:.env`.
- PRs created: 0. Benign flow (public read → PR, no private read) stays allowed (AC6).
- Supabase replay: `tickets.reply` blocked, `tainted by tickets.read #3; private data from tickets.query SELECT * FROM customers`; the query result is already masked (`[EMAIL]`, `[IBAN:…2874]`).
- Lenient profile: the same call is **parked for a human**: dashboard Approve/Deny or `tollgate approve <id>`, admin token separate from role keys, deny/timeout fails closed.
- **Visual:** the agent's three turns in the terminal; dashboard approval panel with the parked `tickets.reply`.

## 6. Content pipeline, real numbers
- 1361 corpus cases (deepset, gandalf, gretel, jackhhao, jbb + own PII / secrets / obfuscation / signatures), fixed 70/30 split.
- Held-out injection recall **0.837** (target 0.85: missed), FPR **0.009**.
- Obfuscated recall 1.000 with normalisation, 0.667 without (AC9).
- `tollgate perf`: Hub checks p95 **0.52 ms**, tier 1 p95 **0.40 ms** (target 5 ms: met); gateway overhead p95 5.3 ms per call.
- Tier 2 short-text p95 **84–141 ms** across runs (target 80: partial), long text p95 1.6 s → tier 2 sync only on short text.
- **Visual:** per-source table from the eval report; IBAN `[IBAN:…2874]` and base64 injection → `block [inj.ignore_prev, t2.injection]`.

## 7. Policy, live
- Add `files: { tools: [fs.read] }` to role-1 → next `tools/list` includes `files.fs.read`, no restart.
- Invalid YAML → rejected, old policy keeps enforcing, `/healthz` shows `last_error`, dashboard shows a red banner.
- Profiles: `cp policies/strict.yaml policy.yaml` (or `balanced`, `lenient`) switches live.
- Signature feed (P6): `tollgate feed publish --add …` → the gateway pulls the HMAC-signed bundle within 10 s and blocks `zz-demo-7` with `sig.demo_ioc`; a tampered bundle is rejected. Ships supply-chain IOCs (pickle opcodes, `torch.load` without `weights_only`, `trust_remote_code=True`, PALChain CVE-2023-36258/36188/36095).
- **Visual:** split screen: editor + `tools/list` output + dashboard banner.

## 8. Test suite and posture
- `tollgate test`: pytest (143 fast tests pass, 6 slow) + eval report.
- Overall pass rate 0.912, FPR 0.034, posture **0.931**.
- Disable `injection` → posture **0.718**: you see exactly what a control is worth.
- **Visual:** the control/weight/posture table, before and after.

## 9. Dashboard and audit
- Streamlit: verdict tiles and series, top rules, tainted sessions, budget burn, latency, posture, policy version, pin alerts.
- One write action: the approval panel (pending list with Approve/Deny, recent decisions); admin token from env, never typed in.
- Every event has its reason, no raw content (sha256 only); export JSONL / CSV.
- **Visual:** dashboard screenshot after `seed_demo.py`.

## 10. Scale and what's next
- Stateless checks per request; taint state keyed by role key; one policy file for all roles.
- Status: 13 of 16 acceptance criteria green, 3 partial (AC8 injection recall, AC15 tier 2 short-text latency, AC16 slide PDF). Posture 0.931.
- Next: separate Edge process, tier 3 judge, persistent pins and approvals, better recall on `deepset`.
- **Visual:** AC status table (green / partial).
