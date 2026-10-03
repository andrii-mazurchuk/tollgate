# Tollgate

**An AI control layer for agents that use MCP tools.** HackYeah 2026, Goldman Sachs task "AI Control Layer".

> **Status (submission 1, 2026-10-03):** working gateway, taint, content pipeline, model door, eval suite and dashboard. 11 of 16 acceptance criteria green, 5 partial; see [TOLLGATE.md › Status at submission 1](TOLLGATE.md#status-at-submission-1-2026-10-03). Every command below was run on `main` before this snapshot.

Tollgate gives every role its own MCP server, generated from one policy file, that exposes exactly the tools that role may use. Every tool call and tool result is checked on your machine by regex and a local classifier. On the server, a session that has read untrusted content can no longer send private data to a public destination. Every decision is logged with its reason.

## Why

In 2025, a poisoned GitHub issue made an agent copy private repositories into a public pull request. Every individual call was allowed by the agent's token. Role-based access alone does not stop that. Tollgate adds **session taint**: once a session reads untrusted content and then private data, any write to a public sink is blocked, and the block names the cause.

## How it works

```
Agent ──► Edge (local) ──────────────► Hub (server) ──────────────► MCP servers A, B, C
          content checks on              /mcp/{role}: role key,       using the role's own
          calls and results:             tools, argument limits,      credential per server
          normalise, regex,              taint, budgets, audit
          classifier                     /v1/chat ──► Ollama
```

- **Hub (server, authoritative):**
  - one virtual MCP per role
  - role-bound keys
  - argument limits
  - credentials per role
  - session taint
  - token budgets and loop cut-off
  - audit log
  - dashboard
- **Edge (client, protective):** local content and intent checks. Raw content stays on the machine. *At submission 1 the content pipeline (`tollgate/content/`) runs in-process inside `tollgate serve`; a separate client-side Edge process is planned.*
- **One `policy.yaml`** drives both. It is hot reloaded, and an invalid edit is rejected while the old policy stays active.

## Quick start

Needs Python ≥ 3.13 and [uv](https://docs.astral.sh/uv/). The first `tollgate test` downloads the tier 2 ONNX model (~739 MB) from Hugging Face.

```bash
uv sync
uv run tollgate replay github          # the 2025 GitHub attack, taint off vs on (in-process, no server)
uv run tollgate test                   # pytest suite + eval report (pass rate, FPR, posture, latency)
uv run tollgate test --eval-only       # eval report only
uv run tollgate serve                  # gateway on :8080 (role MCPs + 3 mock MCP servers + model door)
```

Connect an agent to a role (second terminal):

```bash
uv run tollgate key issue --role role-1
# tg_role-1_k…                          the key
# MCP URL: http://127.0.0.1:8080/mcp/role-1/      (trailing slash matters)
# Header:  Authorization: Bearer tg_role-1_k…
# Model door: http://127.0.0.1:8080/v1/chat/completions   (OpenAI-compatible)
```

Dashboard (third terminal):

```bash
uv run python dashboard/seed_demo.py   # optional: fills audit/events.jsonl with real gateway flows
uv run streamlit run dashboard/app.py  # http://localhost:8501, reads audit/ + the gateway's /healthz, /admin/*
```

Fast test run without the slow model tests: `uv run pytest -q -m "not slow"` (98 passed, 5 slow deselected at submission 1).

**Ollama.** The model door (`/v1/chat/completions`) proxies to Ollama at `http://127.0.0.1:11434/v1` (override with `TOLLGATE_UPSTREAM`). Run `ollama pull qwen3:1.7b` (role-1) and `ollama pull qwen3:4b` (role-2). Without Ollama, an allowed model returns **502 `upstream.error`**; the allow-list (403 `model.denied`) and budget (429) checks still work. Everything else runs without Ollama.

## For judges

| You want to | Do this |
|---|---|
| Run the test suite | `uv run tollgate test` → pytest, then the eval report: per-source confusion matrix, pass rate, FPR, posture score, latency |
| Replay a real attack | `uv run tollgate replay github` → leaks with taint off (PR created with salaries), **BLOCK** `taint.flow` with taint on. Supabase replay: in progress |
| Change a role's tools | With `tollgate serve` running, add `files: { tools: [fs.read] }` under `roles.role-1.servers` in `policy.yaml`. The next `tools/list` on `/mcp/role-1/` includes `files.fs.read`. No restart. |
| Break the policy on purpose | Save an invalid `policy.yaml` (e.g. append `roles: [oops`). `curl http://127.0.0.1:8080/healthz` shows `policy.last_error` with the parse error and the old `version`; the dashboard shows a red "Policy reload REJECTED … Still enforcing <version>" banner. The old policy keeps enforcing. Fix the file and it reloads. |
| Change a threshold | Edit `content.injection.high` (or `taint.enabled`) in `policy.yaml`. The next call follows the new rule. `taint.block_flow.action: approve` is accepted but the approval flow is not built yet; it is treated as block. |
| Disable a control | Set `content.injection: off` in `policy.yaml`, run `uv run tollgate test --eval-only`. Posture drops from 0.899 to 0.727. |
| Add an attack signature | Append to `signatures.yaml`. Matching inputs are blocked on the next call (reloaded on mtime). |
| Send your own attack prompt | `curl -H "Authorization: Bearer <key>" -H "Content-Type: application/json" -d '{"model":"qwen3:1.7b","messages":[{"role":"user","content":"…"}]}' http://127.0.0.1:8080/v1/chat/completions` (needs Ollama for a 200) |
| See metrics and export the audit | `uv run streamlit run dashboard/app.py` → `http://localhost:8501` → Export JSONL / CSV |
| 3-minute walkthrough | [DEMO.md](DEMO.md) |

## Policy at a glance

```yaml
roles:
  role-1:
    servers:
      github: { access: read }                       # all read tools of github
  role-2:
    servers:
      github:  { access: rw }
      tickets: { access: rw }
      files:   { tools: [fs.list, fs.read, fs.write] }   # exact pick
    approval: [github.pr.create]
    budget:   { tokens_per_day: 500000 }
taint:
  block_flow: { from: private_data, to: public_sink, action: block }
```

This is the target shape (`approval:` is not built yet). The real file is [`policy.yaml`](policy.yaml); a fuller sketch is in [TOLLGATE.md §4.6](TOLLGATE.md#46-policyyaml-sketch). Commented `strict` / `balanced` / `lenient` profiles under `policies/` are in progress.

## Docs

- [TOLLGATE.md](TOLLGATE.md): goal, architecture, features by importance, statistics, acceptance criteria (with status at submission 1), build order, demo
- [DEMO.md](DEMO.md): 3-minute demo script with fallbacks
- [docs/slides.md](docs/slides.md): 10-slide outline
- [docs/submission.md](docs/submission.md): submission draft
- `docs/architecture.md`: architecture diagram (in progress)
- [API_CONTRACT.md](API_CONTRACT.md): `scan()` and `AuditEvent`, the boundary between gateway and content
- [RESEARCH.md](RESEARCH.md): brief analysis, judging criteria, datasets, technology survey, alternative ideas
- [Product map](https://claude.ai/artifact/VScYMyEP8mAdALTqa3jxq6): visual walkthrough with a role builder, attack replay and a tier 1 playground

## Stack

Python 3.13 · uv · fastmcp 4.0.10 · Starlette + uvicorn · ONNX Runtime + tokenizers (`protectai/deberta-v3-base-prompt-injection-v2`, CPU) · huggingface-hub · PyYAML · Ollama · SQLite (tickets mock) · Streamlit + pandas · pytest + pytest-asyncio. No paid APIs; everything runs locally.
