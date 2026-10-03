# Tollgate

**An AI control layer for agents that use MCP tools.** HackYeah 2026, Goldman Sachs task "AI Control Layer".

> **Status: pre-build.** The commands below are the target interface, not working code yet. The spec and acceptance criteria are in [TOLLGATE.md](TOLLGATE.md).

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
- **Edge (client, protective):** local content and intent checks. Raw content stays on the machine.
- **One `policy.yaml`** drives both. It is hot reloaded, and an invalid edit is rejected while the old policy stays active.

## Quick start (target)

```bash
pip install -e .
ollama pull qwen3:4b
tollgate serve                 # Hub, Edge, 3 mock MCP servers, dashboard
```

Connect an agent to a role:

```bash
tollgate key issue --role role-2 --ttl 8h
# MCP URL:   http://localhost:8080/mcp/role-2      (header: Authorization: Bearer <key>)
# Model URL: http://localhost:8080/v1              (OpenAI-compatible)
```

## For judges

| You want to | Do this |
|---|---|
| Run the test suite | `tollgate test` → pass rate, false-positive rate, posture score |
| Replay a real attack | `tollgate replay github` (or `supabase`) |
| Change a role's tools | Edit `roles.<role>.servers` in `policy.yaml`. The next `tools/list` reflects it. |
| Flip block to approve, or change a threshold | Edit `taint.block_flow.action` or `content.injection.high`. The next call follows the new rule. |
| Add an attack signature | Append to `signatures.yaml`. Matching inputs are blocked on the next call. |
| Send your own attack prompt | POST to `/v1/chat/completions` |
| See metrics and export the audit | Dashboard at `http://localhost:8501` → Export JSONL/CSV |

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

A fuller sketch is in [TOLLGATE.md §4.6](TOLLGATE.md#46-policyyaml-sketch). The shipped `policy.yaml` will be fully commented, with `strict`, `balanced` and `lenient` profiles.

## Docs

- [TOLLGATE.md](TOLLGATE.md): goal, architecture, features by importance, statistics, acceptance criteria, build order, demo
- [RESEARCH.md](RESEARCH.md): brief analysis, judging criteria, datasets, technology survey, alternative ideas
- [Product map](https://claude.ai/artifact/VScYMyEP8mAdALTqa3jxq6): visual walkthrough with a role builder, attack replay and a tier 1 playground

## Stack

Python 3.12 · fastmcp 4.0.10 · Starlette · ONNX Runtime (`protectai/deberta-v3-base-prompt-injection-v2`) · Ollama · SQLite · Streamlit · pytest. No paid APIs; everything runs locally.
