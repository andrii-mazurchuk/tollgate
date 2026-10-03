# Tollgate architecture

```mermaid
flowchart LR
    agent["Agent / MCP client<br/>(Claude, Cursor, script)"]
    llm["Agent's LLM calls"]

    subgraph gw["tollgate serve (one process)"]
        direction LR
        key["Key check<br/>Bearer key bound to role → 401"]
        subgraph hub["Hub: RoleGate middleware, /mcp/&lt;role&gt;/"]
            direction TB
            role["Role MCP<br/>tools/list filtered, call denied again<br/>role.denied"]
            limits["Argument limits<br/>path glob, select_only<br/>role.constraint"]
            loops["Loop cut-off<br/>same key+tool+args &gt; N<br/>loop.cutoff"]
            taint["Session taint<br/>untrusted + private → public_sink<br/>taint.flow"]
            role --> limits --> loops --> taint
        end
        subgraph edge["Edge: content pipeline scan()"]
            direction TB
            norm["Normalise<br/>NFKC, invisibles, base64"]
            t1["Tier 1<br/>PII + checksum, secrets,<br/>injection phrases, signatures"]
            t2["Tier 2 (gated)<br/>DeBERTa ONNX on CPU"]
            norm --> t1 --> t2
        end
        door["Model door /v1/chat/completions<br/>allow-list → budget 429 → prompt scan<br/>→ upstream → response scan"]
        audit[("audit/events.jsonl<br/>one AuditEvent per decision")]
        admin["/healthz /admin/taint /admin/budget"]
    end

    subgraph src["Source MCPs (mocks, in-process)"]
        github["github"]
        tickets["tickets (SQLite)"]
        files["files"]
    end

    policy[["policy.yaml<br/>(policies/strict|balanced|lenient)"]]
    ollama["Ollama<br/>qwen3:1.7b / qwen3:4b"]
    dash["Dashboard (Track B)"]

    agent -->|"MCP over HTTP"| key --> role
    taint -->|"tool args"| edge
    edge -->|"allowed / redacted call"| src
    src -->|"tool result"| edge
    edge -->|"result, redacted"| agent
    llm --> door
    door -.->|"prompt + response"| edge
    door --> ollama
    policy -.->|"hot reload: stat() per request,<br/>invalid file rejected"| hub
    policy -.-> door
    policy -.->|"content: section"| edge
    hub --> audit
    door --> audit
    audit --> dash
    admin --> dash
```

How a tool call flows, as built in `tollgate/gateway/__init__.py`:

1. The agent connects to `/mcp/<role>/` with a role key; `require_key` returns 401 unless the key is valid and bound to that role.
2. `RoleGate` (fastmcp middleware) re-reads `policy.yaml` on every request; `tools/list` is filtered, and `tools/call` is denied again for a tool outside the role (`access: read|rw` or an exact `tools:` list).
3. Argument limits (`constrain:`) check path globs and `select_only` SQL before anything is forwarded.
4. The loop cut-off blocks the same key + tool + arguments more than `loops.max_identical_calls` times in a row.
5. Session taint (keyed by role key, not MCP session id) blocks a `public_sink` call once the session has both read an `untrusted_source` and a `private_data` tool; the message names both causes.
6. The content pipeline scans the tool arguments (block or redact in place), the call goes to the source MCP, and the result is scanned again (redacted before the agent sees it). Tier 2 runs synchronously only on short text, at `sync_points`, or on a tier 1 escalation.
7. The model door applies the same idea to LLM traffic: per-role model allow-list, daily token budget (429), prompt and response scans, then Ollama.
8. Every decision writes one `AuditEvent` (verdict, reasons, per-stage `latency_ms`, taint flags, sha256 of the content, never the raw text) to `audit/events.jsonl`, which the dashboard reads.
9. Measured (`tollgate perf`, `audit/perf.json`): Hub checks p95 about 0.5 ms, tier 1 p95 about 0.4 ms; tier 2 comes from `audit/eval.json`.
10. A policy edit takes effect on the next call; an invalid file is rejected and the previous policy keeps running (`/healthz` shows the error).
