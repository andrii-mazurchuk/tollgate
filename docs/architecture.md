# Tollgate architecture

## Simplified

![Tollgate, simplified](img/arch-simple.svg)

Three doors, one policy. MCP tool calls go through the Edge (content checks) and the Hub (per-role gate) to the source MCPs. The agent's built-in tools (shell, file read/write, web fetch) and the user's prompt reach the same checks through the **hook door** `POST /hook`. LLM calls go through the model door (prompt scanned before any upstream call) to Ollama or the offline scripted model. `policy.yaml` hot-reloads into all three; the signed feed updates Edge signatures; every decision lands in the audit JSONL. Two UIs read it: the local edge `/edge` (developer laptop, full text stays local) and the server console `/console` (security lead, fingerprints only, behind console accounts). Human approval is API/CLI only (`/admin/approvals`, `tollgate approve|deny`).

**Deployment.** One binary (`tollgate up`) in two roles: a **local enforcer** plus an **optional control plane**. The local enforcer runs on each laptop: hooks and MCP go to localhost, full text never leaves the machine, it works offline, and a solo developer needs nothing more. The optional control plane adds enrollment, roles, policy, revocation, the threat feed and fleet audit (fingerprints only). The demo runs both on one machine; splitting into `--role edge|hub` with policy sync is the next step. The developer's interface is the deny message inside the agent (reason, what to do, link to the step on the local edge); `tollgate open` opens the details on demand.

## Detailed

```mermaid
flowchart LR
    agent["Agent / MCP client<br/>(Claude Code, Codex, Cursor, Gemini CLI, Hermes, script)<br/>key minted per launch"]
    builtin["Agent built-ins + prompt<br/>(Bash, Read, Write, WebFetch...)"]
    shim["tollgate hook AGENT EVENT<br/>(stdlib shim, fails closed;<br/>--fast: native http, fails open)"]
    llm["Agent's LLM calls"]

    subgraph gw["tollgate up (one process)"]
        direction LR
        key["Key check<br/>Bearer key bound to role → 401<br/>peer revoked / role removed → 401"]
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
        hook["Hook door POST /hook<br/>key → role → builtins.deny → content scan<br/>→ builtins labels → taint (Bash read-only when tainted)"]
        audit[("audit/events.jsonl<br/>one AuditEvent per decision")]
        puller["Feed puller (lifespan task)<br/>every interval_s: GET bundle,<br/>verify HMAC, newer version only"]
        admin["/healthz (pin_alerts, feed) /admin/taint /admin/budget<br/>/admin/approvals (POST needs admin token)"]
        edgeui["Local edge UI /edge<br/>overview, sessions trace, checks in ms,<br/>events, setup"]
        console["Server console /console<br/>access map, peers & roles, sessions (fingerprints), Try it,<br/>policy view/switch/edit, threat feed, self-test, users, export"]
        accts[("audit/accounts.json<br/>Admin / Viewer, invites, sessions")]
    end

    subgraph src["Source MCPs (mocks, in-process)"]
        github["github"]
        tickets["tickets (SQLite)"]
        files["files"]
    end

    policy[["policy.yaml<br/>(policies/strict|balanced|lenient)"]]
    ollama["Ollama<br/>qwen3:1.7b / qwen3:4b"]
    peersreg[("audit/peers.json<br/>peers, roles, one-time enroll tokens")]
    laptop["Laptop: tollgate enroll TOKEN<br/>tollgate connect AGENT --role R --peer P<br/>(writes MCP entry + hooks)"]
    evaljson[("audit/eval.json, tests.json, perf.json<br/>from tollgate test / perf")]
    feedsrv["Signature feed server<br/>tollgate feed serve :8090<br/>GET /bundle.json (HMAC-signed)"]
    sigs[["signatures.yaml"]]

    agent -->|"MCP over HTTP"| key --> role
    taint -->|"tool args"| edge
    edge -->|"allowed / redacted call"| src
    src -->|"tool result"| edge
    edge -->|"result, redacted"| agent
    builtin --> shim -->|"Claude Code hook JSON"| hook
    hook -.->|"input / result / prompt"| edge
    hook -.->|"same session state"| taint
    hook --> audit
    llm --> door
    door -.->|"prompt + response"| edge
    door -->|"Ollama, or scripted model<br/>(--scripted-model)"| ollama
    policy -.->|"hot reload: stat() per request,<br/>invalid file rejected"| hub
    policy -.-> door
    policy -.->|"content: section"| edge
    hub --> audit
    door --> audit
    audit --> edgeui
    audit -->|"sha256 only, no text"| console
    laptop -->|"enroll once; mint a key per launch"| peersreg
    peersreg -.->|"verify(): revoked peer / removed role"| key
    console -->|"set roles, revoke, enroll token"| peersreg
    console -->|"profile switch / access edit<br/>(backup + atomic write)"| policy
    console -->|"publish a signature"| feedsrv
    evaljson --> console
    feedsrv -->|"pull"| puller
    puller -->|"atomic write<br/>(tmp + os.replace)"| sigs
    sigs -.->|"mtime reload"| t1
    admin --> console
    accts -.->|"cookie + CSRF, or admin token"| console
```

How a tool call flows, as built in `tollgate/gateway/__init__.py`:

1. The agent connects to `/mcp/<role>/` with a role key; `require_key` returns 401 unless the key is valid and bound to that role.
2. Tool pinning: at startup every source tool's name + description + input schema is hashed. A tool whose hash later changes (rug pull) is hidden from `tools/list`, its calls are denied (`pin.changed`), and the alert is audited and listed in `/healthz` `pin_alerts`. Re-pinning is a restart.
3. `RoleGate` (fastmcp middleware) re-reads `policy.yaml` on every request; `tools/list` is filtered, and `tools/call` is denied again for a tool outside the role (`access: read|rw` or an exact `tools:` list).
4. Argument limits (`constrain:`) check path globs and `select_only` SQL before anything is forwarded.
5. The loop cut-off blocks the same key + tool + arguments more than `loops.max_identical_calls` times in a row.
6. Session taint (keyed by role key, not MCP session id) blocks a `public_sink` call once the session has both read an `untrusted_source` and a `private_data` tool; the message names both causes. With `taint.block_flow.action: approve`, or a tool in `roles.<role>.approval`, the call is parked instead: it appears in `GET /admin/approvals` and waits up to `approval.timeout_s` for `POST /admin/approvals/{id}` (`TOLLGATE_ADMIN_TOKEN`, never a role key) or `tollgate approve|deny <id>`. Deny or timeout fails closed (`approval.denied` / `approval.timeout`).
7. The content pipeline scans the tool arguments (block or redact in place), the call goes to the source MCP, and the result is scanned again (redacted before the agent sees it). Tier 2 runs synchronously only on short text, at `sync_points`, or on a tier 1 escalation.
8. The model door applies the same idea to LLM traffic: per-role model allow-list, daily token budget (429), prompt and response scans, then Ollama.
9. Every decision writes one `AuditEvent` (verdict, reasons, per-stage `latency_ms`, taint flags, sha256 of the content, never the raw text) to `audit/events.jsonl`. The local edge keeps the full text in a local store (`keep_text`, retention) for `/edge`; the console only ever shows the fingerprint.
10. Measured: hub checks p95 under 1 ms, tier 1 p95 2.5 ms, tier 2 on short text ~65–90 ms p95 against an 80 ms target (borderline; gated so long tool results skip it in balanced). Sources: `audit/perf.json` (`tollgate perf`) and `audit/eval.json`.
11. A policy edit takes effect on the next call; an invalid file is rejected and the previous policy keeps running (`/healthz` shows the error).
12. `tollgate up` runs the gateway in-process, serving `/console` and `/edge`; `--scripted-model` points the model door at an in-process scripted hijacked model, so no Ollama is needed. (The early Streamlit dashboard was removed.)
13. P6 signature feed (`tollgate/feed/`): `tollgate feed serve` is the externally managed system; it serves `feed/bundle_src.yaml` as `{version, issued_at, signatures, sig}`, `sig` = HMAC-SHA256 (`TOLLGATE_FEED_SECRET`) over the canonical JSON of the rest. `tollgate feed publish --add 'id=..,pattern=..,action=block,tags=A;B'` appends a rule and bumps the version. With `feed: {url, interval_s}` in the policy, a lifespan task pulls the bundle, rejects a bad signature (`/healthz` `feed.last_error`, file untouched), and writes a newer version to `content.signatures` atomically, stamped `# feed-version: N` so a restart does not rewrite it. Tier 1 picks the file up by mtime on the next scan. Without `feed:` the local file is authoritative. `tollgate up` also starts the feed server when `feed:` is set. The seed bundle adds model supply-chain rules: pickle `GLOBAL` opcodes, `torch.load` without `weights_only=True`, `trust_remote_code=True`, `yaml.load` without `SafeLoader`, and langchain PALChain / PythonREPLTool (CVE-2023-36258 / GHSA-2qmj-7962-cjq8, CVE-2023-36188, CVE-2023-36095).
14. Identity (`tollgate/gateway/peers.py`): a laptop enrolls once with a one-time token (`tollgate enroll-token` or the console's Enroll a laptop; 24 h expiry); the admin sets which roles it may run (Peers & roles). `tollgate connect claude-code|codex|cursor|gemini|hermes|print --role R --peer P` mints a key per agent launch (`tg_<role>_<peer>-<n>_<mac>`), so each run starts with clean taint. Minting is refused for a revoked peer or a role it may not run; revoking a peer, or removing a role from it, invalidates its keys on the next request. `tollgate seed-fleet` enrolls 6 demo laptops and drives real traffic through the gateway with minted keys.
15. Console (`tollgate/console.py`, `tollgate/console_feed.py`, `tollgate/console_try.py`, `tollgate/console_map.py`, `tollgate/console_auth.py`, `tollgate/ui/console/`): `/console/api/*`. Access needs a console account session (cookie + CSRF token, same-origin `Origin`, JSON body) or `Authorization: Bearer $TOLLGATE_ADMIN_TOKEN`; Viewers read, Admins write (403 otherwise); until the owner account exists, loopback may read but not write. Policy writes (profile switch, role × server × tool access edits) back up the file, write atomically and reload; a conflicting concurrent edit gets 409; an invalid file shows "Edit rejected … Still enforcing <version>". Threat feed lists signatures in force and publishes a signed one; Self-test shows the eval headline against targets and the misses, and can rerun the eval.
16. Hook door (`tollgate/gateway/hooks.py`, `tollgate/connect.py`): `tollgate connect <agent> --write` writes the agent's MCP entry and hooks (Claude Code `.mcp.json` + `.claude/settings.json`, Codex `.codex/config.toml`, Cursor `.cursor/hooks.json`, Gemini `.gemini/settings.json`, Hermes `~/.hermes/config.yaml`). Each hook runs `tollgate hook <agent> <event>`, which maps the agent's JSON to Claude Code's and `POST`s it to `/hook` with `TOLLGATE_KEY`; any error (hub down, bad key, 5xx, bad stdin) answers with the agent's deny form. On `/hook`: PreToolUse checks the role's `builtins.deny`, scans the input (redaction rewrites it), labels the call from `builtins:` (Bash by command pattern, plus a built-in sink floor) and applies session taint; when the session is untrusted and holds private data, Bash passes only plain read-only commands. PostToolUse scans the result (secrets/PII masked; an injection flag taints the session). UserPromptSubmit blocks an injected prompt. Calls to our own `mcp__tollgate__*` server pass through (the MCP door already checked them). One audit event per hook call, door `hook`.
17. Deployment: the same binary is the local enforcer (each laptop, offline-capable, text stays local) and the optional control plane (enrollment, roles, policy, revocation, feed, fleet audit as fingerprints). Company-wide, managed settings (Claude Code `managed-settings.json`, Codex `requirements.toml`, Cursor enterprise hooks) pin the hooks and MCP servers so a developer cannot remove them ([connectivity.md](connectivity.md)).
