# Connecting agents to Tollgate

**Decided:** Andrey, 2026-10-04 05:50. **Research:** primary docs, 2026-10-04 (sources at the end).

Tollgate checks agents through three doors. Each one is optional, and they combine.

| Door | What it sees | Who uses it |
|---|---|---|
| **Per-role MCP** `/mcp/{role}/` (Streamable HTTP + `Authorization: Bearer <key>`) | The MCP tools the role may use, with their arguments and results | Any MCP client: Claude Code, Codex, Cursor, Gemini CLI, Hermes, OpenClaw, VS Code |
| **Hook** `POST /hook` (new) | **Every** tool call the agent makes, built-ins included (shell, file read/write, web fetch), its result, and the user's prompt | Claude Code (native `type: "http"` hook); Codex, Cursor, Gemini CLI and Hermes through `tollgate hook <agent>` |
| **Model door** `/v1/chat/completions` | Prompts and replies, the model allow-list, the token budget | OpenAI-compatible clients: Hermes, OpenClaw, the OpenAI Agents SDK, LangChain, our demo agent |

**Later:** Anthropic Messages (`/v1/messages`) and OpenAI Responses (`/v1/responses`), with streaming, so Claude Code's and Codex's own model traffic can also pass through. This is not in this build.

## Identity
- The key is the same as everywhere else: one key minted per agent launch (`tollgate connect`). It is bound to a laptop (peer) and a role, and it is the session for taint.
- A hook request carries it as `Authorization: Bearer <key>`.

## `POST /hook` contract
The request is Claude Code's hook JSON, unchanged. The `tollgate hook <agent>` shim maps the other agents onto it.
```json
{"hook_event_name": "PreToolUse | PostToolUse | UserPromptSubmit",
 "session_id": "…", "cwd": "…",
 "tool_name": "Bash | Read | Edit | Write | WebFetch | WebSearch | Grep | Glob | mcp__<server>__<tool> | …",
 "tool_input": {…},
 "tool_response": "… (PostToolUse; also accept tool_output)",
 "prompt": "… (UserPromptSubmit; also accept user_prompt)",
 "agent": "claude-code | codex | cursor | gemini | hermes (set by the shim; absent = claude-code)"}
```
The response is in Claude Code's format. The shim translates it per agent.
- **PreToolUse:**
  ```json
  {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow|deny",
                          "permissionDecisionReason": "Tollgate: <plain sentence>", "updatedInput": {…}?}}
  ```
- **PostToolUse:**
  ```json
  {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": "<masked>"?}}
  ```
  plus `"additionalContext": "Tollgate: …"` when something was flagged.
- **UserPromptSubmit:** `{"decision": "block", "reason": "Tollgate: …"}`, or `{}` to allow.

Every hook call writes a normal audit event (`door: "hook"`, `tool: "builtin.<Name>"` or the MCP tool name, the verdict, reasons, stages, state before/after, trace fields). It shows in the edge and the console like any other call.

**Failure behaviour:** the shim fails **closed** (it exits 2 when the hub is unreachable). Claude Code's native http hook behaviour on errors isn't verified; we document it.

## Built-in tools in the policy
```yaml
builtins:                       # agent-native tools seen through /hook (Claude Code names; the shim maps others)
  Read:      [private_data]
  Grep:      [private_data]
  Glob:      []
  Edit:      []
  Write:     []
  WebFetch:  [untrusted_source]
  WebSearch: [untrusted_source]
  Bash:                         # labels by command pattern (fnmatch on the command, first match wins), else `default`
    public_sink:      ["git push*", "gh pr create*", "gh issue comment*", "curl * -d *", "curl *--data*", "curl * -F *", "scp *", "wget --post*"]
    untrusted_source: ["curl *", "wget *", "gh issue view*", "gh pr view*"]
    default:          []
roles:
  role-2:
    builtins: { deny: [WebSearch] }   # optional per role. Absent = every built-in allowed (Andrey: allowed, labelled, guarded by taint)
```
**PreToolUse:**
1. key → role;
2. the role's built-in deny list;
3. argument checks (content scan of `tool_input` at the args point: secrets or PII → deny or mask per the role's content policy);
4. labels → the data-flow rule. A public destination after the session read outside text while holding private data → **deny**, with the same plain cause as the MCP door.

**PostToolUse:**
1. labels on the tool → update the session state (untrusted / holds private);
2. content scan of the result at the result point: PII and secrets masked via `updatedToolOutput`, injection → flagged and the session marked untrusted.

**UserPromptSubmit:** content scan at the prompt point. Injection or blocked data → `decision: block`.

MCP tools called through the hook (`mcp__tollgate__…`) were already checked by the MCP door. The hook allows them and doesn't double-count them.

## `tollgate connect <agent>`
`tollgate connect claude-code|codex|cursor|gemini|hermes --role R --peer P [--port N] [--write]`
- It mints a key and prints the MCP entry plus hooks for that agent.
- `--write` writes them into the **project's** config: `.mcp.json` + `.claude/settings.json`, `.codex/config.toml`, `.cursor/mcp.json` + `.cursor/hooks.json`, `.gemini/settings.json`, or Hermes' `~/.hermes/config.yaml` (it prints a diff first and never overwrites unrelated keys).
- **Claude Code:** an http hook pointing at `/hook`, with the key header taken from `TOLLGATE_KEY`.
- **Others:** a command hook running `tollgate hook <agent>`.

**Company-wide enforcement (docs only):**
- Claude Code: `managed-settings.json` with `allowManagedHooksOnly`, `allowManagedMcpServersOnly` and `allowedHttpHookUrls`.
- Codex: `requirements.toml` with managed hooks and the MCP allowlist.
- Cursor: enterprise `hooks.json`.

## Real upstream MCP servers
`servers:` accepts any of these, next to `mock:`:
```yaml
servers:
  github:   { url: "https://api.githubcopilot.com/mcp/", headers: { Authorization: "Bearer ${GITHUB_TOKEN}" } }
  files:    { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"] }
  tickets:  { mock: mocks.tickets }
```
Tollgate connects to each upstream (through a fastmcp client or proxy) and keeps exposing only the role's tools under `/mcp/{role}/`, with every check unchanged. `${VAR}` is expanded from the environment; secrets never go into policy.yaml.

Shape (checked by `validate`): exactly one of `mock:`, `url:` (+ `headers:`, `transport: http|sse`) or `command:` (+ `args:`, `env:`, `cwd:`). A missing `${VAR}` stops startup with an error naming the variable, never its value. Upstream tools appear as `<server>.<tool>` with `_` turned into `.` (filesystem's `read_text_file` is `files.read.text.file`), so `tools:`, `constrain:` and `labels:` use that spelling. Each upstream is probed once at startup; one that does not answer is logged, reported in `/healthz` (`upstreams`) and shown as unreachable in the role detail, and the other servers keep working. Stdio processes are kept alive for the hub's lifetime and stopped on shutdown. Verified with `bunx @modelcontextprotocol/server-filesystem <dir>` (bun runs the npm package; no npx needed).

## Sources
- **Claude Code:**
  - https://code.claude.com/docs/en/hooks
  - https://code.claude.com/docs/en/mcp
  - https://code.claude.com/docs/en/managed-settings
- **Codex:**
  - https://learn.chatgpt.com/docs/hooks
  - https://learn.chatgpt.com/docs/extend/mcp?surface=cli
  - https://learn.chatgpt.com/docs/enterprise/managed-configuration
- **Cursor:**
  - https://cursor.com/docs/hooks
  - https://cursor.com/docs/context/mcp
- **Gemini CLI:**
  - https://geminicli.com/docs/hooks/reference/
  - https://geminicli.com/docs/tools/mcp-server/
- **Hermes:**
  - https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks
  - https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference
- **OpenClaw:**
  - https://docs.openclaw.ai/plugins/hooks
  - https://docs.openclaw.ai/gateway/config-extensions
- **VS Code:** https://code.visualstudio.com/docs/copilot/customization/hooks
