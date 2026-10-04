"""Client side of the hook door: `tollgate connect <agent>` config writers and the `tollgate hook <agent>` shim.

Stdlib only (the shim runs on every tool call of the agent, so it must start fast). Field names were checked against
each agent's docs (sources in docs/connectivity.md). The request/response format on the wire is Claude Code's.
"""
import difflib
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

AGENTS = ("claude-code", "codex", "cursor", "gemini", "hermes")
CLAUDE_EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit")
# agent's own event name -> Claude event name (the shim gets the agent's name as an argument from the generated config)
EVENTS = {
    "claude-code": {e: e for e in CLAUDE_EVENTS},
    "codex": {e: e for e in CLAUDE_EVENTS},
    "cursor": {"preToolUse": "PreToolUse", "postToolUse": "PostToolUse", "beforeSubmitPrompt": "UserPromptSubmit"},
    "gemini": {"BeforeTool": "PreToolUse", "AfterTool": "PostToolUse", "BeforeAgent": "UserPromptSubmit"},
    # ponytail: Hermes' shell-hook prompt event isn't documented; tool calls only
    "hermes": {"pre_tool_call": "PreToolUse", "post_tool_call": "PostToolUse"},
}
# agent's built-in tool name -> Claude Code name (the policy's `builtins:` are keyed by Claude names)
TOOLS = {
    "codex": {"apply_patch": "Edit"},
    "cursor": {"Shell": "Bash", "Delete": "Write"},
    "gemini": {"run_shell_command": "Bash", "read_file": "Read", "read_many_files": "Read", "write_file": "Write",
               "replace": "Edit", "glob": "Glob", "search_file_content": "Grep", "grep_search": "Grep",
               "list_directory": "Glob", "web_fetch": "WebFetch", "google_web_search": "WebSearch"},
    "hermes": {"terminal": "Bash", "read_file": "Read", "write_file": "Write", "patch": "Edit",
               "search_files": "Grep", "web_search": "WebSearch", "web_extract": "WebFetch"},
}
TIMEOUT = 10  # seconds the agent waits for one hook; the shim's own HTTP timeout is 8


# ---------------------------------------------------------------- shim: agent JSON -> Claude JSON -> agent JSON

def tool_name(agent: str, name: str, payload: dict) -> str:
    if agent == "cursor" and name.startswith("MCP:"):
        return f"mcp__{payload.get('mcp_server_name') or 'unknown'}__{name[4:]}"
    if agent in ("gemini", "hermes") and name.startswith("mcp_"):
        srv = (payload.get("mcp_context") or {}).get("server_name")
        if srv and name.startswith(f"mcp_{srv}_"):
            return f"mcp__{srv}__{name[len(srv) + 5:]}"
        srv, _, tool = name[4:].partition("_")  # ponytail: server names containing "_" split wrong without mcp_context
        return f"mcp__{srv}__{tool}"
    return TOOLS.get(agent, {}).get(name, name)


def to_claude(agent: str, event: str, p: dict) -> dict:
    """The agent's hook stdin -> the POST /hook request body (Claude Code's hook JSON + "agent")."""
    ev = EVENTS[agent].get(event or p.get("hook_event_name", ""), event or p.get("hook_event_name"))
    out = {"hook_event_name": ev, "agent": agent,
           "session_id": p.get("session_id") or p.get("conversation_id") or "",
           "cwd": p.get("cwd") or (p.get("workspace_roots") or [os.getcwd()])[0]}
    if ev == "UserPromptSubmit":
        out["prompt"] = p.get("prompt") or p.get("user_prompt") or ""
        return out
    out["tool_name"] = tool_name(agent, p.get("tool_name") or "", p)
    out["tool_input"] = p.get("tool_input") if "tool_input" in p else p.get("args") or {}
    if ev == "PostToolUse":
        r = next((p[k] for k in ("tool_response", "tool_output", "result") if k in p), "")
        if isinstance(r, dict) and "llmContent" in r:  # Gemini wraps the result
            r = r["llmContent"]
        out["tool_response"] = r
    return out


def post(body: dict, url: str | None = None) -> dict:
    """POST /hook. Raises on anything but a 2xx JSON object (or empty) answer; the caller fails closed."""
    url = (url or os.environ.get("TOLLGATE_URL") or "http://127.0.0.1:8080").rstrip("/") + "/hook"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {os.environ.get('TOLLGATE_KEY', '')}"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            raw = r.read().decode() or "{}"
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} {e.read().decode(errors='replace')[:200]}") from None
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(str(getattr(e, "reason", e))) from None
    resp = json.loads(raw)
    if not isinstance(resp, dict):
        raise RuntimeError("answer is not a JSON object")
    return resp


def verdict(event: str, resp: dict) -> dict:
    """Claude-format answer -> {deny, reason, input, output, context}."""
    h = resp.get("hookSpecificOutput") or {}
    deny = h.get("permissionDecision") == "deny" or resp.get("decision") == "block"
    return {"deny": deny, "reason": h.get("permissionDecisionReason") or resp.get("reason") or "Tollgate: blocked",
            "input": h.get("updatedInput"), "output": h.get("updatedToolOutput"),
            "context": h.get("additionalContext") or resp.get("additionalContext")}


def render(agent: str, claude_req: dict, claude_resp: dict | None, v: dict) -> tuple[dict | None, int]:
    """The agent's answer: (JSON for stdout or None, exit code). Deny = exit 2 + stderr reason everywhere it means
    "block" (Claude, Codex, Cursor, Gemini); Hermes ignores exit codes, so it gets {"action": "block"} and exit 0."""
    ev, deny, why = claude_req["hook_event_name"], v["deny"], v["reason"]
    if agent in ("claude-code", "codex"):
        return (None, 2) if deny else (claude_resp or None, 0)
    if agent == "cursor":
        if ev == "UserPromptSubmit":
            return ({"continue": False, "user_message": why}, 2) if deny else ({"continue": True}, 0)
        if ev == "PreToolUse":
            if deny:
                return {"permission": "deny", "user_message": why, "agent_message": why}, 2
            return {"permission": "allow", **({"updated_input": v["input"]} if v["input"] is not None else {})}, 0
        out = {}
        if v["output"] is not None and claude_req["tool_name"].startswith("mcp__"):
            out["updated_mcp_tool_output"] = v["output"]  # Cursor can replace MCP results only
        elif v["output"] is not None:
            out["additional_context"] = "Tollgate: the previous tool result held sensitive data; treat it as masked."
        if v["context"]:
            out["additional_context"] = (out.get("additional_context", "") + " " + v["context"]).strip()
        return out, 0
    if agent == "gemini":
        if deny:
            return None, 2
        if ev == "PreToolUse" and v["input"] is not None:
            return {"hookSpecificOutput": {"tool_input": v["input"]}}, 0
        if ev == "PostToolUse" and v["output"] is not None:  # "deny" on AfterTool = replace what the agent sees
            return {"decision": "deny", "reason": v["output"]}, 0
        return ({"hookSpecificOutput": {"additionalContext": v["context"]}} if v["context"] else {}), 0
    # hermes
    if deny:
        return {"action": "block", "message": why}, 0
    if ev == "PreToolUse" and v["input"] is not None:
        return {"action": "modify", "args": v["input"]}, 0
    if ev == "PostToolUse" and v["output"] is not None:
        return {"action": "modify", "result": v["output"]}, 0  # ponytail: result-rewrite shape unverified in docs
    return {"action": "allow"}, 0


def hook(agent: str, event: str | None, stdin: str | bytes, url: str | None = None) -> tuple[str, str, int]:
    """One hook call: (stdout, stderr, exit code). Fails closed: bad input, unknown event, hub unreachable, non-2xx,
    bad answer, any exception -> the agent's deny form (an uncaught error would exit 1 = non-blocking)."""
    ev = EVENTS[agent].get(event or "", "")
    req = {"hook_event_name": ev if ev in CLAUDE_EVENTS else "PreToolUse", "tool_name": ""}  # for a deny on bad input
    resp, why = None, "Tollgate: hook error"
    try:
        payload = json.loads((stdin.decode("utf-8-sig") if isinstance(stdin, bytes) else stdin) or "{}")  # utf-8-sig: PowerShell pipes a BOM
        if not isinstance(payload, dict):
            raise ValueError("hook input is not a JSON object")
        r = to_claude(agent, event, payload)
        if r["hook_event_name"] not in CLAUDE_EVENTS:
            raise ValueError(f"unknown hook event {r['hook_event_name']!r}")
        req, why = r, "Tollgate unreachable"
        resp = post(req, url)
        v = verdict(req["hook_event_name"], resp)
    except Exception as e:  # noqa: BLE001 - any failure is a deny
        resp, v = None, {"deny": True, "reason": f"{why}: {e}", "input": None, "output": None, "context": None}
    try:
        out, code = render(agent, req, resp, v)
    except Exception as e:  # noqa: BLE001
        v = {"deny": True, "reason": f"Tollgate: hook error: {e}"}
        out, code = ({"action": "block", "message": v["reason"]}, 0) if agent == "hermes" else (None, 2)
    return (json.dumps(out) if out is not None else ""), (v["reason"] if v["deny"] else ""), code


def main(argv: list[str]) -> int:
    """`tollgate hook <agent> [<agent event>] [--url U]`, agent JSON on stdin."""
    args = [a for a in argv if not a.startswith("--")]
    url = argv[argv.index("--url") + 1] if "--url" in argv and argv.index("--url") + 1 < len(argv) else None
    if url in args:
        args.remove(url)
    if not args or args[0] not in AGENTS:
        print(f"usage: tollgate hook {'|'.join(AGENTS)} [EVENT] [--url http://127.0.0.1:8080]", file=sys.stderr)
        return 2
    try:
        stdin = sys.stdin.buffer.read()
    except Exception as e:  # noqa: BLE001 - unreadable stdin is a deny, not exit 1
        stdin = f"\x00{e}".encode()
    out, err, code = hook(args[0], args[1] if len(args) > 1 else None, stdin, url)
    if out:
        sys.stdout.write(out + "\n")
    if err:
        sys.stderr.write(err + "\n")
    return code


# ---------------------------------------------------------------- connect: per-agent config

def hook_command(agent: str, event: str, base: str) -> str:
    """Absolute venv python, so the hook works from any directory without `uv` resolving the project each call."""
    return f'"{Path(sys.executable).as_posix()}" -m tollgate.cli hook {agent} {event} --url {base}'


def configs(agent: str, base: str, role: str, fast: bool = False) -> list[tuple[str, object]]:
    """(path relative to --dir, content) per file. JSON/YAML content is a dict, Codex's TOML is text. The key is
    never in here: every agent reads it from the TOLLGATE_KEY env var."""
    mcp = f"{base}/mcp/{role}/"
    cmd = lambda ev: hook_command(agent, ev, base)  # noqa: E731
    if agent == "claude-code":
        # default: command hook via the shim, which fails CLOSED; native http hooks are faster but fail open (--fast)
        http = {"type": "http", "url": f"{base}/hook", "timeout": TIMEOUT,
                "headers": {"Authorization": "Bearer ${TOLLGATE_KEY}"}, "allowedEnvVars": ["TOLLGATE_KEY"]}
        hk = (lambda ev: http) if fast else (lambda ev: {"type": "command", "command": cmd(ev), "timeout": TIMEOUT})  # noqa: E731
        return [(".mcp.json", {"mcpServers": {"tollgate": {
                    "type": "http", "url": mcp, "headers": {"Authorization": "Bearer ${TOLLGATE_KEY}"}}}}),
                (".claude/settings.json", {"hooks": {
                    "PreToolUse": [{"matcher": "*", "hooks": [hk("PreToolUse")]}],
                    "PostToolUse": [{"matcher": "*", "hooks": [hk("PostToolUse")]}],
                    "UserPromptSubmit": [{"hooks": [hk("UserPromptSubmit")]}]}})]
    if agent == "codex":
        hooks = "".join(f'\n[[hooks.{ev}]]\n[[hooks.{ev}.hooks]]\ntype = "command"\n'
                        f"command = '{cmd(ev)}'\ntimeout = {TIMEOUT}\n" for ev in CLAUDE_EVENTS)
        return [(".codex/config.toml", f'[mcp_servers.tollgate]\nurl = "{mcp}"\n'
                                       f'bearer_token_env_var = "TOLLGATE_KEY"\n{hooks}')]
    if agent == "cursor":
        h = lambda ev, **kw: [{"command": cmd(ev), "timeout": TIMEOUT, "failClosed": True, **kw}]  # noqa: E731
        return [(".cursor/mcp.json", {"mcpServers": {"tollgate": {
                    "url": mcp, "headers": {"Authorization": "Bearer ${env:TOLLGATE_KEY}"}}}}),
                (".cursor/hooks.json", {"version": 1, "hooks": {
                    "preToolUse": h("preToolUse", matcher="*"), "postToolUse": h("postToolUse", matcher="*"),
                    "beforeSubmitPrompt": h("beforeSubmitPrompt")}})]
    if agent == "gemini":
        h = lambda ev: {"type": "command", "command": cmd(ev), "timeout": TIMEOUT * 1000}  # noqa: E731  (ms)
        return [(".gemini/settings.json", {
            "mcpServers": {"tollgate": {"httpUrl": mcp, "headers": {"Authorization": "Bearer ${TOLLGATE_KEY}"}}},
            "hooks": {"BeforeTool": [{"matcher": ".*", "hooks": [h("BeforeTool")]}],
                      "AfterTool": [{"matcher": ".*", "hooks": [h("AfterTool")]}],
                      "BeforeAgent": [{"hooks": [h("BeforeAgent")]}]}})]
    return [("config.yaml", {  # hermes, relative to ~/.hermes
        "mcp_servers": {"tollgate": {"url": mcp, "headers": {"Authorization": "Bearer ${TOLLGATE_KEY}"}}},
        "hooks": {ev: [{"command": cmd(ev), "timeout": TIMEOUT}] for ev in EVENTS["hermes"]}})]


def _ours(item) -> bool:
    return "tollgate" in json.dumps(item).lower()


def merge(old, new):
    """Deep merge of our keys into an existing config: dicts recurse, lists keep the user's items and replace ours."""
    if isinstance(old, dict) and isinstance(new, dict):
        return {**old, **{k: merge(old[k], v) if k in old else v for k, v in new.items()}}
    if isinstance(old, list) and isinstance(new, list):
        return [i for i in old if not _ours(i)] + new
    return new


MARK_START, MARK_END = "# >>> tollgate (managed by `tollgate connect codex`)", "# <<< tollgate"


def merge_toml(old: str, block: str) -> str:
    """No TOML writer in the deps: replace/append a marked block, turn on `[features] hooks`, validate with tomllib."""
    text = re.sub(rf"\n?{re.escape(MARK_START)}.*?{re.escape(MARK_END)}\n?", "\n", old, flags=re.S).rstrip()
    feats = tomllib.loads(text).get("features") if text else None
    if feats is None:
        block = "[features]\nhooks = true\n\n" + block
    elif not feats.get("hooks"):
        if "hooks" in feats:  # `hooks = false` -> true
            text = re.sub(r"^hooks\s*=\s*false\s*$", "hooks = true", text, count=1, flags=re.M)
        else:
            text = re.sub(r"^\[features\][ \t]*$", "[features]\nhooks = true", text, count=1, flags=re.M)
    new = (text + "\n\n" if text else "") + f"{MARK_START}\n{block.rstrip()}\n{MARK_END}\n"
    tomllib.loads(new)  # raises if the user's file clashes (e.g. its own [mcp_servers.tollgate]); nothing is written
    return new


def dump(path: str, content) -> str:
    if isinstance(content, str):  # printed Codex TOML; --write sets the flag in place instead (merge_toml)
        return '[features]\nhooks = true\n\n' + content
    if path.endswith(".yaml"):
        import yaml
        return yaml.safe_dump(content, sort_keys=False, allow_unicode=True)
    return json.dumps(content, indent=2) + "\n"


def write(root: Path, path: str, content) -> str:
    """Merges into root/path and returns a short unified diff (nothing for an unchanged file)."""
    f = root / path
    old = f.read_text(encoding="utf-8") if f.exists() else ""
    if isinstance(content, str):
        new = merge_toml(old, content)
    elif path.endswith(".yaml"):
        import yaml
        new = dump(path, merge(yaml.safe_load(old) or {}, content))
    else:
        new = dump(path, merge(json.loads(old) if old.strip() else {}, content))
    if new != old:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(new, encoding="utf-8")
    diff = difflib.unified_diff(old.splitlines(), new.splitlines(), f"a/{path}", f"b/{path}", n=0, lineterm="")
    return "\n".join(diff) or f"{path}: unchanged"


NOTES = {
    "claude-code": "Claude Code: hooks run `tollgate hook claude-code <Event>`, which fails CLOSED (hub down = call "
                   "denied). --fast uses Claude Code's native http hooks instead: no process start per call, but they "
                   "fail OPEN (docs: a connection failure is a non-blocking error).",
    "codex": "Codex: `[features] hooks = true` is set; the project's .codex/ is read only for trusted projects, and "
             "non-managed hooks must be reviewed and trusted once with /hooks in the CLI.",
    "cursor": "Cursor: hooks use failClosed, so a crashed shim blocks too. Restart Cursor after writing hooks.json.",
    "gemini": "Gemini CLI: settings.json expands $TOLLGATE_KEY from the environment; hook timeouts are in ms.",
    "hermes": "Hermes: user-level file (~/.hermes/config.yaml); headers expand ${TOLLGATE_KEY} from the env or "
              "~/.hermes/.env. Only tool calls are hooked (no documented prompt event). --write re-dumps the YAML "
              "(comments are lost).",
}


def env_lines(key: str) -> str:
    return (f"# PowerShell (this window):  $env:TOLLGATE_KEY = \"{key}\"\n"
            f"# PowerShell (persistent):   setx TOLLGATE_KEY \"{key}\"\n"
            f"# bash/zsh:                  export TOLLGATE_KEY='{key}'\n"
            "# bash/zsh (persistent):     add that export line to ~/.bashrc or ~/.zshrc (not done for you)")


def claude_mcp_add(base: str, role: str) -> str:
    """User-scope MCP for Claude Code goes through its own CLI: ~/.claude.json is Claude Code's live state file, which
    it rewrites while running, so we never edit it. Single quotes keep ${TOLLGATE_KEY} literal in bash and PowerShell."""
    return ("claude mcp add --transport http --scope user --header 'Authorization: Bearer ${TOLLGATE_KEY}' "
            f"tollgate {base}/mcp/{role}/")


def connect(agent: str, key: str, role: str, base: str, write_dir: Path | None, fast: bool = False,
            scope: str = "project") -> str:
    """The text `tollgate connect <agent>` prints; with write_dir, also merges the files there. scope "user": the same
    files under ~ (write_dir is then the home dir), except Claude Code's MCP entry, which is a `claude mcp add` line."""
    files = configs(agent, base, role, fast)
    parts = [f"Tollgate for {agent}: role {role}, MCP {base}/mcp/{role}/, hooks -> {base}/hook ({scope} scope)",
             "Set the key in the shell that launches the agent (the configs only reference the env var):",
             env_lines(key), ""]
    if scope == "user" and agent == "claude-code":
        files = [f for f in files if f[0] != ".mcp.json"]
        parts += ["Register the MCP server at user scope (Claude Code's own CLI writes ~/.claude.json):",
                  claude_mcp_add(base, role), ""]
    for path, content in files:
        prefix = "~/.hermes/" if agent == "hermes" else "~/" if scope == "user" else ""
        shown = (prefix if write_dir is None else "") + path
        if write_dir is None:
            parts += [f"--- {shown}", dump(path, content).rstrip(), ""]
        else:
            parts += [write(write_dir, path, content), ""]
    parts.append(NOTES[agent])
    return "\n".join(parts)
