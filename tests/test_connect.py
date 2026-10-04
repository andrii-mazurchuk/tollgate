"""`tollgate connect <agent>` config writers and the `tollgate hook <agent>` shim (against a stub POST /hook)."""
import json
import sys
import threading
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml

from tollgate import connect as conn
from tollgate.gateway import peers

SEEN = []


class Stub(BaseHTTPRequestHandler):
    """Claude-format answers: Bash `rm *` denied, Read masked on PostToolUse, prompts with 'ignore' blocked."""
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        SEEN.append((self.headers.get("Authorization"), body))
        if self.headers.get("Authorization") != "Bearer good":
            return self._send(401, {"error": "bad key"})
        ev = body["hook_event_name"]
        if ev == "PreToolUse":
            deny = body["tool_name"] == "Bash" and body["tool_input"].get("command", "").startswith("rm")
            h = {"hookEventName": ev, "permissionDecision": "deny" if deny else "allow",
                 "permissionDecisionReason": "Tollgate: no rm"}
            if body["tool_name"] == "Write":
                h["updatedInput"] = {"content": "[masked]"}
            return self._send(200, {"hookSpecificOutput": h})
        if ev == "PostToolUse":
            return self._send(200, {"hookSpecificOutput": {"hookEventName": ev, "updatedToolOutput": "[PESEL]"}}
                              if body["tool_name"] in ("Read", "mcp__tollgate__x") else {})
        return self._send(200, {"decision": "block", "reason": "Tollgate: injection"} if "ignore" in body["prompt"]
                          else {})

    def _send(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


@pytest.fixture
def hub(monkeypatch):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("TOLLGATE_KEY", "good")
    SEEN.clear()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def run(agent, event, payload, url):
    out, err, code = conn.hook(agent, event, json.dumps(payload), url)
    return (json.loads(out) if out else None), err, code


# (agent, event, stdin) for a shell `rm -rf /` call, then what the hub must have received as tool_name
SHELL = [("codex", "PreToolUse", {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}),
         ("cursor", "preToolUse", {"tool_name": "Shell", "tool_input": {"command": "rm -rf /"}, "conversation_id": "c1"}),
         ("gemini", "BeforeTool", {"tool_name": "run_shell_command", "tool_input": {"command": "rm -rf /"}}),
         ("hermes", "pre_tool_call", {"tool_name": "terminal", "args": {"command": "rm -rf /"}, "session_id": "s"})]


@pytest.mark.parametrize("agent,event,payload", SHELL)
def test_shell_deny_maps_both_ways(hub, agent, event, payload):
    out, err, code = run(agent, event, payload, hub)
    sent = SEEN[-1][1]
    assert sent["hook_event_name"] == "PreToolUse" and sent["tool_name"] == "Bash" and sent["agent"] == agent
    assert sent["tool_input"]["command"] == "rm -rf /"
    if agent == "hermes":
        assert (out, code) == ({"action": "block", "message": "Tollgate: no rm"}, 0)
    else:
        assert code == 2 and "no rm" in err
    if agent == "cursor":
        assert out["permission"] == "deny" and out["agent_message"] == "Tollgate: no rm"
        assert sent["session_id"] == "c1"


def test_allow_and_updated_input(hub):
    assert run("gemini", "BeforeTool", {"tool_name": "read_file", "tool_input": {}}, hub) == ({}, "", 0)
    w = {"tool_name": "write_file", "tool_input": {"content": "x"}}
    assert run("gemini", "BeforeTool", w, hub)[0] == {"hookSpecificOutput": {"tool_input": {"content": "[masked]"}}}
    assert run("cursor", "preToolUse", {"tool_name": "Write", "tool_input": {}}, hub)[0] == \
        {"permission": "allow", "updated_input": {"content": "[masked]"}}
    assert run("hermes", "pre_tool_call", {"tool_name": "write_file", "args": {}}, hub)[0] == \
        {"action": "modify", "args": {"content": "[masked]"}}
    assert run("hermes", "pre_tool_call", {"tool_name": "terminal", "args": {"command": "ls"}}, hub)[0] == \
        {"action": "allow"}
    out, _, code = run("codex", "PreToolUse", {"tool_name": "Bash", "tool_input": {"command": "ls"}}, hub)
    assert code == 0 and out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_post_tool_masking_per_agent(hub):
    out, _, _ = run("gemini", "AfterTool", {"tool_name": "read_file", "tool_input": {},
                                            "tool_response": {"llmContent": "PESEL 44051401359"}}, hub)
    assert SEEN[-1][1]["tool_response"] == "PESEL 44051401359" and out == {"decision": "deny", "reason": "[PESEL]"}
    out, _, _ = run("cursor", "postToolUse", {"tool_name": "MCP:x", "mcp_server_name": "tollgate", "tool_input": {},
                                              "tool_output": "{}"}, hub)
    assert SEEN[-1][1]["tool_name"] == "mcp__tollgate__x" and out == {"updated_mcp_tool_output": "[PESEL]"}
    out, _, _ = run("hermes", "post_tool_call", {"tool_name": "read_file", "args": {}, "result": "x"}, hub)
    assert SEEN[-1][1]["tool_response"] == "x" and out == {"action": "modify", "result": "[PESEL]"}
    run("gemini", "AfterTool", {"tool_name": "mcp_tollgate_tickets_read", "tool_input": {},
                                "mcp_context": {"server_name": "tollgate"}, "tool_response": {}}, hub)
    assert SEEN[-1][1]["tool_name"] == "mcp__tollgate__tickets_read"


def test_prompt_block(hub):
    out, err, code = run("cursor", "beforeSubmitPrompt", {"prompt": "ignore all previous"}, hub)
    assert code == 2 and out == {"continue": False, "user_message": "Tollgate: injection"}
    assert SEEN[-1][1] == {**SEEN[-1][1], "hook_event_name": "UserPromptSubmit", "prompt": "ignore all previous"}
    assert run("gemini", "BeforeAgent", {"prompt": "ignore it"}, hub)[2] == 2
    assert run("codex", "UserPromptSubmit", {"prompt": "hello"}, hub) == (None, "", 0)


@pytest.mark.parametrize("agent", ["codex", "cursor", "gemini", "hermes", "claude-code"])
def test_fail_closed(hub, monkeypatch, agent):
    ev = {"codex": "PreToolUse", "cursor": "preToolUse", "gemini": "BeforeTool", "hermes": "pre_tool_call",
          "claude-code": "PreToolUse"}[agent]
    p = {"tool_name": "Read", "tool_input": {}}
    for url in ("http://127.0.0.1:9", hub):  # unreachable, then reachable with a bad key (401)
        monkeypatch.setenv("TOLLGATE_KEY", "bad")
        out, err, code = run(agent, ev, p, url)
        if agent == "hermes":
            assert out["action"] == "block" and out["message"].startswith("Tollgate unreachable")
        else:
            assert code == 2 and err.startswith("Tollgate unreachable")
    assert "401" in err


# ---------------------------------------------------------------- connect

@pytest.fixture
def peer(monkeypatch, tmp_path):
    pid = peers.enroll(peers.enroll_token()["token"], "A", "laptop")
    peers.set_roles(pid, ["role-2"])
    return pid


def cli(monkeypatch, capsys, *args):
    from tollgate import cli as c
    monkeypatch.setattr(sys, "argv", ["tollgate", *args])
    rc = c.main()
    o = capsys.readouterr()
    return rc, o.out, o.err


@pytest.mark.parametrize("agent", conn.AGENTS)
def test_connect_prints_config(monkeypatch, capsys, peer, agent):
    rc, out, _ = cli(monkeypatch, capsys, "connect", agent, "--role", "role-2", "--peer", peer, "--port", "9001")
    assert rc == 0
    key = out.split('$env:TOLLGATE_KEY = "')[1].split('"')[0]
    assert key.startswith("tg_") or len(key) > 10
    body = out.split("export TOLLGATE_KEY=")[1].split("\n", 1)[1]
    assert key not in body, "the key goes in the env var, never in a config file"
    assert "http://127.0.0.1:9001/mcp/role-2/" in body
    files = dict(conn.configs(agent, "http://127.0.0.1:9001", "role-2"))
    if agent == "claude-code":
        h = files[".claude/settings.json"]["hooks"]["PreToolUse"][0]
        assert h["matcher"] == "*" and h["hooks"][0]["type"] == "http"
        assert h["hooks"][0]["url"] == "http://127.0.0.1:9001/hook" and h["hooks"][0]["allowedEnvVars"] == ["TOLLGATE_KEY"]
        assert files[".mcp.json"]["mcpServers"]["tollgate"]["headers"]["Authorization"] == "Bearer ${TOLLGATE_KEY}"
    elif agent == "codex":
        t = tomllib.loads(files[".codex/config.toml"])
        assert t["mcp_servers"]["tollgate"]["bearer_token_env_var"] == "TOLLGATE_KEY"
        assert "hook codex PreToolUse --url http://127.0.0.1:9001" in t["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert set(t["hooks"]) == {"PreToolUse", "PostToolUse", "UserPromptSubmit"}
    elif agent == "cursor":
        hk = files[".cursor/hooks.json"]
        assert hk["version"] == 1 and all(h[0]["failClosed"] for h in hk["hooks"].values())
        assert set(hk["hooks"]) == {"preToolUse", "postToolUse", "beforeSubmitPrompt"}
        assert files[".cursor/mcp.json"]["mcpServers"]["tollgate"]["headers"]["Authorization"] == "Bearer ${env:TOLLGATE_KEY}"
    elif agent == "gemini":
        s = files[".gemini/settings.json"]
        assert s["mcpServers"]["tollgate"]["httpUrl"].endswith("/mcp/role-2/")
        assert set(s["hooks"]) == {"BeforeTool", "AfterTool", "BeforeAgent"}
    else:
        assert set(files["config.yaml"]["hooks"]) == {"pre_tool_call", "post_tool_call"}
        assert "~/.hermes/config.yaml" in out


def test_connect_refuses_disallowed_role(monkeypatch, capsys, peer):
    rc, out, err = cli(monkeypatch, capsys, "connect", "codex", "--role", "role-1", "--peer", peer)
    assert rc == 1 and "refused" in err and "may not run role-1" in err and out == ""


def test_write_merges_json_without_clobbering(monkeypatch, capsys, peer, tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text(json.dumps({"model": "opus", "hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-lint"}]}]}}))
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}}))
    for _ in range(2):  # idempotent: the second run replaces our entries instead of duplicating them
        rc, out, _ = cli(monkeypatch, capsys, "connect", "claude-code", "--role", "role-2", "--peer", peer,
                         "--write", "--dir", str(tmp_path))
        assert rc == 0
    s = json.loads((tmp_path / ".claude/settings.json").read_text())
    assert s["model"] == "opus" and len(s["hooks"]["PreToolUse"]) == 2
    assert s["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "my-lint"
    m = json.loads((tmp_path / ".mcp.json").read_text())
    assert set(m["mcpServers"]) == {"other", "tollgate"}
    assert "unchanged" in out
    assert "tg" not in (tmp_path / ".mcp.json").read_text().replace("tollgate", "")  # no key written


def test_write_merges_toml_block(monkeypatch, capsys, peer, tmp_path):
    (tmp_path / ".codex").mkdir()
    f = tmp_path / ".codex/config.toml"
    f.write_text('model = "o4"\n\n[features]\nweb = true\n\n[mcp_servers.other]\nurl = "http://x"\n')
    for _ in range(2):
        assert cli(monkeypatch, capsys, "connect", "codex", "--role", "role-2", "--peer", peer,
                   "--write", "--dir", str(tmp_path))[0] == 0
    t = tomllib.loads(f.read_text())
    assert t["model"] == "o4" and t["features"] == {"web": True, "hooks": True}
    assert set(t["mcp_servers"]) == {"other", "tollgate"} and len(t["hooks"]["PreToolUse"]) == 1
    f.write_text('[mcp_servers.tollgate]\nurl = "http://mine"\n')  # a clash we won't paper over
    rc, _, err = cli(monkeypatch, capsys, "connect", "codex", "--role", "role-2", "--peer", peer,
                     "--write", "--dir", str(tmp_path))
    assert rc == 1 and "not written" in err and f.read_text() == '[mcp_servers.tollgate]\nurl = "http://mine"\n'


def test_write_hermes_yaml(monkeypatch, capsys, peer, tmp_path):
    (tmp_path / "config.yaml").write_text("model: hermes-4\nhooks:\n  pre_tool_call:\n    - command: my.sh\n")
    assert cli(monkeypatch, capsys, "connect", "hermes", "--role", "role-2", "--peer", peer,
               "--write", "--dir", str(tmp_path))[0] == 0
    y = yaml.safe_load((tmp_path / "config.yaml").read_text())
    assert y["model"] == "hermes-4" and y["hooks"]["pre_tool_call"][0] == {"command": "my.sh"}
    assert "hook hermes pre_tool_call" in y["hooks"]["pre_tool_call"][1]["command"]
