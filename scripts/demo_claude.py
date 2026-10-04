"""Replays the live Claude Code beat without Claude Code: the same three tool calls, as Claude Code's hook JSON,
through the real fail-closed shim (`python -m tollgate.cli hook claude-code <Event>`) against a running hub.

    $env:TOLLGATE_KEY = "<key from tollgate connect>"; uv run python scripts/demo_claude.py
    TOLLGATE_URL (default http://127.0.0.1:8080). Run it again after revoking the laptop: step 1 is denied.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

URL = os.environ.get("TOLLGATE_URL", "http://127.0.0.1:8080")
PAGE = ("<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1>"
        "<p>This domain is for use in illustrative examples in documents.</p></body></html>")
PAYROLL = Path("payroll.txt").read_text(encoding="utf-8") if Path("payroll.txt").exists() else (
    "name,role,salary_pln\nAnna Nowak,CTO,42000\nJan Kowalski,Engineer,21000\n")
STEPS = [  # (tool, input, what the tool returned)
    ("Bash", {"command": "curl -s https://example.com", "description": "Fetch example.com"}, PAGE),
    ("Read", {"file_path": str(Path.cwd() / "payroll.txt")}, PAYROLL),
    ("Bash", {"command": "git push origin main", "description": "Push to origin"}, ""),
]


def shim(event: str, body: dict) -> tuple[int, str]:
    body = {"hook_event_name": event, "session_id": "demo-replay", "cwd": str(Path.cwd()), **body}
    p = subprocess.run([sys.executable, "-m", "tollgate.cli", "hook", "claude-code", event, "--url", URL],
                       input=json.dumps(body), capture_output=True, text=True, encoding="utf-8")
    return p.returncode, (p.stderr or p.stdout).strip()


def main() -> int:
    if not os.environ.get("TOLLGATE_KEY"):
        print("set TOLLGATE_KEY first (tollgate connect claude-code ... prints it)", file=sys.stderr)
        return 2
    for i, (tool, ti, out) in enumerate(STEPS, 1):
        shown = ti.get("command") or Path(ti["file_path"]).name
        code, msg = shim("PreToolUse", {"tool_name": tool, "tool_input": ti})
        if code:
            print(f"{i}. {tool}({shown}) -> DENIED\n   {msg}")
            return 0
        code, msg = shim("PostToolUse", {"tool_name": tool, "tool_input": ti, "tool_response": out})
        print(f"{i}. {tool}({shown}) -> allowed" + (f"  [{msg[:160]}]" if "Tollgate" in msg else ""))
    print("not denied: is the hub on the demo policy (builtins: Bash git push* = public_sink)?")
    return 1


if __name__ == "__main__":
    sys.exit(main())
