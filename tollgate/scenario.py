"""Runs the Acme scenario (scenario/acme.yaml) step by step through the real gateway over HTTP (in-process ASGI),
as the step's role, with one key per scenario session. Used by the edge UI and tests/test_scenario_acme.py."""
import copy
import json
import os
from pathlib import Path

import httpx2
import yaml
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

from tollgate import explain
from tollgate.gateway import keys, model_door, taint

PATH = Path(__file__).resolve().parents[1] / "scenario" / "acme.yaml"


def load(path: Path = PATH) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def steps(spec: dict) -> list[dict]:
    """Flat step list; operator acts mark every step operator."""
    out = []
    for act in spec["acts"]:
        for s in act["steps"]:
            out.append({**s, "act": act["id"], "operator": bool(act.get("operator") or s.get("operator"))})
    return out


def expected_words(e: dict) -> str:
    if "tools" in e:
        return "exactly " + ", ".join(e["tools"])
    if "count" in e:
        return f"{e['count']} tools, without " + ", ".join(e.get("absent", []))
    parts = [str(e["verdict"]).upper()] if "verdict" in e else []
    if "status" in e and e.get("status") != 200:
        parts.append(f"HTTP {e['status']}")
    if e.get("rule"):
        parts.append(explain.rule(e["rule"])[0].rstrip("."))
    if e.get("state"):
        parts.append("session " + " + ".join(explain.state_words(e["state"])))
    if e.get("contains"):
        parts.append("shows " + ", ".join(e["contains"]))
    if e.get("no_new_pr"):
        parts.append("no PR created")
    return "; ".join(parts)


class Runner:
    def __init__(self, app, spec: dict | None = None, audit_path=None):
        self.app, self.spec = app, spec or load()
        self.by_id = {s["id"]: s for s in steps(self.spec)}
        self.keys: dict[str, str] = {}     # scenario session -> role key
        self.prev: dict[str, str] = {}     # scenario session -> last tool output ($prev)
        self.results: dict[str, dict] = {}
        self.labels: dict[str, str] = {}   # key_id -> "Scenario 3: a3-attack" (edge session names)

    def _factory(self, **kw):
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.app), base_url="http://edge", **kw)

    def key(self, step: dict) -> str:
        sess, role = step["session"], self.spec["agents"][step["agent"]]["role"]
        if step.get("fresh") or sess not in self.keys:
            self.keys[sess] = keys.issue(role)
            self.prev.pop(sess, None)
            self.labels[keys.verify(self.keys[sess])[1]] = f"Scenario act {step['act']} ({sess})"
        return self.keys[sess]

    def reset(self) -> None:
        """Fresh mocks, budgets and keys (TOLLGATE taint of scenario keys dropped)."""
        from mocks import files, github, tickets
        github.PRS.clear()
        tickets.reset()
        files.FS.clear()
        files.FS.update(FS0)
        for k in self.keys.values():
            taint.reset(keys.verify(k)[1])
        model_door.USED.clear()
        self.keys.clear()
        self.prev.clear()
        self.results.clear()

    def _last_event(self, key_id: str) -> dict | None:
        from tollgate.gateway import audit
        p = Path(os.environ.get("TOLLGATE_AUDIT") or audit.DEFAULT_PATH)
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        for line in reversed(lines):  # ponytail: full read per step; fine for a demo-sized log
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("key_id") == key_id:
                return ev
        return None

    async def run(self, step_id: str) -> dict:
        step = self.by_id[step_id]
        if step["operator"]:
            return {"id": step_id, "status": "operator", "got": "done in the Server console", "pass": None}
        try:
            got = await self._run(step)
        except Exception as e:  # a step that crashes is a FAIL with the reason, not a 500
            got = {"error": f"{type(e).__name__}: {e}"}
        ok, why = check(step.get("expect") or {}, got)
        res = {"id": step_id, "status": "pass" if ok else "fail", "pass": ok, "expected": expected_words(step["expect"]),
               "got": got_words(got), "why": why, "trace_id": got.get("trace_id"), "session_id": got.get("key_id")}
        self.results[step_id] = res
        return res

    async def _run(self, step: dict) -> dict:
        from mocks.github import PRS
        key = self.key(step)
        role, key_id = keys.verify(key)
        kind = step["kind"]
        if kind == "wrong_url":
            async with self._factory() as c:
                r = await c.post(f"/mcp/{step['url_role']}/", headers={"Authorization": f"Bearer {key}"},
                                 json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            return {"status": r.status_code, "key_id": key_id}
        if kind == "list_tools":
            async with Client(StreamableHttpTransport(f"http://edge/mcp/{role}/", auth=key,
                                                      httpx_client_factory=self._factory)) as c:
                return {"tools": sorted(t.name for t in await c.list_tools()), "key_id": key_id}
        if kind == "call":
            args = {k: self.prev.get(step["session"], "") if v == "$prev" else v for k, v in step["args"].items()}
            prs, text, err = len(PRS), "", None
            async with Client(StreamableHttpTransport(f"http://edge/mcp/{role}/", auth=key,
                                                      httpx_client_factory=self._factory)) as c:
                try:
                    res = await c.call_tool(step["tool"], args)
                    text = "".join(getattr(b, "text", "") for b in res.content)
                    self.prev[step["session"]] = text
                except ToolError as e:
                    err = str(e)
            return {**_event_fields(self._last_event(key_id)), "text": text, "error": err,
                    "new_prs": len(PRS) - prs, "key_id": key_id}
        if kind in ("chat", "chat_until_budget"):
            prompt = step.get("prompt") or "lorem ipsum " * 4000  # ~12k tokens per call: the budget runs out fast
            async with self._factory() as c:
                for _ in range(1 if kind == "chat" else 40):
                    r = await c.post("/v1/chat/completions", headers={"Authorization": f"Bearer {key}"},
                                     json={"model": step["model"], "messages": [{"role": "user", "content": prompt}]})
                    if kind == "chat" or r.status_code == 429:
                        break
            return {**_event_fields(self._last_event(key_id)), "status": r.status_code, "key_id": key_id}
        raise ValueError(f"unknown step kind {kind}")


FS0: dict = {}


def _snapshot_fs():
    from mocks import files
    FS0.update(copy.deepcopy(files.FS))


_snapshot_fs()


def _event_fields(ev: dict | None) -> dict:
    if not ev:
        return {}
    return {"verdict": ev.get("verdict"), "rules": [r.get("rule") for r in ev.get("reasons") or []],
            "state": ev.get("state_after"), "trace_id": ev.get("trace_id")}


def check(e: dict, got: dict) -> tuple[bool, str]:
    """(passed, why not)."""
    if got.get("error") and "verdict" not in got and "tools" not in got and "status" not in got:
        return False, got["error"]
    if "tools" in e and got.get("tools") != sorted(e["tools"]):
        return False, f"tools differ: {got.get('tools')}"
    if "count" in e and (len(got.get("tools") or []) != e["count"] or set(e.get("absent", [])) & set(got["tools"])):
        return False, f"{len(got.get('tools') or [])} tools: {got.get('tools')}"
    if "status" in e and got.get("status", 200) != e["status"]:
        return False, f"HTTP {got.get('status')}"
    if "verdict" in e and got.get("verdict") != e["verdict"]:
        return False, f"verdict {got.get('verdict')}"
    if e.get("rule") and e["rule"] not in (got.get("rules") or []):
        return False, f"rules {got.get('rules')}"
    if e.get("state") and got.get("state") != e["state"]:
        return False, f"session {got.get('state')}"
    missing = [c for c in e.get("contains", []) if c not in (got.get("text") or "")]
    if missing:
        return False, f"missing {missing}"
    if e.get("no_new_pr") and got.get("new_prs"):
        return False, "a PR was created"
    return True, ""


def got_words(g: dict) -> str:
    if "tools" in g:
        return f"{len(g['tools'])} tools: " + ", ".join(g["tools"])
    if g.get("verdict") is None and "status" in g:
        return f"HTTP {g['status']}"
    if g.get("verdict") is None:
        return g.get("error") or "no result"
    parts = [g["verdict"].upper()]
    if g.get("status") not in (None, 200):
        parts.append(f"HTTP {g['status']}")
    main = explain.main_reason({"reasons": [{"rule": r} for r in g.get("rules") or []]})
    if main:
        parts.append(explain.rule(main["rule"])[0].rstrip("."))
    if g.get("state"):
        parts.append("session " + " + ".join(explain.state_words(g["state"])))
    return "; ".join(parts)
