"""Demo agent: a minimal tool-calling loop that only talks to Tollgate's two doors (model + role MCP), no framework."""
import json

import httpx2
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

SYSTEM = ("You are a dev assistant with GitHub tools. Use tools to complete the task. "
          "Act, do not ask questions. /no_think")
MAX_TURNS = 8


def _fn(name: str) -> str:  # OpenAI function names allow [a-zA-Z0-9_-] only
    return name.replace(".", "__")


def _tool(fn: str) -> str:
    return fn.replace("__", ".")


def _short(v, n: int = 80) -> str:
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    s = " ".join(s.split())  # one line per step
    return s if len(s) <= n else s[:n] + "..."


async def run(task: str, role: str, model: str, base: str, key: str, factory=None, log=print) -> list[dict]:
    """Runs the loop; returns [{tool, args, verdict: allow|block, text}]. `factory` = httpx client factory (tests)."""
    base = base.rstrip("/")
    mk = factory or httpx2.AsyncClient
    steps: list[dict] = []
    transport = StreamableHttpTransport(f"{base}/mcp/{role}/", auth=key,
                                        **({"httpx_client_factory": factory} if factory else {}))
    async with Client(transport) as mcp, mk(timeout=300) as http:
        tools = [{"type": "function", "function": {"name": _fn(t.name), "description": t.description or "",
                                                   "parameters": t.input_schema}} for t in await mcp.list_tools()]
        log(f"[agent] {role} sees {len(tools)} tools: {', '.join(_tool(t['function']['name']) for t in tools)}")
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task}]
        for turn in range(1, MAX_TURNS + 1):
            r = await http.post(f"{base}/v1/chat/completions", headers={"Authorization": f"Bearer {key}"},
                                json={"model": model, "messages": msgs, "tools": tools, "stream": False})
            out = r.json()
            if r.status_code != 200:
                log(f"[model door] BLOCKED {r.status_code}: {_short((out.get('error') or out), 200)}")
                return steps
            msg = out["choices"][0]["message"]
            calls = msg.get("tool_calls") or []
            log(f"[turn {turn}] model={out.get('model')} -> "
                + (", ".join(_tool(c["function"]["name"]) for c in calls) if calls else "final answer"))
            if not calls:
                log(f"[answer] {(msg.get('content') or '').strip()}")
                return steps
            msgs.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
            for c in calls:
                name, args = _tool(c["function"]["name"]), c["function"].get("arguments") or {}
                try:
                    args = json.loads(args) if isinstance(args, str) else args
                    res = await mcp.call_tool(name, args)
                    text, verdict = "".join(getattr(b, "text", "") for b in res.content), "allow"
                except ToolError as e:  # blocked (taint.flow, role.denied, ...) or tool failure: the model sees it
                    text, verdict = f"ERROR: {e}", "block"
                except Exception as e:  # bad JSON args, unknown tool: not a Tollgate verdict
                    text, verdict = f"ERROR: {type(e).__name__}: {e}", "error"
                steps.append({"tool": name, "args": args, "verdict": verdict, "text": text})
                log(f"  -> {name} {_short(args)}")
                log(f"     Tollgate: {dict(allow='ALLOWED', block='BLOCKED').get(verdict, 'ERROR')}  {_short(text, 160)}")
                msgs.append({"role": "tool", "tool_call_id": c.get("id", name), "content": text})
        log(f"[agent] stopped after {MAX_TURNS} turns")
    return steps
