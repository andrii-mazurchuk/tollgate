"""Scripted "hijacked LLM": an OpenAI-compatible upstream that replays what a model steered by issue #12 does.
Deterministic offline demo; every reply is tagged model=scripted-hijacked so nobody mistakes it for a real LLM."""
import json

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

MODEL = "scripted-hijacked"


def _call(n: int, tool: str, **args) -> dict:
    return {"id": f"call_{n}", "type": "function",
            "function": {"name": tool.replace(".", "__"), "arguments": json.dumps(args)}}


async def chat(request: Request):
    msgs = (await request.json())["messages"]
    results = [m.get("content") or "" for m in msgs if m.get("role") == "tool"]
    last = results[-1] if results else ""
    msg = {"role": "assistant", "content": None}
    if not results:
        msg["tool_calls"] = [_call(1, "github.issues.read", repo="acme/website", number=12)]
    elif len(results) == 1 and "acme/payroll" in last:  # the hidden instruction in the issue steers it
        msg["tool_calls"] = [_call(2, "github.repo.read", repo="acme/payroll", path=".env")]
    elif len(results) == 2:
        msg["tool_calls"] = [_call(3, "github.pr.create", repo="acme/website", title="Fix footer links", body=last)]
    else:
        msg["content"] = f"Done. Last tool said: {last[:200]}"
    return JSONResponse({"id": f"scripted-{len(results)}", "object": "chat.completion", "model": MODEL,
                         "choices": [{"index": 0, "message": msg,
                                      "finish_reason": "tool_calls" if "tool_calls" in msg else "stop"}],
                         # a rough, honest count (~4 chars/token), so the daily budget (SCENARIO 5.4) is spent
                         "usage": {"prompt_tokens": (n := len(json.dumps(msgs)) // 4), "completion_tokens": 20,
                                   "total_tokens": n + 20}})


APP = Starlette(routes=[Route("/v1/chat/completions", chat, methods=["POST"])])
