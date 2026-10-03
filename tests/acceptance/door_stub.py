"""Stub OpenAI-compatible upstream for model door tests (no Ollama). Echoes the last user message."""
import httpx2
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

SEEN: list[dict] = []  # (headers, body) the upstream received
TOKENS = 600


async def chat(request: Request):
    body = await request.json()
    SEEN.append({"headers": dict(request.headers), **body})
    text = next(m["content"] for m in reversed(body["messages"]) if m["role"] == "user")
    if "leak" in text:
        text = "sure: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    return JSONResponse({"id": "c1", "object": "chat.completion", "model": body["model"],
                         "choices": [{"index": 0, "message": {"role": "assistant", "content": f"echo: {text}"},
                                      "finish_reason": "stop"}],
                         "usage": {"prompt_tokens": TOKENS // 2, "completion_tokens": TOKENS // 2,
                                   "total_tokens": TOKENS}})


STUB = Starlette(routes=[Route("/v1/chat/completions", chat, methods=["POST"])])


def door(policy_data: dict, monkeypatch, tmp_path):
    """(app, client factory) for a gateway whose model door forwards to the stub."""
    from tollgate.gateway import build_app
    from tollgate.gateway.policy import PolicyHolder

    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "events.jsonl"))
    monkeypatch.setenv("TOLLGATE_UPSTREAM", "http://stub/v1")
    SEEN.clear()
    app = build_app(PolicyHolder(policy_data), upstream=httpx2.ASGITransport(app=STUB))

    def client():
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://t")
    return app, client


def ask(model: str, text: str, **extra) -> dict:
    return {"model": model, "messages": [{"role": "system", "content": "be brief"},
                                         {"role": "user", "content": text}], **extra}
