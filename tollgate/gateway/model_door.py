"""Model door: POST /v1/chat/completions, an OpenAI-compatible proxy (Ollama by default) with model allow-list
(AC12), prompt/response scanning, and per-role daily token budgets (AC11)."""
import hashlib
import json
import os
import time
from datetime import datetime, timezone

import httpx2
from fastmcp.exceptions import ToolError
from starlette.requests import Request
from starlette.responses import JSONResponse

from tollgate.content import scan
from tollgate.contract import AuditEvent, Reason
from tollgate.gateway import audit, keys, local_text, taint, trace

DEFAULT_UPSTREAM = "http://127.0.0.1:11434/v1"
USED: dict[tuple[str, str], int] = {}  # (role, UTC day) -> tokens. ponytail: in-memory, lost on restart


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def budget(policy: dict) -> dict:
    """{role: {used, limit}} for today; limit None = unlimited."""
    return {r: {"used": USED.get((r, _today()), 0), "limit": ((rp or {}).get("budget") or {}).get("tokens_per_day")}
            for r, rp in (policy.get("roles") or {}).items()}


def _err(status: int, code: str, msg: str, reasons=()) -> JSONResponse:
    return JSONResponse({"error": {"message": msg, "type": "tollgate", "code": code,
                                   "reasons": [r.__dict__ for r in reasons]}}, status)


def _text(content) -> str:
    """OpenAI content is a string or a list of parts; only text parts are scanned."""
    if isinstance(content, str):
        return content
    return "".join(p.get("text", "") for p in content or [] if isinstance(p, dict))


def _keep(texts: dict, point: str, text: str, v) -> None:
    """Edge-only full text: messages joined per scan point, spans offset into the joined text."""
    t = texts.setdefault(point, {"original": "", "sent": "", "spans": []})
    off = len(t["original"]) + (1 if t["original"] else 0)
    t["spans"] += [[s + off, e + off] for r in v.reasons if r.span for s, e in [r.span]]
    sep = "\n" if t["original"] else ""
    t["original"] += sep + text
    t["sent"] += sep + (v.redacted_text if v.action == "redact" else text)


def build_door(policy, upstream: httpx2.AsyncBaseTransport | None = None):
    """Starlette endpoint. `upstream` is a test transport; the URL comes from TOLLGATE_UPSTREAM."""
    from tollgate.gateway import apply_verdict, content_policy  # late: avoids a cycle with gateway/__init__

    async def chat(request: Request):
        ident = keys.from_header(request.headers.get("authorization"))
        if not ident:
            return JSONResponse({"error": {"message": "invalid key", "code": "auth.invalid"}}, 401)
        role, key_id = ident
        try:
            body = await request.json()
        except ValueError:
            return _err(400, "request.invalid", "body must be JSON")
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            return _err(400, "request.invalid", "need {model, messages: [...]}")
        if body.get("stream"):
            return _err(400, "request.stream", "stream: true is not supported yet; send stream: false")

        data = policy.data
        rp = (data.get("roles") or {}).get(role) or {}
        model = body.get("model")
        # every role: an injected `assistant`/`tool`/`developer` message reaches the model just the same
        prompt = "\n".join(_text(m.get("content")) for m in body["messages"] if isinstance(m, dict))
        ev = AuditEvent(ts=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                        role=role, key_id=key_id, door="model", verdict="allow", scan_point="prompt",
                        source="model", tool=str(model),
                        content_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
                        policy_version=policy.version, trace_id=trace.new_id(), session_id=key_id)
        ev.state_before = ev.state_after = trace.label(taint.STATE.get(key_id))  # the model door never changes taint
        texts: dict = {}

        def deny(status, rule, msg):
            ev.verdict = "block"
            ev.reasons.append(Reason(rule=rule, tier=0, detail=msg))
            return _err(status, rule, f"{rule}: {msg}", ev.reasons)

        try:
            t0 = time.perf_counter()
            if role not in (data.get("roles") or {}):
                return deny(403, "role.denied", f"unknown role {role}")
            if model not in (rp.get("models") or []):
                return deny(403, "model.denied", f"{model} is not allowed for {role}")
            limit = (rp.get("budget") or {}).get("tokens_per_day")
            if limit is not None and USED.get((role, _today()), 0) >= limit:
                return deny(429, "budget.exceeded", f"{role} used {USED[(role, _today())]} of {limit} tokens today")
            ev.latency_ms["role"] = round((time.perf_counter() - t0) * 1000, 3)

            cpol = content_policy(data, rp)
            try:
                # per message, so a redaction lands back in the message it came from
                for m in body["messages"]:
                    if isinstance(m, dict):
                        v = scan(_text(m.get("content")), "prompt", cpol)
                        _keep(texts, "prompt", _text(m.get("content")), v)
                        apply_verdict(ev, v, "prompt")
                        if v.action == "redact":
                            m["content"] = v.redacted_text
            except ToolError as e:
                return _err(400, "content.blocked", str(e), ev.reasons)

            base, transport = os.environ.get("TOLLGATE_UPSTREAM") or DEFAULT_UPSTREAM, upstream
            if base == "scripted":  # offline demo: in-process hijacked-LLM replay, tagged model=scripted-hijacked
                from tollgate.agent.scripted import APP
                base, transport = "http://scripted/v1", httpx2.ASGITransport(app=APP)
            try:
                async with httpx2.AsyncClient(transport=transport, timeout=300) as c:
                    r = await c.post(f"{base.rstrip('/')}/chat/completions", json=body)
                out = r.json()
            except (httpx2.HTTPError, ValueError) as e:
                return deny(502, "upstream.error", f"{base}: {type(e).__name__}: {e}")
            if r.status_code != 200:
                return JSONResponse(out, r.status_code)

            if not isinstance(out, dict):
                return deny(502, "upstream.error", f"{base}: reply is not a JSON object")
            used = (out.get("usage") or {}).get("total_tokens") if isinstance(out.get("usage"), dict) else None
            if not isinstance(used, int) or isinstance(used, bool) or used < 0:  # no refunds, no free calls
                used = max(1, (len(json.dumps(body)) + len(json.dumps(out))) // 4)  # ponytail: ~4 chars/token
            ev.tokens = used
            USED[(role, _today())] = USED.get((role, _today()), 0) + ev.tokens  # charged even if the reply is blocked
            try:
                for ch in out.get("choices") or []:
                    msg = ch.get("message") or {}
                    v = scan(_text(msg.get("content")), "response", cpol)
                    _keep(texts, "response", _text(msg.get("content")), v)
                    apply_verdict(ev, v, "response")
                    if v.action == "redact":
                        msg["content"] = v.redacted_text
            except ToolError as e:
                return _err(400, "content.blocked", str(e), ev.reasons)
            if ev.verdict == "allow":
                ev.scan_point = "response"
            return JSONResponse(out)
        finally:
            audit.write(ev)
            local_text.write(ev.trace_id, texts)

    return chat
