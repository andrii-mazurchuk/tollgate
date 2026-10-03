"""Local edge UI: static app at /edge, JSON API at /edge/api/ (read-only except the scenario), SSE of new trace ids.

Loopback only: the API serves full local text and the edge key. Sessions = role keys (taint is keyed by key)."""
import asyncio
import json
import math
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from tollgate import explain, scenario
from tollgate.gateway import audit, keys, local_text

UI = Path(__file__).resolve().parent / "ui" / "edge"
ACTIONS = ("allow", "redact", "approve", "block")
ACTIVE_MIN = 15  # a session with no action for this long shows as ended


def version() -> str:
    try:
        from importlib.metadata import version as v
        return v("tollgate")
    except Exception:
        return "0.1.0"


def edge_key() -> str:
    """The developer's agent key: TOLLGATE_EDGE_KEY, else a stable key for TOLLGATE_EDGE_ROLE (default role-2)."""
    return os.environ.get("TOLLGATE_EDGE_KEY") or keys.issue(os.environ.get("TOLLGATE_EDGE_ROLE", "role-2"), "edge")


def load_events() -> list[dict]:
    try:
        lines = Path(os.environ.get("TOLLGATE_AUDIT") or audit.DEFAULT_PATH).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if isinstance(ev, dict) and "ts" in ev:
            out.append(ev)
    return out


def _ts(ev: dict) -> datetime:
    return datetime.fromisoformat(ev["ts"].replace("Z", "+00:00"))


def _sid(ev: dict) -> str:
    return ev.get("session_id") or ev.get("key_id") or "?"


def _state(ev: dict) -> str:
    """state_after, or the pre-trace flags of older events."""
    if ev.get("state_after"):
        return ev["state_after"]
    return "+".join(n for n, f in (("untrusted", "tainted"), ("holds_private", "holds_private")) if ev.get(f)) or "clean"


def sessions(events: list[dict], labels: dict | None = None, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    groups: dict[str, list] = {}
    for e in events:
        groups.setdefault(_sid(e), []).append(e)
    out = []
    for sid, evs in groups.items():
        evs.sort(key=_ts)
        last, c = evs[-1], Counter(e.get("verdict") for e in evs)
        tools = list(dict.fromkeys(explain.tool(e.get("tool"), e.get("door", "tool")) for e in evs))
        out.append({"id": sid, "role": last.get("role"), "agent": explain.AGENTS.get(last.get("role"), last.get("role")),
                    "label": (labels or {}).get(sid), "first_ts": evs[0]["ts"], "last_ts": last["ts"],
                    "active": now - _ts(last) < timedelta(minutes=ACTIVE_MIN), "state": _state(last),
                    "state_words": explain.state_words(_state(last)), "last_verdict": last.get("verdict"),
                    "tools": tools, "counts": {a: c.get(a, 0) for a in ACTIONS}, "n": len(evs)})
    return sorted(out, key=lambda s: s["last_ts"], reverse=True)


def timeline(events: list[dict], sid: str, texts: dict | None = None) -> list[dict]:
    """Oldest first: each event with its plain explanation, check chain and local full text."""
    texts = texts or {}
    out = []
    for e in sorted((e for e in events if _sid(e) == sid), key=_ts):
        out.append({**e, "explain": explain.event(e), "text": texts.get(e.get("trace_id")),
                    "state_words_before": explain.state_words(e.get("state_before")),
                    "state_words_after": explain.state_words(_state(e))})
    return out


def _bucket(span_s: float) -> int:
    for b in (60, 300, 900, 3600, 4 * 3600, 86400):
        if span_s / b <= 30:
            return b
    return 86400 * math.ceil(span_s / 86400 / 30)


def analytics(events: list[dict], labels: dict | None = None) -> dict:
    if not events:
        return {"series": [], "bucket_s": 60, "totals": dict.fromkeys(ACTIONS, 0), "blocked": 0, "masked": 0,
                "top_reasons": [], "per_session": [], "n": 0}
    events = sorted(events, key=_ts)
    span = (_ts(events[-1]) - _ts(events[0])).total_seconds()
    b = _bucket(span)
    rows: dict[float, dict] = {}
    for e in events:
        t = _ts(e).timestamp() // b * b
        rows.setdefault(t, {"t": datetime.fromtimestamp(t, timezone.utc).isoformat().replace("+00:00", "Z"),
                            **dict.fromkeys(ACTIONS, 0)})[e.get("verdict", "allow")] += 1
    totals = Counter(e.get("verdict") for e in events)
    reasons = Counter()
    for e in events:
        r = explain.main_reason(e)
        if r and (e.get("verdict") != "allow" or r["rule"].startswith(("inj.", "t2."))):
            reasons[r["rule"].split(".")[0] + "." if r["rule"].startswith("sig.") else r["rule"]] += 1
    return {"series": [rows[k] for k in sorted(rows)], "bucket_s": b,
            "totals": {a: totals.get(a, 0) for a in ACTIONS}, "blocked": totals.get("block", 0),
            "masked": totals.get("redact", 0), "n": len(events),
            "top_reasons": [{"rule": r, "label": explain.rule(r)[0], "count": n} for r, n in reasons.most_common(8)],
            "per_session": [{"id": s["id"], "agent": s["agent"], "label": s["label"], "counts": s["counts"]}
                            for s in sessions(events, labels)][:12]}


def health(events: list[dict], policy, pins, feed, since: str | None) -> dict:
    """ok, or attention with a short message and what to open: policy rejected, pin alert, a blocked/waiting action."""
    st = policy.status()
    if st.get("last_error"):
        return {"level": "alert", "message": "Policy change rejected", "detail": st["last_error"]["message"]}
    if pins and pins.alerts:
        return {"level": "alert", "message": "A tool changed on the server", "detail": next(iter(pins.alerts.values()))}
    fs = feed.state if feed else {}
    if fs.get("url") and fs.get("last_error"):
        return {"level": "warn", "message": "Threat feed unreachable", "detail": fs["last_error"]}
    cut = since or ""
    hits = [e for e in events if e.get("verdict") in ("block", "approve") and e["ts"] > cut]
    if hits:
        last = max(hits, key=_ts)
        n_block = sum(e["verdict"] == "block" for e in hits)
        msg = (f"{n_block} action{'s' * (n_block != 1)} blocked" if n_block else "Waiting for approval")
        return {"level": "warn" if last["verdict"] == "approve" else "alert", "message": msg, "ts": last["ts"],
                "trace_id": last.get("trace_id"), "session_id": _sid(last)}
    return {"level": "ok", "message": "All good"}


def classifier() -> str:
    from tollgate.content import tier2
    if os.environ.get("TOLLGATE_T2") == "off" or tier2._model is False:
        return "off"
    return "ready" if tier2._model else "loads on first use"


def mask(key: str) -> str:
    return key[:8] + "…" + key[-4:]


SNIPPETS = {
    "Claude Code": 'claude mcp add --transport http tollgate {mcp} --header "Authorization: Bearer {KEY}"',
    "Cursor": json.dumps({"mcpServers": {"tollgate": {"url": "{mcp}", "headers": {"Authorization": "Bearer {KEY}"}}}},
                         indent=2),
    "OpenAI SDK": 'from openai import OpenAI\n\nclient = OpenAI(base_url="{v1}", api_key="{KEY}")\n'
                  'client.chat.completions.create(model="{model}", messages=[{{"role": "user", "content": "Hi"}}])',
}


def routes(policy) -> list:
    def local(view):
        async def h(request: Request):
            if not (request.client and request.client.host in ("127.0.0.1", "::1", "localhost", "testclient")):
                return JSONResponse({"error": "the edge UI is local only"}, 403)
            return await view(request)
        return h

    def runner(request) -> scenario.Runner:
        st = request.app.state
        if getattr(st, "scenario", None) is None:
            st.scenario = scenario.Runner(request.app)
        return st.scenario

    def labels(request) -> dict:
        r = getattr(request.app.state, "scenario", None)
        key_id = keys.verify(edge_key())
        return {**(r.labels if r else {}), **({key_id[1]: "Your agent"} if key_id else {})}

    async def status(request):
        key = edge_key()
        role, key_id = keys.verify(key) or ("?", "?")
        st, base = policy.status(), str(request.base_url).rstrip("/")
        fs = request.app.state.feed.state
        return JSONResponse({
            "account": {"role": role, "agent": explain.AGENTS.get(role, role), "key_id": key_id},
            "server": {"url": base, "connected": True}, "app_version": version(),
            "policy": {"version": st["version"], "profile": policy.data.get("mode"), "error": st["last_error"]},
            "feed": {"version": fs.get("version"), "url": fs.get("url"), "error": fs.get("last_error")},
            "classifier": classifier(),
            "health": health(load_events(), policy, request.app.state.pins, request.app.state.feed,
                             request.query_params.get("since"))})

    async def list_sessions(request):
        return JSONResponse({"sessions": sessions(load_events(), labels(request))})

    async def one_session(request):
        sid, evs = request.path_params["id"], load_events()
        meta = next((s for s in sessions(evs, labels(request)) if s["id"] == sid), None)
        if meta is None:
            return JSONResponse({"error": "unknown session"}, 404)
        return JSONResponse({"session": meta, "timeline": timeline(evs, sid, local_text.load())})

    async def get_analytics(request):
        return JSONResponse(analytics(load_events(), labels(request)))

    async def setup(request):
        key, base = edge_key(), str(request.base_url).rstrip("/")
        role = (keys.verify(key) or ("role-2",))[0]
        mcp, v1 = f"{base}/mcp/{role}/", f"{base}/v1"
        model = ((policy.data.get("roles") or {}).get(role) or {}).get("models", ["qwen3:4b"])[0]
        return JSONResponse({"server": base, "mcp_url": mcp, "model_url": v1, "role": role,
                             "agent": explain.AGENTS.get(role, role), "key": key, "key_masked": mask(key),
                             "snippets": {k: s.replace("{mcp}", mcp).replace("{v1}", v1).replace("{model}", model)
                                          .replace("{{", "{").replace("}}", "}") for k, s in SNIPPETS.items()}})

    async def setup_test(request):
        from fastmcp import Client
        from fastmcp.client.transports import StreamableHttpTransport
        import httpx2
        key = edge_key()
        role = keys.verify(key)[0]

        def factory(**kw):
            return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=request.app), base_url="http://edge", **kw)
        try:
            async with Client(StreamableHttpTransport(f"http://edge/mcp/{role}/", auth=key,
                                                      httpx_client_factory=factory)) as c:
                tools = sorted(t.name for t in await c.list_tools())
        except Exception as e:
            return JSONResponse({"ok": False, "error": f"{type(e).__name__}: {e}"})
        return JSONResponse({"ok": True, "tools": [{"name": t, "plain": explain.tool(t)} for t in tools]})

    async def events(request):
        q: asyncio.Queue = asyncio.Queue()
        audit.LISTENERS.add(q)

        async def gen():
            try:
                yield "retry: 2000\n\n"
                while True:
                    try:
                        tid = await asyncio.wait_for(q.get(), 15)
                        yield f"data: {json.dumps({'trace_id': tid})}\n\n"
                    except TimeoutError:
                        yield ": ping\n\n"
            finally:
                audit.LISTENERS.discard(q)
        return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    async def get_scenario(request):
        r = runner(request)
        acts = []
        for act in r.spec["acts"]:
            ss = [s for s in scenario.steps(r.spec) if s["act"] == act["id"]]
            acts.append({"id": act["id"], "title": act["title"], "subtitle": act.get("subtitle"),
                         "operator": bool(act.get("operator")),
                         "steps": [{"id": s["id"], "text": s["text"], "operator": s["operator"], "needs": s.get("needs"),
                                    "agent": r.spec["agents"][s["agent"]]["name"] if s.get("agent") else "Operator",
                                    "expected": scenario.expected_words(s["expect"]) if s.get("expect") else None,
                                    "result": r.results.get(s["id"])} for s in ss]})
        return JSONResponse({"acts": acts})

    async def run_step(request):
        r = runner(request)
        if request.path_params["step"] not in r.by_id:
            return JSONResponse({"error": "unknown step"}, 404)
        return JSONResponse(await r.run(request.path_params["step"]))

    async def reset(request):
        runner(request).reset()
        return JSONResponse({"ok": True})

    api = [Route("/status", local(status)), Route("/sessions", local(list_sessions)),
           Route("/sessions/{id}", local(one_session)), Route("/analytics", local(get_analytics)),
           Route("/setup", local(setup)), Route("/setup/test", local(setup_test)), Route("/events", local(events)),
           Route("/scenario", local(get_scenario)), Route("/scenario/run/{step}", local(run_step), methods=["POST"]),
           Route("/scenario/reset", local(reset), methods=["POST"])]
    return [Mount("/edge/api", routes=api), Route("/edge", lambda r: RedirectResponse("/edge/")),
            Mount("/edge", app=StaticFiles(directory=UI, html=True))]
