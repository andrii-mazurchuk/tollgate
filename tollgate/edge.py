"""Local edge UI: static app at /edge, JSON API at /edge/api/ (read-only except the scenario and local settings),
SSE of new trace ids.

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


_CACHE: dict = {}


def load_events() -> list[dict]:
    """Audit events, re-parsed only when the file's (path, mtime, size) changes. Callers must not mutate the list."""
    p = Path(os.environ.get("TOLLGATE_AUDIT") or audit.DEFAULT_PATH)
    try:
        st = p.stat()
        sig = (str(p), st.st_mtime_ns, st.st_size)
        if _CACHE.get("sig") == sig:
            return _CACHE["events"]
        lines = p.read_text(encoding="utf-8").splitlines()
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
    _CACHE.update(sig=sig, events=out)
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
                    "tools": tools, "duration_s": (_ts(last) - _ts(evs[0])).total_seconds(), "counts": {a: c.get(a, 0) for a in ACTIONS}, "n": len(evs)})
    return sorted(out, key=lambda s: s["last_ts"], reverse=True)


def timeline(events: list[dict], sid: str, texts: dict | None = None) -> list[dict]:
    """Oldest first: each event with its plain explanation, check chain and local full text."""
    texts = texts or {}
    out = []
    for e in sorted((e for e in events if _sid(e) == sid), key=_ts):
        out.append({**e, "explain": explain.event(e), "text": texts.get(e.get("trace_id")), "kind": kind(e),
                    "action": action_words(e) if kind(e) else None,
                    "ms": round(sum(st.get("ms") or 0 for st in e.get("stages") or []), 1),
                    "state_words_before": explain.state_words(e.get("state_before")),
                    "state_words_after": explain.state_words(_state(e))})
    return out


FLAG = ("inj.", "t2.", "sig.")


def kind(ev: dict) -> str | None:
    """blocked | masked | waiting | flagged (went through, but injection-like text) | None (nothing to see)."""
    v = ev.get("verdict")
    if v in ("block", "redact", "approve"):
        return {"block": "blocked", "redact": "masked", "approve": "waiting"}[v]
    r = explain.main_reason(ev)
    return "flagged" if r and r["rule"].startswith(FLAG) else None


def action_words(ev: dict) -> str:
    """'Data-flow rule: blocked', 'Secret detector: masked 2 values', 'Injection check: flagged'."""
    r, k = explain.main_reason(ev), kind(ev)
    name = explain.check_name(r and r["rule"])
    if k == "masked":
        n = sum((x.get("rule") or "").startswith(("secret.", "pii.")) for x in ev.get("reasons") or []) or 1
        return f"{name}: masked {n} value{'s' * (n != 1)}"
    return f"{name}: " + {"blocked": "blocked", "waiting": "held for approval", "flagged": "flagged"}.get(k, "passed")


RANGES = {"15m": 900, "1h": 3600}
BUCKETS = (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 3 * 3600, 6 * 3600, 12 * 3600, 86400)


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat().replace("+00:00", "Z")


def window(rng: str, now: datetime) -> tuple[datetime | None, tuple[datetime, datetime] | None]:
    """(start of the range, the previous equal period) for 15m | 1h | today (local midnight) | all."""
    if rng in RANGES:
        d = timedelta(seconds=RANGES[rng])
        return now - d, (now - 2 * d, now - d)
    if rng == "today":
        start = now.astimezone().replace(hour=0, minute=0, second=0, microsecond=0)
        return start, (start - timedelta(days=1), now - timedelta(days=1))
    return None, None


def _in(events, a, b) -> list[dict]:
    return [e for e in events if (a is None or _ts(e) >= a) and _ts(e) <= b]


def series(events: list[dict], start: datetime | None, now: datetime) -> tuple[list[dict], int]:
    """Buckets from the range and the data spread: the chart spans the data in the range (first event to a little
    after the last, at least 30 s) in 20-40 bars, so a burst of a few seconds is not one lonely bar in an empty hour."""
    if not events:
        return [], 60
    first, last = min(map(_ts, events)), max(map(_ts, events))
    a = max(start, first) if start else first
    end = min(now, last + max(timedelta(seconds=10), (last - a) / 4))
    span = max(30.0, (end - a).total_seconds())
    b = next((x for x in BUCKETS if span / x <= 40), 86400 * math.ceil(span / 86400 / 40))
    t0 = a.timestamp() // b * b
    rows = [{"t": _iso(t0 + i * b), **dict.fromkeys(ACTIONS, 0)} for i in range(int((a.timestamp() + span - t0) // b) + 1)]
    for e in events:
        i = int((_ts(e).timestamp() - t0) // b)
        if 0 <= i < len(rows):
            rows[i][e.get("verdict", "allow")] += 1
    return rows, b


def _kpis(evs: list[dict]) -> dict:
    c = Counter(e.get("verdict") for e in evs)
    return {"checked": len(evs), "blocked": c.get("block", 0), "masked": c.get("redact", 0),
            "sessions": len({_sid(e) for e in evs})}


def _item(e: dict, labels: dict | None = None) -> dict:
    return {"ts": e["ts"], "kind": kind(e), "action": action_words(e), "sentence": explain.event(e)["sentence"],
            "check": explain.check_name((explain.main_reason(e) or {}).get("rule")), "role": e.get("role"),
            "agent": explain.AGENTS.get(e.get("role"), e.get("role")),
            "tool": explain.tool(e.get("tool"), e.get("door", "tool")),
            "session_id": _sid(e), "session_label": (labels or {}).get(_sid(e)), "trace_id": e.get("trace_id")}


def overview(events: list[dict], rng: str = "today", labels: dict | None = None, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    start, prev = window(rng, now)
    cur = _in(events, start, now)
    k, p = _kpis(cur), (_kpis(_in(events, *prev)) if prev else None)
    rows, b = series(cur, start, now)
    reasons, tools = Counter(), Counter()
    for e in cur:
        tools[explain.tool(e.get("tool"), e.get("door", "tool"))] += 1
        r = explain.main_reason(e)
        if r and kind(e):
            reasons[explain.rule(r["rule"])[0]] += 1
    look = sorted((e for e in cur if kind(e) in ("blocked", "flagged", "waiting")), key=_ts, reverse=True)[:6]
    return {"range": rng, "start": start and start.isoformat(), "now": now.isoformat(), "bucket_s": b, "series": rows,
            "kpis": {n: {"value": k[n], "prev": p[n] if p else None} for n in k},
            "top_reasons": [{"label": r, "count": n} for r, n in reasons.most_common(6)],
            "top_tools": [{"name": t, "count": n} for t, n in tools.most_common(8)],
            "needs_look": [_item(e, labels) for e in look]}


def events_list(events: list[dict], rng: str = "today", filters: dict | None = None, labels: dict | None = None,
                now: datetime | None = None) -> dict:
    """Blocked/masked/waiting/flagged only, newest first; filters action|agent(role)|check are ANDed."""
    now = now or datetime.now(timezone.utc)
    items = [_item(e, labels) for e in sorted(_in(events, window(rng, now)[0], now), key=_ts, reverse=True) if kind(e)]
    facets = {"action": sorted({x["kind"] for x in items}), "agent": sorted({x["role"] for x in items if x["role"]}),
              "check": sorted({x["check"] for x in items}), "names": {x["role"]: x["agent"] for x in items}}
    f = {"action": "kind", "agent": "role", "check": "check"}
    for k, v in (filters or {}).items():
        if k in f and v:
            items = [x for x in items if x[f[k]] == v]
    return {"items": items[:500], "facets": facets}


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


LABEL_WORDS = {"untrusted_source": "outside text", "private_data": "private data", "public_sink": "public destination"}
LABEL_WHY = {"untrusted_source": "anyone outside can write this text", "private_data": "returns company or customer data",
             "public_sink": "what it writes can be seen outside the company"}
ACTION_WORDS = {"block": "block", "approve": "ask a human", "redact": "mask", "allow": "allow"}
PII = {"iban": "IBANs", "pesel": "PESEL numbers", "nip": "NIP tax ids", "card": "card numbers", "email": "email addresses"}


def limit_words(arg: str, rule: str) -> str:
    if rule == "select_only":
        return f"{arg}: a single SELECT only"
    if arg == "to_domain":
        return f"recipients @{rule.lstrip('@')} only"
    return f"{arg}: only {rule.removesuffix('/**')}" + (" and below" if rule.endswith("/**") else "")


def agent(data: dict, role: str, source_tools: dict, feed_state: dict, used: dict) -> dict:
    """Everything about how this role's agent is set up, from the live policy and each source's own tool list."""
    from tollgate.gateway import content_policy, tool_allowed
    from types import SimpleNamespace
    rp = (data.get("roles") or {}).get(role) or {}
    constrain, approval = rp.get("constrain") or {}, set(rp.get("approval") or [])
    servers = []
    for srv, tools in source_tools.items():
        allowed, denied = [], []
        for t in tools:
            name = f"{srv}.{t.name.replace('_', '.')}"
            ro = bool(t.annotations and t.annotations.read_only_hint)
            item = {"name": name, "plain": explain.tool(name), "write": not ro}
            if tool_allowed(rp, SimpleNamespace(name=name, annotations=t.annotations)):
                lim = [limit_words(a, r) for a, r in (constrain.get(name) or {}).items()]
                allowed.append({**item, "limits": lim + (["asks a human first"] if name in approval else [])})
            else:
                denied.append(item)
        spec = (rp.get("servers") or {}).get(srv) or {}
        servers.append({"name": srv, "reachable": bool(spec), "access": spec.get("access") or "picked tools" if spec else None,
                        "allowed": allowed, "denied": denied})
    flow = (data.get("taint") or {}).get("block_flow") or {}
    on = (data.get("taint") or {}).get("enabled", True)
    act = ACTION_WORDS.get(flow.get("action", "block"), "block")
    labels = [{"tool": t, "plain": explain.tool(t), "labels": ls, "words": [LABEL_WORDS[x] for x in ls],
               "why": "; ".join(LABEL_WHY[x] for x in ls)} for t, ls in (data.get("labels") or {}).items()
              if any(t.startswith(s["name"] + ".") and s["reachable"] for s in servers)]
    c = content_policy(data, rp)
    acts = {**{PII.get(k, k): v for k, v in (c.get("pii") or {}).items()}, "Secrets": c.get("secrets", "block")}
    inj = c.get("injection") or {}
    lo, hi = inj.get("low", 0.5), inj.get("high", 0.9)
    sig_path = Path(c.get("signatures") or "signatures.yaml")
    try:
        import yaml
        n_sig = len(yaml.safe_load(sig_path.read_text(encoding="utf-8")) or [])
    except (OSError, ValueError, TypeError):
        n_sig = 0
    return {
        "role": role, "agent": explain.AGENTS.get(role, role), "servers": servers,
        "models": rp.get("models") or [], "budget": used,
        "labels": labels,
        "flow_rule": {"enabled": on, "action": flow.get("action", "block"),
                      "sentence": (f"When a session has read outside text and holds private data, a call to a public "
                                   f"destination is {'blocked' if act == 'block' else 'held until a human approves'}.")
                      if on else "Off: sessions are not tracked, only the role limits apply."},
        "content": {"masked": [k for k, v in acts.items() if v == "redact"],
                    "blocked": [k for k, v in acts.items() if v == "block"],
                    "asks": [k for k, v in acts.items() if v == "approve"],
                    "injection": {"profile": data.get("mode"), "low": lo, "high": hi,
                                  "words": f"Blocks when the classifier is at least {round(hi * 100)}% sure; "
                                           + (f"flags from {round(lo * 100)}%." if lo < hi else "below that, text passes.")
                                           + (" Hidden links that leak data are blocked." if inj.get("md_exfil", "block") == "block" else "")},
                    "signatures": {"version": feed_state.get("version"), "count": n_sig,
                                   "source": "threat feed" if feed_state.get("url") else "local file"}},
        "policy": {"profile": data.get("mode"), "managed_by": "your security team"},
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

    def rng(request) -> str:
        r = request.query_params.get("range", "today")
        return r if r in ("15m", "1h", "today", "all") else "today"

    async def get_overview(request):
        return JSONResponse(overview(load_events(), rng(request), labels(request)))

    async def get_events(request):
        q = request.query_params
        return JSONResponse(events_list(load_events(), rng(request), {k: q.get(k) for k in ("action", "agent", "check")},
                                        labels(request)))

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

    async def get_agent(request):
        from tollgate.gateway import model_door
        role = (keys.verify(edge_key()) or ("role-2",))[0]
        st = request.app.state
        tools = {n: await src.list_tools() for n, src in (getattr(st, "sources", None) or {}).items()}
        data = policy.data
        a = agent(data, role, tools, st.feed.state, model_door.budget(data).get(role) or {})
        a["policy"]["version"] = policy.status()["version"]
        return JSONResponse(a)

    def settings_view():
        return {"settings": local_text.settings(), "ceiling": local_text.ceiling(policy.data),
                "path": str(local_text.settings_path())}

    async def settings(request):
        if request.method == "POST":
            try:
                new = local_text.check_settings(await request.json(), local_text.ceiling(policy.data))
            except ValueError as e:
                return JSONResponse({"error": str(e) or "need a JSON object"}, 400)
            local_text.save_settings(new)
        return JSONResponse(settings_view())

    async def stream(request):
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
           Route("/sessions/{id}", local(one_session)), Route("/overview", local(get_overview)),
           Route("/events", local(get_events)),
           Route("/setup", local(setup)), Route("/agent", local(get_agent)),
           Route("/settings", local(settings), methods=["GET", "POST"]), Route("/setup/test", local(setup_test)), Route("/stream", local(stream)),
           Route("/scenario", local(get_scenario)), Route("/scenario/run/{step}", local(run_step), methods=["POST"]),
           Route("/scenario/reset", local(reset), methods=["POST"])]
    return [Mount("/edge/api", routes=api), Route("/edge", lambda r: RedirectResponse("/edge/")),
            Mount("/edge", app=StaticFiles(directory=UI, html=True))]
