"""Server console (docs/ui-spec.md "Server console, revision 1"): static app at /console, JSON API at /console/api/*.

Loopback or the admin token, like /admin/*. The hub never serves text: sessions/{id} drops `text`, keeps the
fingerprint. Numbers come from the audit log; peers from the registry (gateway/peers.py)."""
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from tollgate import edge, explain
from tollgate.gateway import model_door, peers
from tollgate.gateway.approvals import admin_ok, admin_request

UI = Path(__file__).resolve().parent / "ui" / "console"
ONLINE = timedelta(minutes=5)
ATTACK = ("inj.", "t2.", "sig.", "taint.")
UNENROLLED = "unenrolled"  # the id of the row grouping legacy keys (no peer)


def is_attack(e: dict) -> bool:
    """A blocked injection, threat-feed signature or data-flow event."""
    return e.get("verdict") == "block" and any((r.get("rule") or "").startswith(ATTACK) for r in e.get("reasons") or [])


def pid(e: dict) -> str:
    return peers.peer_of(e.get("key_id") or "") or UNENROLLED


def _with_peer(x: dict, key_id: str, reg: dict) -> dict:
    p = peers.peer_of(key_id or "")
    return {**x, "peer": p or UNENROLLED, "peer_label": peers.label(p, reg)}


def _online(events: list[dict]) -> dict[str, str]:
    """peer id -> newest event ts, for every peer seen."""
    last: dict[str, str] = {}
    for e in events:
        k = pid(e)
        if e["ts"] > last.get(k, ""):
            last[k] = e["ts"]
    return last


def peer_rows(events: list[dict], reg: dict, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    last, by = _online(events), {}
    for e in events:
        by.setdefault(pid(e), []).append(e)
    ids = list(reg["peers"]) + ([UNENROLLED] if UNENROLLED in by else [])
    out = []
    for i in ids:
        p, evs = reg["peers"].get(i) or {}, by.get(i, [])
        seen = last.get(i)
        out.append({"id": i, "label": peers.label(None if i == UNENROLLED else i, reg),
                    "owner": p.get("owner"), "device": p.get("device"),
                    "roles": p.get("roles") if p else sorted({e.get("role") for e in evs if e.get("role")}),
                    "enrolled_at": p.get("enrolled_at"), "minted": p.get("minted"),
                    "revoked": bool(p.get("revoked_at")), "revoked_at": p.get("revoked_at"),
                    "online": bool(seen and now - edge._ts({"ts": seen}) < ONLINE), "last_seen": seen,
                    "sessions": len({edge._sid(e) for e in evs}), "actions": len(evs),
                    "blocked": sum(e.get("verdict") == "block" for e in evs)})
    return sorted(out, key=lambda r: (r["id"] == UNENROLLED, r["revoked"], r["device"] or ""))


def session_rows(events: list[dict], reg: dict, now: datetime | None = None) -> list[dict]:
    return [_with_peer(s, s["id"], reg) for s in edge.sessions(events, None, now)]


def overview(events: list[dict], rng: str, reg: dict, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    ov = edge.overview(events, rng, None, now)
    start, prev = edge.window(rng, now)
    cur = edge._in(events, start, now)
    old = edge._in(events, *prev) if prev else None
    online = sum(edge._ts({"ts": t}) > now - ONLINE for k, t in _online(events).items() if k != UNENROLLED)

    def kpi(f):
        return {"value": f(cur), "prev": f(old) if old is not None else None}
    blocked = [e for e in cur if e.get("verdict") == "block"]
    reasons = Counter(explain.rule(r["rule"])[0] for e in blocked if (r := explain.main_reason(e)))
    roles = Counter(e.get("role") for e in blocked)
    attacks = sorted((e for e in cur if is_attack(e)), key=edge._ts, reverse=True)[:50]
    return {"range": rng, "start": ov["start"], "now": ov["now"], "series": ov["series"], "bucket_s": ov["bucket_s"],
            "kpis": {"checked": ov["kpis"]["checked"], "blocked": ov["kpis"]["blocked"],
                     "attacks": kpi(lambda evs: sum(map(is_attack, evs))),
                     "peers_online": {"value": online, "prev": None}},
            "by_reason": [{"label": r, "count": n} for r, n in reasons.most_common()],
            "by_role": [{"role": r, "agent": explain.AGENTS.get(r, r), "count": n} for r, n in roles.most_common()],
            "attacks": [_with_peer(edge._item(e), e.get("key_id"), reg) for e in attacks]}


def health(events, app, policy) -> dict:
    """The edge health; blocked attacks read as 'N attacks stopped'."""
    st = app.state
    h = edge.health(events, policy, st.pins, st.feed, None)
    if h["level"] == "alert" and h.get("trace_id"):
        cut = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        n = sum(is_attack(e) for e in events if e["ts"] > cut)
        if n:
            h["message"] = f"{n} attack{'s' * (n != 1)} stopped"
    return h


def routes(policy) -> list:
    def admin(view):
        async def h(request: Request):
            if not admin_request(request):
                return JSONResponse({"error": "admin token required (TOLLGATE_ADMIN_TOKEN)"}, 401)
            return await view(request)
        return h

    def roles() -> list[str]:
        return list(policy.data.get("roles") or {})

    async def role_view(request, role: str) -> dict:
        st = request.app.state
        tools = {n: await src.list_tools() for n, src in (getattr(st, "sources", None) or {}).items()}
        data = policy.data
        a = edge.agent(data, role, tools, st.feed.state, model_door.budget(data).get(role) or {})
        a["policy"]["version"] = policy.status()["version"]
        return a

    def one_peer(i: str, reg: dict) -> dict | None:
        return next((p for p in peer_rows(edge.load_events(), reg) if p["id"] == i), None)

    async def status(request):
        st, fs = policy.status(), request.app.state.feed.state
        return JSONResponse({"health": health(edge.load_events(), request.app, policy),
                             "admin": "token" if admin_ok(request.headers.get("authorization")) else "loopback",
                             "policy": {"version": st["version"], "profile": policy.data.get("mode")},
                             "feed": {"version": fs.get("version")}, "app_version": edge.version()})

    async def get_overview(request):
        r = request.query_params.get("range", "today")
        r = r if r in ("15m", "1h", "today", "all") else "today"
        return JSONResponse(overview(edge.load_events(), r, peers.load()))

    async def list_peers(request):
        evs, reg = edge.load_events(), peers.load()
        rows = peer_rows(evs, reg)
        out = []
        for role in roles():
            a = await role_view(request, role)
            ev_r = [e for e in evs if e.get("role") == role]
            out.append({"role": role, "agent": a["agent"],
                        "peers": sum(role in p["roles"] and not p["revoked"] for p in rows if p["id"] != UNENROLLED),
                        "servers": [{"name": s["name"], "allowed": len(s["allowed"]), "hidden": len(s["denied"])}
                                    for s in a["servers"]],
                        "actions": len(ev_r), "blocked": sum(e.get("verdict") == "block" for e in ev_r)})
        return JSONResponse({"roles": out, "peers": rows})

    async def get_peer(request):
        i, evs, reg = request.path_params["id"], edge.load_events(), peers.load()
        p = one_peer(i, reg)
        if p is None:
            return JSONResponse({"error": "unknown peer"}, 404)
        mine = [e for e in evs if pid(e) == i]
        ks: dict[str, dict] = {}
        for e in sorted(mine, key=edge._ts):
            k = ks.setdefault(e.get("key_id"), {"key_id": e.get("key_id"), "role": e.get("role"), "first_ts": e["ts"],
                                                "n": 0})
            k.update(last_ts=e["ts"], n=k["n"] + 1)
        return JSONResponse({**p, "sessions": session_rows(mine, reg),
                             "keys": sorted(ks.values(), key=lambda k: k["last_ts"], reverse=True)})

    async def set_roles(request):
        i = request.path_params["id"]
        try:
            want = (await request.json()).get("roles")
        except (ValueError, AttributeError):
            want = None
        if not isinstance(want, list) or any(r not in roles() for r in want):
            return JSONResponse({"error": f"roles must be a list drawn from {roles()}"}, 400)
        try:
            peers.set_roles(i, want)
        except KeyError:
            return JSONResponse({"error": "unknown peer"}, 404)
        return JSONResponse(one_peer(i, peers.load()))

    async def revoke(request):
        i = request.path_params["id"]
        try:
            peers.revoke(i)
        except KeyError:
            return JSONResponse({"error": "unknown peer"}, 404)
        return JSONResponse(one_peer(i, peers.load()))

    async def enroll_token(request):
        t = peers.enroll_token()
        return JSONResponse({**t, "command": f"tollgate enroll {t['token']} --owner … --device …"})

    async def get_role(request):
        role = request.path_params["role"]
        if role not in roles():
            return JSONResponse({"error": "unknown role"}, 404)
        rows = peer_rows(edge.load_events(), peers.load())
        return JSONResponse({**await role_view(request, role),
                             "peers": [p for p in rows if p["id"] != UNENROLLED and role in p["roles"]]})

    async def list_sessions(request):
        q = request.query_params
        rows = session_rows(edge.load_events(), peers.load())
        for k in ("peer", "role"):
            if q.get(k):
                rows = [s for s in rows if s[k] == q[k]]
        if q.get("state") in ("active", "ended"):
            rows = [s for s in rows if s["active"] == (q["state"] == "active")]
        elif q.get("state"):
            rows = [s for s in rows if s["state"] == q["state"]]
        return JSONResponse({"sessions": rows})

    async def one_session(request):
        sid, evs, reg = request.path_params["id"], edge.load_events(), peers.load()
        meta = next((s for s in session_rows(evs, reg) if s["id"] == sid), None)
        if meta is None:
            return JSONResponse({"error": "unknown session"}, 404)
        tl = [{k: v for k, v in e.items() if k != "text"} for e in edge.timeline(evs, sid)]
        return JSONResponse({"session": meta, "timeline": tl})

    api = [Route("/status", admin(status)), Route("/overview", admin(get_overview)),
           Route("/peers", admin(list_peers)), Route("/peers/{id}", admin(get_peer)),
           Route("/peers/{id}/roles", admin(set_roles), methods=["POST"]),
           Route("/peers/{id}/revoke", admin(revoke), methods=["POST"]),
           Route("/enroll-token", admin(enroll_token), methods=["POST"]),
           Route("/roles/{role}", admin(get_role)),
           Route("/sessions", admin(list_sessions)), Route("/sessions/{id}", admin(one_session))]
    return [Mount("/console/api", routes=api), Route("/console", lambda r: RedirectResponse("/console/")),
            Mount("/console", app=StaticFiles(directory=UI, html=True))]
