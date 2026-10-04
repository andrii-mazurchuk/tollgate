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

from tollgate import edge, explain, telemetry
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
    reasons = Counter(explain.check_name((explain.main_reason(e) or {}).get("rule")) for e in blocked)
    roles = Counter(e.get("role") for e in blocked)
    attacks = sorted((e for e in cur if is_attack(e)), key=edge._ts, reverse=True)[:50]
    return {"range": rng, "start": ov["start"], "now": ov["now"], "series": ov["series"], "bucket_s": ov["bucket_s"],
            "kpis": {"checked": ov["kpis"]["checked"], "blocked": ov["kpis"]["blocked"],
                     "attacks": kpi(lambda evs: sum(map(is_attack, evs))),
                     "peers_online": {"value": online, "prev": None}},
            "by_reason": [{"label": r, "count": n} for r, n in reasons.most_common()],
            "by_role": [{"role": r, "agent": explain.AGENTS.get(r, r), "count": n} for r, n in roles.most_common()],
            "attacks": [_with_peer(edge._item(e), e.get("key_id"), reg) for e in attacks],
            "latency": telemetry.latency(cur)}


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

    async def get_policy(request):
        st, data = request.app.state, policy.data
        tools = {n: await src.list_tools() for n, src in (getattr(st, "sources", None) or {}).items()}
        return JSONResponse({"status": policy_status(policy), "matrix": matrix(data, tools),
                             "rules": rules(data, st.feed.state), "history": policy.history[::-1],
                             "profiles": profiles(data)})

    async def set_profile(request):
        try:
            name = (await request.json()).get("profile")
        except (ValueError, AttributeError):
            name = None
        if name not in PROFILES or not policy.path:
            return JSONResponse({"error": f"profile must be one of {list(PROFILES)}"}, 400)
        backup = switch_profile(policy, name)
        return JSONResponse({"status": policy_status(policy), "backup": backup})

    async def set_access(request):
        import yaml
        from tollgate.gateway.policy import validate
        try:
            body = await request.json()
            base, chg = body.get("base_version"), body.get("changes")
        except (ValueError, AttributeError):
            base = chg = None
        if not policy.path or not isinstance(chg, list) or not chg or not all(isinstance(c, dict) for c in chg):
            return JSONResponse({"error": "need {base_version, changes: [{role, tool, allowed}]}"}, 400)
        cur = policy.status()["version"]
        if base != cur:
            return JSONResponse({"error": f"the policy changed meanwhile (now {cur})", "version": cur}, 409)
        st = request.app.state
        tools = {n: await src.list_tools() for n, src in (getattr(st, "sources", None) or {}).items()}
        try:
            new, sentences = edit_access(policy.data, tools, chg)
            raw = yaml.safe_dump(new, sort_keys=False, allow_unicode=True).encode("utf-8")
            validate(yaml.safe_load(raw))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, 400)
        if not sentences:
            return JSONResponse({"error": "nothing changes"}, 400)
        backup = replace_policy(policy, raw, "Edited in console")
        return JSONResponse({"status": policy_status(policy), "backup": backup, "sentences": sentences})

    api = [Route("/status", admin(status)), Route("/overview", admin(get_overview)),
           Route("/policy", admin(get_policy)), Route("/policy/profile", admin(set_profile), methods=["POST"]),
           Route("/policy/access", admin(set_access), methods=["POST"]),
           Route("/peers", admin(list_peers)), Route("/peers/{id}", admin(get_peer)),
           Route("/peers/{id}/roles", admin(set_roles), methods=["POST"]),
           Route("/peers/{id}/revoke", admin(revoke), methods=["POST"]),
           Route("/enroll-token", admin(enroll_token), methods=["POST"]),
           Route("/roles/{role}", admin(get_role)),
           Route("/sessions", admin(list_sessions)), Route("/sessions/{id}", admin(one_session))]
    from tollgate import console3  # revision 3: Threat feed + Self-test
    api += console3.routes(policy, admin)
    api.append(Route("/export", admin(telemetry.export)))  # exportable audit log (CSV | JSONL)
    return [Mount("/console/api", routes=api), Route("/console", lambda r: RedirectResponse("/console/")),
            Mount("/console", app=StaticFiles(directory=UI, html=True))]


# --- Policy view (docs/ui-spec.md "Server console, revision 2") ---
PROFILES = ("strict", "balanced", "lenient")
RANK = {"allow": 0, "flag": 1, "redact": 2, "approve": 3, "block": 4}


def _r(v) -> int:  # looseness of an action: higher = looser
    return -RANK.get(v, 0)


def _act(v) -> str:
    return edge.ACTION_WORDS.get(v, v)


# ponytail: hand-picked settings, not a generic YAML differ; add a row when the profiles start differing elsewhere
SETTINGS = [  # (path, plain, default, looseness, words)
    (("taint", "block_flow", "action"), "Private data to a public destination", "block", _r, _act),
    (("approval", "timeout_s"), "Time a human has to approve", 30, float, lambda v: f"{v} s"),
    (("loops", "max_identical_calls"), "Identical calls in a row before cut-off", 5, float, str),
    *[(("roles", r, "budget", "tokens_per_day"), f"{a} tokens per day", 0, float, lambda v: f"{v:,}")
      for r, a in explain.AGENTS.items()],
    *[(("roles", r, "models"), f"{a} models", [], len, lambda v: ", ".join(v) or "none")
      for r, a in explain.AGENTS.items()],
    (("roles", "role-2", "constrain", "files.fs.write", "path"), "Support assistant file writes", "",
     lambda v: not v, lambda v: edge.limit_words("path", v) if v else "no limit"),
    *[(("content", "pii", k), w[0].upper() + w[1:], "redact", _r, _act) for k, w in edge.PII.items()],
    (("roles", "role-2", "content", "secrets"), "Support assistant secrets", "block", _r, _act),  # global: block
    (("content", "injection", "tier1_action"), "Known injection phrases", "allow", _r, _act),
    (("content", "injection", "tool_result_action"), "Injection found in a tool result", "flag", _r, _act),
    (("content", "injection", "high"), "Classifier certainty that blocks", 0.9, float, lambda v: f"{round(v * 100)}%"),
    (("content", "injection", "low"), "Classifier certainty that flags", 0.5, float, lambda v: f"{round(v * 100)}%"),
]


def _get(d: dict, path: tuple, default=None):
    for k in path:
        d = d.get(k) if isinstance(d, dict) else None
    return default if d is None else d


def _profile(name: str) -> dict:
    import yaml
    from tollgate.gateway.policy import DEFAULT_PATH
    return yaml.safe_load((DEFAULT_PATH.parent / "policies" / f"{name}.yaml").read_text(encoding="utf-8"))


def changes(old: dict, new: dict) -> list[dict]:
    """What would get stricter or looser going from `old` to `new`, in plain sentences."""
    out = []
    for path, plain, dflt, loose, words in SETTINGS:
        a, b = _get(old, path, dflt), _get(new, path, dflt)
        if loose(a) != loose(b):
            out.append({"plain": f"{plain}: {words(a)} → {words(b)}",
                        "direction": "looser" if loose(b) > loose(a) else "stricter"})
    return out


def profiles(data: dict) -> dict:
    ps = {n: _profile(n) for n in PROFILES}
    diff = [{"setting": ".".join(p), "plain": plain, "values": {n: words(_get(ps[n], p, d)) for n in PROFILES}}
            for p, plain, d, _, words in SETTINGS if len({repr(_get(ps[n], p, d)) for n in PROFILES}) > 1]
    return {"current": data.get("mode") if data.get("mode") in PROFILES else None, "names": list(PROFILES),
            "diff": diff, "changes": {n: changes(data, ps[n]) for n in PROFILES}}


def modified(data: dict) -> bool:
    """The active file's gateway sections (all but Track B's `content`) differ from its profile's file."""
    if data.get("mode") not in PROFILES:
        return False
    p = _profile(data["mode"])
    return any(data.get(k) != p.get(k) for k in set(data) | set(p) if k != "content")


def policy_status(policy) -> dict:
    data = policy.data
    return {**policy.status(), "profile": data.get("mode"), "modified": modified(data)}


def matrix(data: dict, tools: dict) -> dict:
    """Rows are tools grouped by server, one cell per role: read | write | hidden | asks, plus limits in words."""
    roles, rows = list(data.get("roles") or {}), {}
    for role in roles:
        approval = set((data["roles"][role] or {}).get("approval") or [])
        for s in edge.agent(data, role, tools, {}, {})["servers"]:
            for t in s["allowed"] + s["denied"]:
                row = rows.setdefault(s["name"], {}).setdefault(t["name"], {
                    "name": t["name"], "plain": t["plain"], "write": t["write"],
                    "labels": [edge.LABEL_WORDS[x] for x in (data.get("labels") or {}).get(t["name"]) or []],
                    "cells": {}})
                acc = ("hidden" if t not in s["allowed"] else "asks" if t["name"] in approval
                       else "write" if t["write"] else "read")
                row["cells"][role] = {"access": acc,
                                      "limits": [x for x in t.get("limits") or [] if x != "asks a human first"]}
    return {"roles": [{"role": r, "agent": explain.AGENTS.get(r, r)} for r in roles],
            "servers": [{"name": s, "tools": list(ts.values())} for s, ts in rows.items()]}


def rules(data: dict, feed_state: dict) -> list[dict]:
    """One plain card per rule family, generated from the live policy."""
    g = edge.agent(data, "", {}, feed_state, {})  # no role: the global content section
    flow, c, roles = g["flow_rule"], g["content"], data.get("roles") or {}
    name = explain.AGENTS.get
    done = {"redact": "masked", "block": "blocked", "approve": "held for a human", "allow": "allowed"}
    over = [f"for {name(r, r)}, " + ", ".join(f"{edge.PII.get(k, k)} are {done.get(v, v)}"
                                              for k, v in rp["content"].items() if isinstance(v, str))
            for r, rp in roles.items() if (rp or {}).get("content")]
    per = [f"{name(r, r)} may use {', '.join(rp.get('models') or []) or 'no models'} and "
           f"{(rp.get('budget') or {}).get('tokens_per_day') or 0:,} tokens a day." for r, rp in roles.items()]
    sig = c["signatures"]
    loops = (data.get("loops") or {}).get("max_identical_calls", 5)
    ts = (data.get("approval") or {}).get("timeout_s", 30)
    return [
        {"id": "data_flow", "title": "Data-flow rule", "sentence": flow["sentence"],
         "action": _act(flow["action"]) if flow["enabled"] else "off"},
        {"id": "masked", "title": "Masked data", "action": "mask",
         "sentence": f"Masked before the agent sees it: {', '.join(c['masked']) or 'nothing'}."
                     + (f" Instead, {'; '.join(over)}." if over else "")},
        {"id": "blocked", "title": "Blocked data", "action": "block",
         "sentence": f"A call carrying any of these is blocked: {', '.join(c['blocked']) or 'nothing'}."},
        {"id": "injection", "title": "Injection check", "action": "block", "sentence": c["injection"]["words"]},
        {"id": "signatures", "title": "Signatures", "action": "block",
         "sentence": f"Every call is checked against {sig['count']} known attack patterns from the {sig['source']}."},
        {"id": "loops", "title": "Loop guard", "action": "block",
         "sentence": f"The same call repeated more than {loops} times in a row is cut off."},
        {"id": "budgets", "title": "Budgets and models per role", "action": "block", "sentence": " ".join(per)},
        {"id": "approval_timeout", "title": "Approval timeout", "action": "block",
         "sentence": f"A call waiting for a human is refused if nobody answers within {ts} seconds."},
    ]


def replace_policy(policy, raw: bytes, note: str | None = None) -> str:
    """Backs up the active file, puts `raw` in its place (atomic replace), reloads. Returns the backup path."""
    import os
    import shutil
    from tollgate.gateway.policy import history_path
    backup = (history_path().parent / "policy-backups"
              / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{policy.version}.yaml")
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(policy.path, backup)
    tmp = policy.path.with_name(policy.path.name + ".tmp")
    tmp.write_bytes(raw)
    os.replace(tmp, policy.path)  # atomic on Windows too: a hot reload never sees half a file
    policy.reload(note)
    return str(backup)


def switch_profile(policy, name: str) -> str:
    """Puts policies/<name>.yaml in place of the active file (backed up first). Returns the backup."""
    from tollgate.gateway.policy import DEFAULT_PATH
    return replace_policy(policy, (DEFAULT_PATH.parent / "policies" / f"{name}.yaml").read_bytes())


# --- Policy: edit access (docs/ui-spec.md "Server console, revision 3") ---
def _catalog(tools: dict) -> dict:
    """full tool name -> (server, name as the policy lists it, write?), from each source's own tool list."""
    return {f"{s}.{t.name.replace('_', '.')}": (s, t.name.replace("_", "."),
                                                 not (t.annotations and t.annotations.read_only_hint))
            for s, ts in tools.items() for t in ts}


def _lc(x: str) -> str:
    return x[:1].lower() + x[1:]


def edit_access(data: dict, tools: dict, changes: list) -> tuple[dict, list[str]]:
    """Applies [{role, tool, allowed}] to a copy of `data`. Each touched role x server is rewritten in its smallest
    form (all read tools -> access: read, all tools -> access: rw, else tools: [...], none -> server removed); every
    other key (constrain, approval, ...) is kept. Returns (new data, one plain sentence per real change)."""
    import copy
    from types import SimpleNamespace
    from tollgate.gateway import tool_allowed
    cat, new = _catalog(tools), copy.deepcopy(data)
    roles = new.get("roles") or {}
    before: dict[tuple, set] = {}
    after: dict[tuple, set] = {}
    for c in changes:
        role, tool, want = c.get("role"), c.get("tool"), c.get("allowed")
        if role not in roles:
            raise ValueError(f"unknown role {role!r}")
        if tool not in cat:
            raise ValueError(f"unknown tool {tool!r}")
        if not isinstance(want, bool):
            raise ValueError("allowed: need true|false")
        srv, short, _ = cat[tool]
        if (role, srv) not in before:
            rp = roles[role] or {}
            before[role, srv] = {s for n, (sv, s, w) in cat.items() if sv == srv and tool_allowed(
                rp, SimpleNamespace(name=n, annotations=SimpleNamespace(read_only_hint=not w)))}
            after[role, srv] = set(before[role, srv])
        (after[role, srv].add if want else after[role, srv].discard)(short)
    labels = new.get("labels") or {}
    out = []
    for (role, srv), now in after.items():
        mine = [(s, w, n) for n, (sv, s, w) in cat.items() if sv == srv]  # in the source's order
        every, reads = {s for s, _, _ in mine}, {s for s, w, _ in mine if not w}
        roles[role] = roles[role] or {}
        servers = roles[role]["servers"] = roles[role].get("servers") or {}
        rest = {k: v for k, v in (servers.get(srv) or {}).items() if k not in ("access", "tools")}
        if not now:
            servers.pop(srv, None)
        else:
            form = ({"access": "read"} if now == reads else {"access": "rw"} if now == every
                    else {"tools": [s for s, _, _ in mine if s in now]})
            servers[srv] = {**form, **rest}
        agent = explain.AGENTS.get(role, role)
        for s, w, n in mine:
            if (s in now) != (s in before[role, srv]):
                if s in now:
                    tags = ["write" if w else "read"] + [edge.LABEL_WORDS[x] for x in labels.get(n) or []]
                    out.append(f"{agent} may now {_lc(explain.tool(n))} ({', '.join(tags)})")
                else:
                    out.append(f"{agent} can no longer {_lc(explain.tool(n))}")
    return new, out
