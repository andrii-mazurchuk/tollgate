"""Access map (console Overview): who calls what. GET /console/api/map?range=… -> peers, roles, servers, links and
paths (peer -> role -> server) with call and block counts from the audit events in range, plus each node's latest
sessions for the side list. Peer = peers.peer_of(key id); legacy keys go to the Unenrolled bucket."""
from datetime import datetime, timezone

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from tollgate import console, edge, explain
from tollgate.gateway import peers

SERVER_LABEL = {"builtins": "Agent built-ins", "model": "Model"}
TOP_SESSIONS = 8


def server_of(e: dict) -> str:
    """MCP server name; 'builtins' for the agent's own tools (hook door), 'model' for the model door."""
    if e.get("door") == "model":
        return "model"
    tool = e.get("tool") or ""
    if tool.startswith("builtin.") or e.get("source") == "builtin":
        return "builtins"
    return e.get("source") or tool.partition(".")[0] or "unknown"


def _peer_id(e: dict) -> str:
    return peers.peer_of(e.get("key_id") or e.get("session_id") or "") or console.UNENROLLED


def _bump(row: dict, e: dict) -> dict:
    row["calls"] += 1
    row["last_ts"] = max(row.get("last_ts") or "", e["ts"])
    if e.get("verdict") == "block":
        row["blocked"] += 1
        if e["ts"] >= (row.get("_bts") or ""):
            row["_bts"] = e["ts"]
            row["last_blocked"] = {"session_id": edge._sid(e), "trace_id": edge._tid(e), "ts": e["ts"]}
    return row


def _new(**kw) -> dict:
    return {**kw, "calls": 0, "blocked": 0, "last_ts": None, "last_blocked": None}


def _clean(rows) -> list[dict]:
    return [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]


def build(events: list[dict], rng: str, reg: dict, roles: list[str], now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    start, _ = edge.window(rng, now)
    cur = edge._in(events, start, now)
    state = {p["id"]: p for p in console.peer_rows(events, reg, now)}  # online/revoked over all time, not the range
    P = {i: _new(id=i, label=p["label"], online=p["online"], revoked=p["revoked"]) for i, p in state.items()
         if i != console.UNENROLLED}
    R = {r: _new(role=r, agent=explain.AGENTS.get(r, r)) for r in roles}
    S, L, T, sess = {}, {}, {}, {}
    for e in sorted(cur, key=edge._ts):
        p, r, s = _peer_id(e), e.get("role") or "unknown", server_of(e)
        if p not in P:
            P[p] = _new(id=p, label=peers.label(None if p == console.UNENROLLED else p, reg),
                        online=False, revoked=False)
        R.setdefault(r, _new(role=r, agent=explain.AGENTS.get(r, r)))
        S.setdefault(s, _new(id=s, label=SERVER_LABEL.get(s, s)))
        for row in (P[p], R[r], S[s], L.setdefault(f"p:{p}>r:{r}", _new(**{"from": f"p:{p}", "to": f"r:{r}"})),
                    L.setdefault(f"r:{r}>s:{s}", _new(**{"from": f"r:{r}", "to": f"s:{s}"})),
                    T.setdefault((p, r, s), _new(peer=p, role=r, server=s))):
            _bump(row, e)
        x = sess.setdefault(edge._sid(e), {"id": edge._sid(e), "role": r, "agent": explain.AGENTS.get(r, r),
                                            "peer": p, "peer_label": P[p]["label"], "n": 0, "blocked": 0,
                                            "nodes": set()})
        x.update(last_ts=e["ts"], n=x["n"] + 1, blocked=x["blocked"] + (e.get("verdict") == "block"))
        x["nodes"] |= {f"p:{p}", f"r:{r}", f"s:{s}"}
    newest = sorted(sess.values(), key=lambda x: x["last_ts"], reverse=True)
    by_node: dict[str, list] = {"*": []}
    for x in newest:
        for k in ["*", *sorted(x["nodes"])]:
            lst = by_node.setdefault(k, [])
            if len(lst) < TOP_SESSIONS:
                lst.append({k2: v for k2, v in x.items() if k2 != "nodes"})
    return {"range": rng, "now": now.isoformat().replace("+00:00", "Z"),
            "peers": _clean(sorted(P.values(), key=lambda x: (x["id"] == console.UNENROLLED, -x["calls"], x["label"]))),
            "roles": _clean(R.values()),
            "servers": _clean(sorted(S.values(), key=lambda x: -x["calls"])),
            "links": _clean(L.values()), "paths": _clean(T.values()), "sessions": by_node}


def routes(policy, admin) -> list:
    async def get_map(request: Request):
        r = request.query_params.get("range", "today")
        r = r if r in ("15m", "1h", "today", "all") else "today"
        return JSONResponse(build(edge.load_events(), r, peers.load(), list(policy.data.get("roles") or {})))
    return [Route("/map", admin(get_map))]
