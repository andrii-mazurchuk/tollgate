"""Exportable audit log (GET /console/api/export) and latency telemetry (the `latency` key of /console/api/overview).

The hub only holds fingerprints (content_sha256), never text; the export strips a stray `text` key anyway."""
import csv
import io
import json
import math
from datetime import datetime, timezone

from starlette.responses import JSONResponse, StreamingResponse

from tollgate import edge, explain
from tollgate.gateway import peers

TIMED = ("key", "role", "arguments", "data_flow", "content", "budget")
TARGET_MS = {"hub": 5.0, "tier1": 5.0, "classifier": 80.0}  # AC15 targets (classifier: short text)
COLS = ("ts", "peer", "peer_label", "role", "agent", "session_id", "trace_id", "door", "tool", "verdict", "check",
        "rules", "state_before", "state_after", "total_ms", "content_sha256", "policy_version")
KINDS = ("blocked", "masked", "waiting", "flagged", "allowed")


def pct(xs: list[float]) -> dict:
    """Nearest-rank p50/p95."""
    xs = sorted(xs)
    if not xs:
        return {"p50": None, "p95": None, "n": 0}
    q = lambda p: round(xs[max(0, math.ceil(p * len(xs)) - 1)], 3)  # noqa: E731
    return {"p50": q(0.5), "p95": q(0.95), "n": len(xs)}


def _stage_ms(e: dict, name: str):
    return next((s["ms"] for s in e.get("stages") or [] if s.get("name") == name and s.get("ms") is not None), None)


def total_ms(e: dict) -> float:
    return round(sum(s.get("ms") or 0 for s in e.get("stages") or []), 3)


def latency(events: list[dict]) -> dict:
    """p50/p95 per check stage, end to end (sum of the stages' ms), hub checks (role + data flow), tier 1, classifier."""
    timed = [e for e in events if any(s.get("ms") is not None for s in e.get("stages") or [])]
    lat = [e.get("latency_ms") or {} for e in events]
    t2 = pct([x["t2"] for x in lat if "t2" in x])
    stages = []
    for name in TIMED:
        p = pct([m for e in timed if (m := _stage_ms(e, name)) is not None])
        # content = tier 1 + tier 2: it only has the tier 1 target when no classifier time is in it
        target = None if name == "content" and t2["n"] else TARGET_MS["tier1"] if name == "content" else TARGET_MS["hub"]
        stages.append({"name": name, **p, "target": target, "over": bool(p["n"] and p["p95"] > target) if target else False})

    def row(p, t):
        return {**p, "target": t, "over": bool(p["n"] and p["p95"] > t)}
    return {"n": len(timed), "total": pct([total_ms(e) for e in timed]), "stages": stages,
            "hub": row(pct([x.get("role", 0) + x.get("taint", 0) for x in lat if "role" in x]), TARGET_MS["hub"]),
            "tier1": row(pct([x["t1"] for x in lat if "t1" in x]), TARGET_MS["tier1"]),
            "classifier": row(t2, TARGET_MS["classifier"])}


def _list(q, k) -> list[str]:
    return [x for x in (q.get(k) or "").split(",") if x]


def select(events: list[dict], q, reg: dict, now: datetime | None = None) -> list[dict]:
    """The events the console shows: range, then the Sessions view's filters (peer/role/state/search on the session,
    any-of within a filter, AND across), then kind. Oldest first."""
    from tollgate.console import session_rows  # console imports this module
    now = now or datetime.now(timezone.utc)
    rng = q.get("range") if q.get("range") in ("15m", "1h", "today", "all") else "all"
    evs = edge._in(events, edge.window(rng, now)[0], now)
    p, r, st, s = _list(q, "peer"), _list(q, "role"), _list(q, "state"), (q.get("q") or "").lower()
    if p or r or st or s:
        keep = {x["id"] for x in session_rows(events, reg, now)
                if (not p or x["peer"] in p) and (not r or x["role"] in r)
                and (not st or any(y in st for y in (x["state"] or "clean").split("+")))
                and (not s or s in " ".join(str(x[k]) for k in ("agent", "peer_label", "id", "role")).lower())}
        evs = [e for e in evs if edge._sid(e) in keep]
    if ks := _list(q, "kind"):
        evs = [e for e in evs if (edge.kind(e) or "allowed") in ks]
    return sorted(evs, key=edge._ts)


def cell(v) -> str:
    """CSV-injection guard: a cell a spreadsheet would run as a formula gets a leading quote."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def csv_row(e: dict, reg: dict) -> list[str]:
    p = peers.peer_of(e.get("key_id") or "")
    r = explain.main_reason(e)
    return [cell(v) for v in (
        e["ts"], p or "unenrolled", peers.label(p, reg), e.get("role"), explain.AGENTS.get(e.get("role"), e.get("role")),
        edge._sid(e), e.get("trace_id"), e.get("door"), e.get("tool"), e.get("verdict"),
        explain.check_name(r["rule"]) if r and edge.kind(e) else "", ";".join(x.get("rule") or "" for x in e.get("reasons") or []),
        e.get("state_before"), edge._state(e), total_ms(e), e.get("content_sha256"), e.get("policy_version"))]


async def export(request):
    q = request.query_params
    fmt = q.get("format", "csv")
    if fmt not in ("csv", "jsonl"):
        return JSONResponse({"error": "format must be csv or jsonl"}, 400)
    reg = peers.load()
    evs = select(edge.load_events(), q, reg)

    def lines():
        if fmt == "jsonl":
            for e in evs:
                yield json.dumps({k: v for k, v in e.items() if k != "text"}, ensure_ascii=False) + "\n"
            return
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(COLS)
        for e in evs:
            w.writerow(csv_row(e, reg))
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()
        yield buf.getvalue()  # header only, when nothing matched
    name = f"tollgate-audit-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    return StreamingResponse(lines(), media_type="text/csv; charset=utf-8" if fmt == "csv" else "application/x-ndjson",
                             headers={"Content-Disposition": f'attachment; filename="{name}"', "X-Event-Count": str(len(evs))})
