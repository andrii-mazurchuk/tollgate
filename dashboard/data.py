"""Dashboard data shaping (AC14): pure functions over audit event dicts (API_CONTRACT.md 2). No Streamlit here."""
import csv
import io
import json
import statistics
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ACTIONS = ("allow", "redact", "approve", "block")
STAGES = ("role", "taint", "t1", "t2")
CSV_FIELDS = ("ts", "role", "key_id", "door", "verdict", "scan_point", "source", "tool", "rule", "detail",
              "t2_score", "transforms", "latency_ms", "tainted", "holds_private", "tokens", "policy_version")


def load_events(path: str | Path) -> list[dict]:
    """Every parseable line of the audit JSONL; a missing file or a torn last line is not an error."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
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


def ts(ev: dict) -> datetime:
    return datetime.fromisoformat(ev["ts"].replace("Z", "+00:00"))


def since(events: list[dict], minutes: float | None, now: datetime | None = None) -> list[dict]:
    if not minutes:
        return events
    cut = (now or datetime.now(timezone.utc)) - timedelta(minutes=minutes)
    return [e for e in events if ts(e) >= cut]


def filter_events(events, roles=(), doors=(), verdicts=(), minutes=None, now=None) -> list[dict]:
    """Empty selection = no filter on that field."""
    return [e for e in since(events, minutes, now)
            if (not roles or e.get("role") in roles) and (not doors or e.get("door") in doors)
            and (not verdicts or e.get("verdict") in verdicts)]


def counts_by_action(events) -> dict[str, int]:
    c = Counter(e.get("verdict") for e in events)
    return {a: c.get(a, 0) for a in ACTIONS}


def counts_by(events, field: str) -> dict[str, int]:
    return dict(Counter(str(e.get(field)) for e in events).most_common())


def series_by_action(events, bucket_s: int = 60) -> list[dict]:
    """[{t, allow, redact, approve, block}] per time bucket, oldest first."""
    rows: dict[datetime, dict] = {}
    for e in events:
        t = ts(e)
        b = t - timedelta(seconds=t.timestamp() % bucket_s)
        rows.setdefault(b, {"t": b, **dict.fromkeys(ACTIONS, 0)})[e.get("verdict", "allow")] += 1
    return [rows[k] for k in sorted(rows)]


def first_reason(ev: dict) -> dict:
    return (ev.get("reasons") or [{}])[0]


def top_rules(events, n: int = 15) -> list[dict]:
    """[{rule, tier, count}] over every reason of every event, most frequent first."""
    c = Counter((r.get("rule"), r.get("tier")) for e in events for r in e.get("reasons") or [])
    return [{"rule": r, "tier": t, "count": k} for (r, t), k in c.most_common(n)]


def _pct(xs: list[float]) -> dict:
    if len(xs) < 2:
        return {"p50": xs[0] if xs else None, "p95": xs[0] if xs else None, "n": len(xs)}
    q = statistics.quantiles(xs, n=100, method="inclusive")
    return {"p50": round(q[49], 3), "p95": round(q[94], 3), "n": len(xs)}


def latency(events) -> dict:
    """{stage: {p50, p95, n}} for role/taint/t1/t2, plus t2_share = events that ran tier 2 / all events."""
    out = {s: _pct([e["latency_ms"][s] for e in events if s in (e.get("latency_ms") or {})]) for s in STAGES}
    out["t2_share"] = round(out["t2"]["n"] / len(events), 4) if events else None
    return out


def taint_table(events, live: dict | None = None) -> list[dict]:
    """One row per session (key_id) that is tainted or holds private data. Live /admin/taint wins over the audit
    flags; cause = detail of the most recent taint.* reason seen for that key."""
    rows: dict[str, dict] = {}
    for e in sorted(events, key=ts):
        k = e.get("key_id")
        r = rows.setdefault(k, {"key_id": k, "tainted": False, "holds_private": False, "cause": None,
                                "last_seen": None})
        r["tainted"] = r["tainted"] or bool(e.get("tainted"))
        r["holds_private"] = r["holds_private"] or bool(e.get("holds_private"))
        r["last_seen"] = e["ts"]
        for reason in e.get("reasons") or []:
            if str(reason.get("rule", "")).startswith("taint."):
                r["cause"] = reason.get("detail")
    for k, st in (live or {}).items():
        r = rows.setdefault(k, {"key_id": k, "cause": None, "last_seen": None})
        r["tainted"], r["holds_private"] = bool(st.get("tainted")), bool(st.get("holds_private"))
        r["cause"] = r["cause"] or "; ".join(f"{f}: {st[f]}" for f in ("tainted", "holds_private")
                                              if isinstance(st.get(f), str)) or None
    return sorted((r for r in rows.values() if r["tainted"] or r["holds_private"]),
                  key=lambda r: r["last_seen"] or "", reverse=True)


def budget_from_events(events, limits: dict | None = None, day: str | None = None) -> dict:
    """{role: {used, limit}} from model door tokens on `day` (UTC, default today). Fallback when the gateway
    is down; live /admin/budget is preferred because it counts the in-memory state."""
    day = day or datetime.now(timezone.utc).date().isoformat()
    used = Counter()
    for e in events:
        if e.get("door") == "model" and ts(e).date().isoformat() == day:
            used[e.get("role")] += int(e.get("tokens") or 0)
    roles = set(used) | set(limits or {})
    return {r: {"used": used.get(r, 0), "limit": (limits or {}).get(r)} for r in sorted(roles)}


def feed(events, n: int = 50) -> list[dict]:
    """Newest first: ts, role, door, tool, verdict, first reason rule + detail."""
    rows = []
    for e in sorted(events, key=ts, reverse=True)[:n]:
        r = first_reason(e)
        rows.append({"ts": e["ts"], "role": e.get("role"), "door": e.get("door"), "tool": e.get("tool"),
                     "verdict": e.get("verdict"), "rule": r.get("rule"), "detail": r.get("detail")})
    return rows


def to_jsonl(events) -> str:
    return "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events)


def to_csv(events) -> str:
    """Flat CSV: first reason as rule/detail, lists and dicts JSON-encoded."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    for e in events:
        r = first_reason(e)
        row = {f: e.get(f) for f in CSV_FIELDS}
        row.update(rule=r.get("rule"), detail=r.get("detail"), transforms=json.dumps(e.get("transforms") or []),
                   latency_ms=json.dumps(e.get("latency_ms") or {}))
        w.writerow(row)
    return buf.getvalue()


APPROVAL_COLS = ("id", "ts", "role", "key_id", "tool", "reason", "status", "decided_at")


def approvals_view(listing: dict | None) -> tuple[list[dict], list[dict]] | None:
    """GET /admin/approvals -> (pending, recent) rows for the panel; None when the gateway is offline."""
    if listing is None:
        return None
    rows = lambda k: [{c: i.get(c) for c in APPROVAL_COLS} for i in listing.get(k) or []]  # noqa: E731
    return rows("pending"), rows("recent")


def decision_message(code: int) -> str:
    """POST /admin/approvals/{id} status -> what the panel says."""
    return {200: "decision recorded", 401: "admin token rejected: set TOLLGATE_ADMIN_TOKEN to the gateway's token",
            404: "unknown or already decided (approved, denied or timed out)"}.get(code, f"gateway error {code}")


def pin_alerts(health: dict | None) -> list[str]:
    """/healthz pin_alerts -> one line per changed tool."""
    return [f"{a.get('tool')}: tool description changed: possible rug-pull "
            f"({str(a.get('old'))[:12]} -> {str(a.get('new'))[:12]} at {a.get('ts')})"
            for a in (health or {}).get("pin_alerts") or []]
