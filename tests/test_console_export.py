"""Exportable audit log (GET /console/api/export) and latency telemetry (overview.latency)."""
import contextlib
import csv
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx2

from tollgate import telemetry
from tollgate.gateway import peers


def _ts(sec_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=sec_ago)).isoformat().replace("+00:00", "Z")


def _ev(i, key, verdict="allow", role="role-2", tool="github.issues.read", ms=(1.0, 0.01, 2.0), sec_ago=60, **kw):
    st = [{"name": n, "outcome": "ok", "detail": "", "ms": m} for n, m in zip(("role", "data_flow", "content"), ms)]
    return {"ts": _ts(sec_ago), "role": role, "key_id": key, "session_id": key, "door": "tool", "verdict": verdict,
            "tool": tool, "reasons": kw.pop("reasons", []), "trace_id": f"t_{i:04d}", "content_sha256": "ab" * 32,
            "policy_version": "v1", "stages": [{"name": "key", "outcome": "ok", "ms": None}, *st],
            "latency_ms": {"role": ms[0], "taint": ms[1], "t1": ms[2]}, "state_before": "clean", "state_after": "clean", **kw}


@contextlib.asynccontextmanager
async def _app(monkeypatch, events):
    Path(os.environ["TOLLGATE_AUDIT"]).write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    monkeypatch.setenv("TOLLGATE_UPSTREAM", "scripted")
    monkeypatch.setenv("TOLLGATE_T2", "off")
    from tollgate.gateway import build_app
    from tollgate.gateway.policy import load_policy
    app = build_app(load_policy())
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            yield c, app


def _fleet():
    pid = peers.enroll(peers.enroll_token()["token"], "Ada", "ada-x1")
    peers.set_roles(pid, ["role-1", "role-2"])
    blocked = _ev(2, f"{pid}-1", "block", sec_ago=50, tool="=HYPERLINK(\"x\")", state_after="untrusted",
                  reasons=[{"rule": "taint.block_flow", "detail": "private to public"}])
    return pid, [_ev(1, f"{pid}-1"), blocked, _ev(3, "legacy", role="role-1", sec_ago=3 * 3600),
                 {**_ev(4, f"{pid}-2", "redact", sec_ago=40), "text": "AKIA-secret-text"}]


def test_percentiles_and_latency_shape():
    assert telemetry.pct([]) == {"p50": None, "p95": None, "n": 0}
    assert telemetry.pct(list(range(1, 101))) == {"p50": 50, "p95": 95, "n": 100}
    evs = [_ev(i, "k", ms=(float(i), 0.01, 1.0)) for i in range(1, 21)]
    evs.append({**_ev(99, "k", ms=(0.5, 0.01, 9.0)), "latency_ms": {"role": 0.5, "taint": 0.01, "t1": 9.0, "t2": 120.0}})
    L = telemetry.latency(evs)
    role = next(s for s in L["stages"] if s["name"] == "role")
    assert L["n"] == 21 and role["n"] == 21 and role["p95"] == 19.0 and role["over"] and role["target"] == 5.0
    assert next(s for s in L["stages"] if s["name"] == "key")["n"] == 0  # not timed
    assert next(s for s in L["stages"] if s["name"] == "content")["target"] is None  # holds classifier time
    assert L["classifier"] == {"p50": 120.0, "p95": 120.0, "n": 1, "target": 80.0, "over": True}
    assert L["tier1"]["p95"] == 1.0 and not L["tier1"]["over"]
    assert L["total"]["p95"] == 20.01 and L["hub"]["p95"] == 19.01


def test_csv_injection_guard():
    assert [telemetry.cell(v) for v in ("=1+1", "+x", "-2", "@a", "ok", None, 1.5)] == ["'=1+1", "'+x", "'-2", "'@a", "ok", "", "1.5"]


async def test_export_csv_jsonl_filters(monkeypatch):
    pid, evs = _fleet()
    async with _app(monkeypatch, evs) as (c, _):
        r = await c.get("/console/api/export", params={"format": "csv", "range": "all"})
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
        assert r.headers["content-disposition"].startswith('attachment; filename="tollgate-audit-') and ".csv" in r.headers["content-disposition"]
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert list(rows[0]) == list(telemetry.COLS) and len(rows) == 4
        assert [x["trace_id"] for x in rows] == ["t_0003", "t_0001", "t_0002", "t_0004"]  # oldest first
        b = rows[2]
        assert b["peer"] == pid and b["peer_label"] == "ada-x1 · Ada" and b["agent"] == "Support assistant"
        assert b["tool"].startswith("'=") and b["check"] == "Data-flow rule" and b["rules"] == "taint.block_flow"
        assert b["total_ms"] == "3.01" and b["content_sha256"] == "ab" * 32 and b["state_after"] == "untrusted"
        assert rows[0]["peer"] == "unenrolled" and "AKIA" not in r.text and "text" not in rows[0]

        r = await c.get("/console/api/export", params={"format": "jsonl", "range": "all"})
        js = [json.loads(x) for x in r.text.splitlines()]
        assert len(js) == 4 and all("text" not in e for e in js) and "AKIA" not in r.text and js[0]["stages"]

        async def n(**q):
            return len((await c.get("/console/api/export", params={"format": "jsonl", **q})).text.splitlines())
        assert await n(range="1h") == 3 and await n(range="all", role="role-1") == 1
        assert await n(range="all", peer=pid) == 3 and await n(range="all", peer=f"{pid},unenrolled") == 4
        assert await n(range="all", state="untrusted") == 2  # the blocked event's session, both steps
        assert await n(range="all", kind="blocked") == 1 and await n(range="all", kind="allowed") == 2
        assert await n(range="all", q="legacy") == 1
        assert (await c.get("/console/api/export", params={"format": "xml"})).status_code == 400

        ov = (await c.get("/console/api/overview", params={"range": "all"})).json()
        assert ov["latency"]["n"] == 4 and ov["latency"]["hub"]["p95"] == 1.01 and ov["kpis"]["checked"]["value"] == 4


async def test_export_needs_admin(monkeypatch):
    async with _app(monkeypatch, _fleet()[1]) as (_, app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=("10.1.2.3", 5000)),
                                      base_url="http://127.0.0.1") as remote:
            assert (await remote.get("/console/api/export", params={"format": "csv"})).status_code == 401
