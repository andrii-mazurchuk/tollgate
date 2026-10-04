"""Edge UI v2 shapes: overview (KPIs + deltas, dense trend, top reasons/tools, needs a look), events list with
AND filters, the audit read cache, and a scenario reset that leaves other budgets alone."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from tollgate import edge, explain

pytestmark = pytest.mark.track_a
NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)


def ev(sec_ago, verdict="allow", rule=None, tool="github.issues.read", sid="s1", role="role-2", n_rules=1):
    t = (NOW - timedelta(seconds=sec_ago)).isoformat().replace("+00:00", "Z")
    return {"ts": t, "verdict": verdict, "tool": tool, "door": "tool", "role": role, "key_id": sid, "session_id": sid,
            "trace_id": f"t_{sec_ago}_{sid}", "reasons": [{"rule": rule, "tier": 1}] * n_rules if rule else [],
            "stages": [{"name": "key", "outcome": "ok", "ms": 0.4}, {"name": "content", "outcome": "ok", "ms": 2.1}]}


EVENTS = [
    ev(5, "block", "taint.flow", "github.pr.create"),
    ev(6, "redact", "secret.aws_key", "github.repo.read", n_rules=2),
    ev(7, "allow", "inj.ignore_prev", sid="s2", role="role-1"),
    ev(8),
    ev(1200),                    # previous 15 min period
    ev(1300, "block", "role.denied", sid="s3"),
]


def test_kind_and_action_words():
    assert [edge.kind(e) for e in EVENTS[:4]] == ["blocked", "masked", "flagged", None]
    assert explain.check_name("taint.flow") == "Data-flow rule"
    assert edge.action_words(EVENTS[0]) == "Data-flow rule: blocked"
    assert edge.action_words(EVENTS[1]) == "Secret detector: masked 2 values"
    assert edge.action_words(EVENTS[2]) == "Injection check: flagged"


def test_overview_kpis_deltas_and_parts():
    o = edge.overview(EVENTS, "15m", now=NOW)
    k = o["kpis"]
    assert k["checked"] == {"value": 4, "prev": 2} and k["blocked"] == {"value": 1, "prev": 1}
    assert k["masked"] == {"value": 1, "prev": 0} and k["sessions"] == {"value": 2, "prev": 2}
    assert sum(r["block"] + r["allow"] + r["redact"] + r["approve"] for r in o["series"]) == 4
    assert [r["label"] for r in o["top_reasons"]][0] in {explain.rule(x)[0] for x in ("taint.flow", "secret.aws_key",
                                                                                       "inj.ignore_prev")}
    assert o["top_tools"][0] == {"name": "Read an issue", "count": 2}
    assert [x["kind"] for x in o["needs_look"]] == ["blocked", "flagged"]
    assert o["needs_look"][0]["session_id"] == "s1" and o["needs_look"][0]["trace_id"] == "t_5_s1"


def test_trend_is_dense_when_everything_happened_in_seconds():
    o = edge.overview(EVENTS[:4], "all", now=NOW)
    assert 20 <= len(o["series"]) <= 40 and o["bucket_s"] <= 5
    assert sum(1 for r in o["series"] if r["allow"] + r["redact"] + r["block"]) >= 2
    assert edge.overview([], "1h", now=NOW)["kpis"]["checked"]["value"] == 0
    assert edge.overview(EVENTS, "all", now=NOW)["kpis"]["checked"]["prev"] is None


def test_events_list_filters_are_anded():
    out = edge.events_list(EVENTS, "all", {}, now=NOW)
    assert [x["kind"] for x in out["items"]] == ["blocked", "masked", "flagged", "blocked"]
    assert set(out["facets"]["action"]) == {"blocked", "masked", "flagged"}
    assert len(edge.events_list(EVENTS, "15m", {}, now=NOW)["items"]) == 3
    f = edge.events_list(EVENTS, "all", {"action": "blocked", "check": "Role check"}, now=NOW)["items"]
    assert [x["session_id"] for x in f] == ["s3"]
    assert edge.events_list(EVENTS, "all", {"action": "masked", "agent": "role-1"}, now=NOW)["items"] == []


def test_load_events_is_cached_by_mtime(tmp_path, monkeypatch):
    p = tmp_path / "a.jsonl"
    p.write_text(json.dumps(EVENTS[0]) + "\n", encoding="utf-8")
    monkeypatch.setenv("TOLLGATE_AUDIT", str(p))
    a = edge.load_events()
    assert edge.load_events() is a                       # unchanged file: no re-read
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(EVENTS[1]) + "\n")
    assert len(edge.load_events()) == 2


async def test_scenario_reset_keeps_other_budgets(monkeypatch):
    monkeypatch.setenv("TOLLGATE_UPSTREAM", "scripted")
    monkeypatch.setenv("TOLLGATE_T2", "off")
    from tollgate import scenario
    from tollgate.gateway import build_app, model_door
    from tollgate.gateway.policy import load_policy
    app = build_app(load_policy())
    r = scenario.Runner(app)
    day = model_door._today()
    model_door.USED.clear()
    model_door.USED.update({("role-1", day): 50, ("role-2", day): 100})   # the developer's own spend
    async with app.router.lifespan_context(app):
        assert (await r.run("5.1"))["pass"]
        assert model_door.USED[("role-2", day)] > 100
        r.reset()
    assert model_door.USED == {("role-1", day): 50, ("role-2", day): 100}
    model_door.USED.clear()


def test_pre_trace_events_get_one_stable_id():
    """Events written before traces existed have no trace_id; the list and the timeline must agree on a stand-in id."""
    old = {k: v for k, v in ev(30, "block", "role.denied", sid="s9").items() if k != "trace_id"}
    item = edge.events_list([old], "all", {}, now=NOW)["items"][0]
    assert item["trace_id"] and item["trace_id"] == edge.timeline([old], "s9")[0]["trace_id"]


def test_load_events_tails_appends_and_reloads_on_rewrite(tmp_path, monkeypatch):
    import json as _j

    from tollgate import edge
    p = tmp_path / "a.jsonl"
    monkeypatch.setenv("TOLLGATE_AUDIT", str(p))
    line = lambda i: _j.dumps({"ts": f"2026-10-04T00:00:0{i}Z", "n": i}) + "\n"  # noqa: E731
    p.write_text(line(1) + line(2), encoding="utf-8")
    assert [e["n"] for e in edge.load_events()] == [1, 2]
    with p.open("a", encoding="utf-8") as f:
        f.write(line(3) + line(4)[:10])  # a half-written line is not parsed yet
    assert [e["n"] for e in edge.load_events()] == [1, 2, 3]
    with p.open("a", encoding="utf-8") as f:
        f.write(line(4)[10:])
    assert [e["n"] for e in edge.load_events()] == [1, 2, 3, 4]
    p.write_text(line(7), encoding="utf-8")  # rotated / rewritten: full reload
    assert [e["n"] for e in edge.load_events()] == [7]
